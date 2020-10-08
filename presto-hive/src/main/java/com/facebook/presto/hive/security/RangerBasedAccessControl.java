/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.hive.security;

import com.facebook.airlift.log.Logger;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.connector.ConnectorAccessControl;
import com.facebook.presto.spi.connector.ConnectorTransactionHandle;
import com.facebook.presto.spi.security.AccessControlContext;
import com.facebook.presto.spi.security.AccessDeniedException;
import com.facebook.presto.spi.security.ConnectorIdentity;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Authenticator;
import okhttp3.Credentials;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.apache.ranger.plugin.util.ServicePolicies;
import org.jetbrains.annotations.TestOnly;

import javax.inject.Inject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.facebook.presto.spi.security.AccessDeniedException.denyAddColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateView;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateViewWithSelect;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDeleteTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropView;
import static com.facebook.presto.spi.security.AccessDeniedException.denyInsertTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRenameColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRenameTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denySelectColumns;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static java.util.Objects.nonNull;
import static java.util.Objects.requireNonNull;

/**
 * Connector access control which uses existing Ranger policies for authorizations
 */

public class RangerBasedAccessControl
        implements ConnectorAccessControl
{
    public static final String RANGER_PLUGIN_DOWNLOAD_SERVICE = "/service/plugins/policies/download/";
    public static final String RANGER_HTTPS_PLUGIN_DOWNLOAD_SERVICE = "/service/plugins/secure/policies/download/";
    public static final String USER_GROUP_API_USER_KEY = "userid";
    public static final String USER_GROUP_API_GROUP_KEY = "usergroups";
    public static final String CURRENT_USER_REGEX = "{USER}";
    public static final String INFORMATION_SCHEMA = "information_schema";
    public static final String RANGER_URL_POLICY = "url";
    public static final String RANGER_HIVESERVICE = "hiveservice";
    public static final String RANGER_UDF_POLICY = "udf";
    public static final String RANGER_DATABASE = "database";
    public static final String RANGER_TABLE = "table";
    public static final String RANGER_COLUMN = "column";
    public static final String RANGER_HTTPS_STRING = "https://";
    public static final String ALL = "all";
    public static final String COMMA = ",";
    public static final String SELECT = "select";
    public static final String UPDATE = "update";
    public static final String UNION = "UNION";

    private static final Logger log = Logger.get(RangerBasedAccessControl.class);

    private ServicePolicies hiveServicePolicies;

    private RangerPolicy hiveServicePolicy;
    private RangerPolicy hiveparentLevelPolicy;
    private RangerPolicy hiveparentUdfPolicy;
    private RangerPolicy hiveUrlPolicy;

    public Map<String, String> alluserGroupsMap;
    private List<RangerPolicy> allMatchedpolicy = new ArrayList();

    @TestOnly
    public RangerBasedAccessControl()
    {
    }

    @TestOnly
    public void setHiveServicePolicies(ServicePolicies hiveServicePolicies)
    {
        this.hiveServicePolicies = hiveServicePolicies;
    }

    @TestOnly
    public void setAlluserGroupsMap(Map<String, String> alluserGroupsMap)
    {
        this.alluserGroupsMap = alluserGroupsMap;
    }

    @Inject
    public RangerBasedAccessControl(RangerBasedAccessControlConfig config)
    {
        try {
            this.hiveServicePolicies = queryBasicHttpEndpoint(config.getRangerPolicyRestUrl()
                    + RANGER_PLUGIN_DOWNLOAD_SERVICE
                    + config.getHiveServiceName(), ServicePolicies.class);

            loadConstantPolicy(hiveServicePolicies);
            List<HashMap<String, String>> list = Arrays.asList(queryBasicHttpEndpoint(config.getUserGroupRestUrl(), HashMap[].class));

            this.alluserGroupsMap = list.stream().collect(Collectors.toMap(e -> e.get(USER_GROUP_API_USER_KEY).toLowerCase(Locale.ENGLISH),
                    e -> e.get(USER_GROUP_API_GROUP_KEY)));
        }
        catch (Exception e) {
            log.error("Exception while querying ranger service " + e);
            throw new AccessDeniedException("Exception while querying ranger service ");
        }
    }

    private static <T> T getUserListBasicHttp(String endPoint, String username, String password, Class<T> clazz)
            throws IOException
    {
        HttpClient client = new DefaultHttpClient();
        HttpGet httpGet = new HttpGet(endPoint);
        httpGet.addHeader("accept", "application/json");

        HttpResponse httpResponse = client.execute(httpGet);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(httpResponse.getEntity()
                .getContent()));
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(bufferedReader, clazz);
    }

    private static <T> T queryBasicHttpEndpoint(String endPoint, Class<T> clazz)
            throws IOException
    {
        HttpClient client = new DefaultHttpClient();
        HttpGet httpGet = new HttpGet(endPoint);
        httpGet.addHeader("accept", "application/json");

        HttpResponse httpResponse = client.execute(httpGet);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(httpResponse.getEntity()
                .getContent()));
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(bufferedReader, clazz);
    }

    private static <T> T jsonParse(Response response, Class<T> clazz)
            throws IOException
    {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(response.body().byteStream()));
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(bufferedReader, clazz);
    }

    /**
     * This methods sets variable for all one time policies that are independent of user database.
     *
     * @param policies
     */
    private void loadConstantPolicy(ServicePolicies policies)
    {
        for (RangerPolicy policy : policies.getPolicies()) {
            if (nonNull(policy.getResources().get(RANGER_URL_POLICY))) {
                hiveUrlPolicy = policy;
                continue;
            }
            else if (nonNull(policy.getResources().get(RANGER_HIVESERVICE))) {
                hiveServicePolicy = policy;
                continue;
            }

            if (policy.getResources().containsKey(RANGER_DATABASE)) {
                List<String> databases = policy.getResources().get(RANGER_DATABASE).getValues();
                if (databases.contains("*") && nonNull(policy.getResources().get(RANGER_TABLE))) {
                    hiveparentLevelPolicy = policy;
                    continue;
                }
                else if (databases.contains("*") && nonNull(policy.getResources().get(RANGER_UDF_POLICY))) {
                    hiveparentUdfPolicy = policy;
                    continue;
                }
            }

            if (nonNull(hiveUrlPolicy) && nonNull(hiveServicePolicy)
                    && nonNull(hiveparentLevelPolicy) && nonNull(hiveparentUdfPolicy)) {
                break;
            }
        }
    }

    /**
     * This method returns specific policy in hive ranger policy for given db/table
     *
     * @param policies
     * @param db
     * @param table
     * @return RangerPolicy
     */
    private static List<RangerPolicy> getHivePolicy(ServicePolicies policies, String db, String table)
    {
        List<RangerPolicy> hivepolicies = new ArrayList();
        for (RangerPolicy policy : policies.getPolicies()) {
            if (policy.getResources().containsKey(RANGER_DATABASE)) {
                List<String> databases = policy.getResources().get(RANGER_DATABASE).getValues();
                if (patternMatch(db, databases) && !policy.getResources().get(RANGER_DATABASE).getIsExcludes()) {
                    if (policy.getResources().containsKey(RANGER_TABLE)
                            && patternMatch(table, policy.getResources().get(RANGER_TABLE).getValues())
                            && !policy.getResources().get(RANGER_TABLE).getIsExcludes()) {
                        hivepolicies.add(policy);
                    }
                }
            }
        }
        return hivepolicies;
    }

    /**
     * Method returns access list for a given user and group in the policy.
     *
     * @param policy
     * @return
     */
    private static List<String> getAccessList(RangerPolicy policy, String user, Set usergroups)
    {
        List<String> accessList = new ArrayList<>();
        if (nonNull(policy) && policy.getIsEnabled()) {
            for (RangerPolicy.RangerPolicyItem policyItem : policy.getPolicyItems()) {
                if (policyItem.getUsers().contains(user) || isGroupPresent(usergroups, policyItem.getGroups())
                        || policyItem.getUsers().contains(CURRENT_USER_REGEX)) {
                    for (RangerPolicy.RangerPolicyItemAccess item : policyItem.getAccesses()) {
                        if (item.getIsAllowed()) {
                            accessList.add(item.getType());
                        }
                    }
                }
            }
            for (RangerPolicy.RangerPolicyItem policyItem : policy.getAllowExceptions()) {
                if (policyItem.getUsers().contains(user) || isGroupPresent(usergroups, policyItem.getGroups())
                        || policyItem.getUsers().contains(CURRENT_USER_REGEX)) {
                    for (RangerPolicy.RangerPolicyItemAccess item : policyItem.getAccesses()) {
                        if (item.getIsAllowed()) {
                            accessList.add(item.getType());
                        }
                    }
                }
            }
        }
        return accessList;
    }

    /**
     * Method returns access deny list for a given user and group in the policy.
     *
     * @param policy
     * @return
     */
    private static List<String> getDenyAccessList(RangerPolicy policy, String user, Set usergroups)
    {
        List<String> denyaccessList = new ArrayList<>();
        if (nonNull(policy) && policy.getIsEnabled()) {
            for (RangerPolicy.RangerPolicyItem policyItem : policy.getDenyPolicyItems()) {
                if (policyItem.getUsers().contains(user) || isGroupPresent(usergroups, policyItem.getGroups())
                        || policyItem.getUsers().contains(CURRENT_USER_REGEX)) {
                    for (RangerPolicy.RangerPolicyItemAccess item : policyItem.getAccesses()) {
                        if (item.getIsAllowed()) {
                            denyaccessList.add(item.getType());
                        }
                    }
                }
            }
            for (RangerPolicy.RangerPolicyItem policyItem : policy.getDenyExceptions()) {
                if (policyItem.getUsers().contains(user) || isGroupPresent(usergroups, policyItem.getGroups())
                        || policyItem.getUsers().contains(CURRENT_USER_REGEX)) {
                    for (RangerPolicy.RangerPolicyItemAccess item : policyItem.getAccesses()) {
                        if (item.getIsAllowed()) {
                            denyaccessList.add(item.getType());
                        }
                    }
                }
            }
        }
        return denyaccessList;
    }

    /**
     * This method will check if there are any common group is two supplied list
     *
     * @param userGroups
     * @param rangeruserGroups
     * @return
     */
    public static boolean isGroupPresent(Set userGroups, List<String> rangeruserGroups)
    {
        for (String group : rangeruserGroups) {
            if (userGroups.contains(group)) {
                return true;
            }
        }
        return false;
    }

    /**
     * This method does pattern match for a given String to the String in list
     *
     * @param pattern
     * @param ls
     * @return
     */
    public static boolean patternMatch(String pattern, List<String> ls)
    {
        for (String str : ls) {
            str = str.replace("*", ".*");
            str = str.replace("?", ".?");
            str = str.replace("{", "\\{");
            str = str.replace("}", "\\}");
            Pattern r = Pattern.compile(str);
            Matcher m = r.matcher(pattern);
            if (m.matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * This method will match if all the columns supplied in user query
     * matches with ranger policy column access
     *
     * @param columns
     * @param rangerpolicyColums
     * @return
     */
    public static boolean columnMatch(Set<String> columns, List<String> rangerpolicyColums)
    {
        for (String pattern : columns) {
            if (!patternMatch(pattern, rangerpolicyColums)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Method returns column names in a given policy.
     *
     * @param hivePolicy
     * @return
     */
    private static List<String> getpolicyColumns(RangerPolicy hivePolicy)
    {
        List<String> columnList = new ArrayList<>();
        if (nonNull(hivePolicy) && hivePolicy.getResources().containsKey(RANGER_COLUMN)) {
            columnList = hivePolicy.getResources().get(RANGER_COLUMN).getValues();
        }
        return columnList;
    }

    /**
     * Method checks if given sqlOperation is allowed for user or not
     *
     * @param user
     * @param database
     * @param table
     * @param columnNames
     * @param sqlOperation
     * @return
     */
    public boolean checkdenySQLOperation(String user, String database, String table, Set<String> columnNames, String sqlOperation, Set userGroups)
    {
        allMatchedpolicy = getHivePolicy(hiveServicePolicies, database, table);
        log.debug(allMatchedpolicy.toString());
        if (database.equalsIgnoreCase(user)) {
            List<RangerPolicy> hivepolicyList = getHivePolicy(hiveServicePolicies, CURRENT_USER_REGEX, table);
            if (hivepolicyList.size() > 0) {
                allMatchedpolicy.addAll(hivepolicyList);
            }
        }

        for (RangerPolicy hivepolicy : allMatchedpolicy) {
            if (getDenyAccessList(hivepolicy, user, userGroups).contains(sqlOperation)
                    || getDenyAccessList(hivepolicy, user, userGroups).contains(ALL)) {
                log.error("Rejecting Access for user %s because of Deny List of hive policies!!", user);
                return true;  //Access denied
            }
        }

        for (RangerPolicy hivepolicy : allMatchedpolicy) {
            if ((getAccessList(hivepolicy, user, userGroups).contains(sqlOperation)
                    || getAccessList(hivepolicy, user, userGroups).contains(ALL))
                    && !hivepolicy.getResources().get(RANGER_COLUMN).getIsExcludes()) {
                if (columnMatch(columnNames, getpolicyColumns(hivepolicy))) {
                    log.debug("Access permitted for user %s because of hive policy!!", user);
                    return false; //Access will be given
                }
            }
        }
        log.error("Rejecting Access for user %s because of Access List of hive policies!!", user);
        return true;  //Access denied
    }

    /**
     * Enum for different sql operation for which ranger check is enabled
     */
    enum SQLOPERATION
    {
        CreateTable, DropTable, SelectFromColumns, InsertIntoTable, CreateView, DropView, CreateViewWithSelectFromColumns, RenameTable
    }

    /**
     * Check if user-groups mapping exist in data discovery.
     *
     * @return Set of groups
     */
    public Set getUserGroups(ConnectorIdentity identity)
    {
        String groups = alluserGroupsMap.get(identity.getUser().toLowerCase(Locale.ENGLISH));

        if (StringUtils.isEmpty(groups)) {
            throw new AccessDeniedException("Access Denied: ");
        }

        String[] groupList = groups.split(COMMA);
        return new HashSet<>((Arrays.asList(groupList)));
    }

    /**
     * Check if identity is allowed to execute SHOW SCHEMAS in a catalog.
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterSchemas} method must handle filter all results for unauthorized users,
     * since there are multiple way to list schemas.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowSchemas(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context)
    {
    }

    /**
     * Filter the list of schemas to those visible to the identity.
     */
    @Override
    public Set<String> filterSchemas(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, Set<String> schemaNames)
    {
        return schemaNames;
    }

    /**
     * Check if identity is allowed to create the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateTable(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName)
    {
        Set<String> columnNames = new HashSet<>();
        Set<String> userGroups = getUserGroups(identity);
        if (checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, "create", userGroups)) {
            denyCreateTable(tableName.toString(), "Access denied - User " + identity.getUser() + " is not configured with Ranger CREATE policy.");
        }
    }

    /**
     * Filter the list of tables and views to those visible to the identity.
     */
    @Override
    public Set<SchemaTableName> filterTables(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, Set<SchemaTableName> tableNames)
    {
        return tableNames;
    }

    /**
     * Check if identity is allowed to add columns to the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanAddColumn(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName)
    {
        denyAddColumn(tableName.toString());
    }

    /**
     * Check if identity is allowed to drop columns from the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropColumn(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName)
    {
        denyDropColumn(tableName.toString());
    }

    /**
     * Check if identity is allowed to rename a column in the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameColumn(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName)
    {
        denyRenameColumn(tableName.toString());
    }

    /**
     * Check if identity is allowed to select from the specified columns in a relation.  The column set can be empty.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSelectFromColumns(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName, Set<String> columnNames)
    {
        if (!tableName.getSchemaName().equals(INFORMATION_SCHEMA)) {
            Set<String> userGroups = getUserGroups(identity);
            if (checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, SELECT, userGroups)) {
                denySelectColumns(tableName.toString(), columnNames, "Access denied - User " + identity.getUser() + " is not configured with Ranger SELECT policy.");
            }
        }
    }

    /**
     * Check if identity is allowed to drop the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropTable(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName)
    {
        Set<String> columnNames = new HashSet<>();
        Set<String> userGroups = getUserGroups(identity);
        if (checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, "drop", userGroups)) {
            denyDropTable(tableName.toString(), "Access denied - User " + identity.getUser() + " is not configured with Ranger DROP policy.");
        }
    }

    /**
     * Check if identity is allowed to rename the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanRenameTable(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName, SchemaTableName newTableName)
    {
        Set<String> columnNames = new HashSet<>();
        Set<String> userGroups = getUserGroups(identity);
        if (checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, "alter", userGroups)) {
            denyRenameTable(tableName.toString(), newTableName.toString(), "Access denied - User " + identity.getUser() + " is not configured with Ranger ALTER policy.");
        }
    }

    /**
     * Check if identity is allowed to show metadata of tables by executing SHOW TABLES, SHOW GRANTS etc. in a catalog.
     * <p>
     * NOTE: This method is only present to give users an error message when listing is not allowed.
     * The {@link #filterTables} method must filter all results for unauthorized users,
     * since there are multiple ways to list tables.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanShowTablesMetadata(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, String schemaName)
    {
    }

    /**
     * Check if identity is allowed to insert into the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanInsertIntoTable(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName)
    {
        Set<String> columnNames = new HashSet<>();
        Set<String> userGroups = getUserGroups(identity);
        if (checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, UPDATE, userGroups)
                || checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, SELECT, userGroups)) {
            denyInsertTable(tableName.toString(), "Access denied - User " + identity.getUser() + " is not configured with Ranger UPDATE & SELECT policy.");
        }
    }

    /**
     * Check if identity is allowed to delete from the specified table in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDeleteFromTable(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName)
    {
        Set<String> columnNames = new HashSet<>();
        Set<String> userGroups = getUserGroups(identity);
        if (checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, UPDATE, userGroups)
                || checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, SELECT, userGroups)) {
            denyDeleteTable(tableName.toString(), "Access denied - User " + identity.getUser() + " is not configured with Ranger UPDATE & SELECT policy.");
        }
    }

    /**
     * Check if identity is allowed to create the specified view in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateView(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName viewName)
    {
        Set<String> userGroups = getUserGroups(identity);
        if (checkdenySQLOperation(identity.getUser(), viewName.getSchemaName(), viewName.getTableName(), new HashSet<>(), "create", userGroups)) {
            denyCreateView(viewName.toString(), "Access denied - User " + identity.getUser() + " is not configured with Ranger CREATE policy.");
        }
    }

    /**
     * Check if identity is allowed to drop the specified view in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanDropView(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName viewName)
    {
        Set<String> userGroups = getUserGroups(identity);
        Set<String> columnNames = new HashSet<>();

        if (checkdenySQLOperation(identity.getUser(), viewName.getSchemaName(), viewName.getTableName(), columnNames, "drop", userGroups)) {
            denyDropView(viewName.toString(), "Access denied - User " + identity.getUser() + " is not configured with Ranger DROP policy.");
        }
    }

    /**
     * Check if identity is allowed to create a view that selects from the specified columns in a relation.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanCreateViewWithSelectFromColumns(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName, Set<String> columnNames)
    {
        Set<String> userGroups = getUserGroups(identity);
        if (checkdenySQLOperation(identity.getUser(), tableName.getSchemaName(), tableName.getTableName(), columnNames, "create", userGroups)) {
            denyCreateViewWithSelect(tableName.toString(), identity, "Access denied - User " + identity.getUser() + " is not configured with Ranger CREATE policy.");
        }
    }

    /**
     * Check if identity is allowed to set the specified property in this catalog.
     *
     * @throws com.facebook.presto.spi.security.AccessDeniedException if not allowed
     */
    @Override
    public void checkCanSetCatalogSessionProperty(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, String propertyName)
    {
    }

    private static OkHttpClient createAuthenticatedClient(final String username,
            final String password)
    {
        // build client with authentication information.
        OkHttpClient httpClient = new OkHttpClient.Builder().authenticator(new Authenticator()
        {
            public Request authenticate(Route route, Response response)
                    throws IOException
            {
                String credential = Credentials.basic(username, password);
                return response.request().newBuilder().header("Authorization", credential).build();
            }
        }).build();
        return httpClient;
    }

    private static Response doRequest(OkHttpClient httpClient, String anyURL)
            throws IOException
    {
        Request request = new Request.Builder().url(anyURL).header("Accept", "application/json").build();
        Response response = httpClient.newCall(request).execute();
        if (!response.isSuccessful()) {
            throw new IOException("Unexpected code " + response);
        }
        return response;
    }

    public static Interceptor basicAuth(String user, String password)
    {
        requireNonNull(user, "user is null");
        requireNonNull(password, "password is null");

        String credential = Credentials.basic(user, password);
        return chain -> chain.proceed(chain.request().newBuilder()
                .header(AUTHORIZATION, credential)
                .build());
    }
}
