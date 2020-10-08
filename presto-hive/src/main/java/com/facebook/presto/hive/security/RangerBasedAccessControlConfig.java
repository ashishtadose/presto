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

import com.facebook.airlift.configuration.Config;
import io.airlift.units.Duration;
import io.airlift.units.MinDuration;

public class RangerBasedAccessControlConfig
{
    public static final String SECURITY_REFRESH_PERIOD = "ranger.refresh-policy-period";
    public static final String HIVE_POLICY_SERVICE_NAME = "ranger.policy-hive-service-name";
    public static final String RANGER_REST_POLICY_URL = "ranger.policy-rest-url";
    public static final String USER_GROUP_REST_URL = "ranger.user-groups-rest-url";
    public static final String USER_KEYTAB_LOCATION = "ranger.user-keytab-location";
    public static final String USER_PRINCIPAL = "ranger.user-principal";

    private String rangerPolicyRestUrl;
    private String hiveServiceName;
    private Duration refreshPeriod;
    private String userGroupsRestUrl;
    private String userKeytabLocation;
    private String userPrincipal;

    private String basicAuthUser;
    private String basicAuthPassword;
    private RangerServiceAuthType rangerServiceAuthType = RangerServiceAuthType.BASIC;

    @MinDuration("120s")
    public Duration getRefreshPeriod()
    {
        return refreshPeriod;
    }

    @Config(SECURITY_REFRESH_PERIOD)
    public RangerBasedAccessControlConfig setRefreshPeriod(Duration refreshPeriod)
    {
        this.refreshPeriod = refreshPeriod;
        return this;
    }

    public String getHiveServiceName()
    {
        return hiveServiceName;
    }

    @Config(HIVE_POLICY_SERVICE_NAME)
    public RangerBasedAccessControlConfig setHiveServiceName(String hiveServiceName)
    {
        this.hiveServiceName = hiveServiceName;
        return this;
    }

    public String getRangerPolicyRestUrl()
    {
        return rangerPolicyRestUrl;
    }

    @Config(RANGER_REST_POLICY_URL)
    public RangerBasedAccessControlConfig setRangerPolicyRestUrl(String rangerPolicyRestUrl)
    {
        this.rangerPolicyRestUrl = rangerPolicyRestUrl;
        return this;
    }

    public String getUserGroupRestUrl()
    {
        return userGroupsRestUrl;
    }

    @Config(USER_GROUP_REST_URL)
    public RangerBasedAccessControlConfig setUserGroupRestUrl(String userGroupsRestUrl)
    {
        this.userGroupsRestUrl = userGroupsRestUrl;
        return this;
    }

    public String getUserKeytabLocation()
    {
        return userKeytabLocation;
    }

    @Config(USER_KEYTAB_LOCATION)
    public RangerBasedAccessControlConfig setUserKeytabLocation(String userKeytabLocation)
    {
        this.userKeytabLocation = userKeytabLocation;
        return this;
    }

    public String getUserPrincipal()
    {
        return userPrincipal;
    }

    @Config(USER_PRINCIPAL)
    public RangerBasedAccessControlConfig setUserPrincipal(String userPrincipal)
    {
        this.userPrincipal = userPrincipal;
        return this;
    }

    public enum RangerServiceAuthType
    {
        BASIC,
        KERBEROS
    }

    public RangerServiceAuthType getRangerServiceAuthType()
    {
        return rangerServiceAuthType;
    }

    @Config("ranger.service.auth-type")
    public void setRangerServiceAuthType(RangerServiceAuthType rangerServiceAuthType)
    {
        this.rangerServiceAuthType = rangerServiceAuthType;
    }

    public String getBasicAuthUser()
    {
        return basicAuthUser;
    }

    @Config("ranger.service.basic-auth.username")
    public void setBasicAuthUser(String basicAuthUser)
    {
        this.basicAuthUser = basicAuthUser;
    }

    public String getBasicAuthPassword()
    {
        return basicAuthPassword;
    }

    @Config("ranger.service.basic-auth.password")
    public void setBasicAuthPassword(String basicAuthPassword)
    {
        this.basicAuthPassword = basicAuthPassword;
    }
}
