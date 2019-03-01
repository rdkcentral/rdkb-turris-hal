/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/**********************************************************************

    module: dhcpv4c_api.c

        For CCSP Component: DHCPV4-Client Status

    ---------------------------------------------------------------

    description:

        This header file gives the function call prototypes and 
        structure definitions used for the RDK-Broadband 
        DHCPv4 Client Status abstraction layer

        NOTE:
        THIS VERSION IS AN EARLY DRAFT INTENDED TO GET COMMENTS FROM COMCAST.
        TESTING HAS NOT YET BEEN COMPLETED.  
       
    ---------------------------------------------------------------

    environment:

    ---------------------------------------------------------------

    author:

        Cisco

**********************************************************************/

#include <stdio.h>
#include <string.h>
#include "dhcp4cApi.h"
#include "dhcpv4c_api.h"

#if defined(UDHCPC_SWITCH)
// start of UDHCPC client required API
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HAL_DHCPV4C_ERT_DBG(x) do{fprintf x; fflush(stdout);}while(0);

typedef unsigned int token_t;

typedef  enum
_COSA_DML_DHCPC_STATUS
{
    COSA_DML_DHCPC_STATUS_Init                  = 1,
    COSA_DML_DHCPC_STATUS_Selecting,
    COSA_DML_DHCPC_STATUS_Requesting,
    COSA_DML_DHCPC_STATUS_Rebinding,
    COSA_DML_DHCPC_STATUS_Bound,
    COSA_DML_DHCPC_STATUS_Renewing
};

#define DEFAULT_ERT_IFNAME "erouter0"

static const char *dhcp_state[] = {
        "init",
        "selecting",
        "requesting",
        "rebinding",
        "bound",
        "renewing"
};

static INT dhcpv4c_sysevent_get_value(char *query_name, char *query_value, unsigned query_value_size)
{

        if (query_name == NULL || query_value == NULL || query_value_size == 0) {
                return STATUS_FAILURE;
        } else {
                token_t        se_token;
                int            se_fd = -1;

                se_fd = s_sysevent_connect(&se_token);
                if (0 > se_fd) {
                        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d syseventError\n", __FUNCTION__, __LINE__));
                        return STATUS_FAILURE;
                } else {
                        int ret = STATUS_SUCCESS;
                        char ert_ifname[32];
                        char name[64];

                        memset(ert_ifname, 0, sizeof(ert_ifname));

                        ret = sysevent_get(se_fd, se_token, "current_wan_ifname", ert_ifname, sizeof(ert_ifname));
                        if (ret != 0 || strlen(ert_ifname) == 0) {
                                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d syseventError %d\n", __FUNCTION__, __LINE__, ret));
                                return STATUS_FAILURE;
                        }

                        snprintf(name, sizeof(name), query_name, ert_ifname);

                        ret = sysevent_get(se_fd, se_token, name, query_value, query_value_size);

                        if (ret != 0 || strlen(query_value) == 0) {
                                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d syseventError %d\n", __FUNCTION__, __LINE__, ret));
                                return STATUS_FAILURE;
                        }
                }
        }
        return STATUS_SUCCESS;
}

#define UPTIME_FILE_PATH        "/proc/uptime"
#define MAX_LINE_SIZE           64
static int dhcpv4c_get_up_time(unsigned int *up_time)
{
    FILE *fp;
    char line[MAX_LINE_SIZE];
    char *ret_val;
    unsigned int upTime = 0;

   /* This file contains two numbers:
    * the uptime of the system (seconds), and the amount of time spent in idle process (seconds). 
    * We care only for the first one */
    fp = fopen( UPTIME_FILE_PATH, "r");
    if (fp == NULL)
    {
        return -1;
    }

    ret_val = fgets(line,MAX_LINE_SIZE,fp);
    fclose(fp);

    if (ret_val == NULL)
    {
        return -1;
    }

    /* Extracting the first token (number of up-time in seconds). */
    ret_val = strtok (line," .");

    /* we need only the number of seconds */
    upTime += atoi(ret_val);

    *up_time = upTime;

    return 0;
}

INT dhcpv4c_get_ert_lease_time_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));
        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_lease_time", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d query_value===%s===\n", __func__, __LINE__, query_value));
                *pValue = atoi(query_value);
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_remain_lease_time_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                unsigned lease_time = 0, start_time = 0, up_time = 0, remain_lease_time = 0;
                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_lease_time", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d lease time===%s===\n", __func__, __LINE__, query_value));
                lease_time = atoi(query_value);

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_start_time", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d start time===%s===\n", __func__, __LINE__, query_value));
                start_time = atoi(query_value);

                dhcpv4c_get_up_time(&up_time);

                remain_lease_time = lease_time - (up_time - start_time);
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d remain lease time===%u===\n", __func__, __LINE__, remain_lease_time));

                *pValue = remain_lease_time;
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_remain_renew_time_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                unsigned lease_time = 0, start_time = 0, up_time = 0, renew_time = 0, remain_renew_time = 0;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_lease_time", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d lease time===%s===\n", __func__, __LINE__, query_value));
                lease_time = atoi(query_value);
                renew_time = lease_time/2;
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d renew time===%u===\n", __func__, __LINE__, renew_time));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_start_time", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d start time===%s===\n", __func__, __LINE__, query_value));
                start_time = atoi(query_value);

                dhcpv4c_get_up_time(&up_time);

                remain_renew_time = renew_time - (up_time - start_time);
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d remain renew time===%u===\n", __func__, __LINE__, remain_renew_time));

                *pValue = remain_renew_time;
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_remain_rebind_time_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                unsigned lease_time = 0, start_time = 0, up_time = 0, rebind_time = 0, remain_bind_time = 0;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_lease_time", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d lease time===%s===\n", __func__, __LINE__, query_value));
                lease_time = atoi(query_value);
                rebind_time = lease_time*7/8;
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d rebind time===%u===\n", __func__, __LINE__, rebind_time));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_start_time", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d start time===%s===\n", __func__, __LINE__, query_value));
                start_time = atoi(query_value);

                dhcpv4c_get_up_time(&up_time);

                remain_bind_time = rebind_time - (up_time - start_time);
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d remain rebind time===%u===\n", __func__, __LINE__, remain_bind_time));

                *pValue = remain_bind_time;
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_config_attempts_udhcp(INT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                *pValue = 100;
                return STATUS_SUCCESS;
        }
}

INT dhcpv4c_get_ert_ifname_udhcp(CHAR *pName)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pName) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                token_t        se_token;
                int            se_fd = -1;

                se_fd = s_sysevent_connect(&se_token);
                if (0 > se_fd) {
                        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d syseventError\n", __FUNCTION__, __LINE__));
                        return STATUS_FAILURE;
                } else {
                        int ret = STATUS_SUCCESS;
                        char ert_ifname[32];

                        memset(ert_ifname, 0, sizeof(ert_ifname));

                        ret = sysevent_get(se_fd, se_token, "current_wan_ifname", ert_ifname, sizeof(ert_ifname));
                        if (ret != 0 || strlen(ert_ifname) == 0) {
                                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d syseventError use default name %s\n", __FUNCTION__, __LINE__, DEFAULT_ERT_IFNAME));
                                strcpy(pName, DEFAULT_ERT_IFNAME);
                                return STATUS_SUCCESS;
                        }

                        strcpy(pName, ert_ifname);
                }
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_fsm_state_udhcp(INT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                struct in_addr addr;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_dhcp_state", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d dhcp state===%s===\n", __func__, __LINE__, query_value));

                int i = 0;
                for (i=0; i<sizeof(dhcp_state)/sizeof(char*); i++) {
                        if (strcmp(dhcp_state[i], query_value) == 0) {
                                *pValue = i+1;
                                break;
                        }
                }

                if ((i==sizeof(dhcp_state)/sizeof(char*)) && (strcmp("renew", query_value) == 0)) {
                        *pValue = COSA_DML_DHCPC_STATUS_Bound;
                }
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_ip_addr_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                struct in_addr addr;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_ipaddr", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d ip addr===%s===\n", __func__, __LINE__, query_value));
               inet_aton(query_value, &addr);
                *pValue = addr.s_addr;
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_mask_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                struct in_addr addr;
                unsigned mask = 0;
                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_subnet", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d mask===%s===\n", __func__, __LINE__, query_value));
               mask = atoi(query_value);
                 mask = (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF;
                 *pValue = htonl(mask);
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_gw_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                struct in_addr addr;
                unsigned gw_num = 0;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_gw_number", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d gw number===%s===\n", __func__, __LINE__, query_value));
                gw_num = atoi(query_value);

                if (gw_num >= 1) {
                        ret = dhcpv4c_sysevent_get_value("ipv4_%s_gw_0", query_value, sizeof(query_value));
                        if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                                return STATUS_FAILURE;
                        }

                        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d the first gw===%s===\n", __func__, __LINE__, query_value));
                       inet_aton(query_value, &addr);
                        *pValue = addr.s_addr;
                } else {
                        *pValue = 0;
                }
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_dns_svrs_udhcp(dhcpv4c_ip_list_t *pList)
{

        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pList) {
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                struct in_addr addr;
                unsigned dns_num = 0;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_dns_number", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d query_value===%s===\n", __func__, __LINE__, query_value));
                dns_num = atoi(query_value);

                if (dns_num >= 1) {
                        int i = 0;

                        if (dns_num >4)
                                dns_num = 4;

                        for (i=0; i<dns_num; i++) {
                                char gw_str[32];
                                memset(gw_str, 0, sizeof(gw_str));
                                snprintf(gw_str, sizeof(gw_str), "ipv4_%s_dns_%d", "%s", i);
                                ret = dhcpv4c_sysevent_get_value(gw_str, query_value, sizeof(query_value));
                                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                                        continue;
                                }

                                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d query_value===%s===\n", __func__, __LINE__, query_value));
                                inet_aton(query_value, &addr);
                                pList->addrs[i] = addr.s_addr;
                        }
                        pList->number = dns_num;
                } else {
                        pList->number = 0;
                }
        }

        return STATUS_SUCCESS;
}

INT dhcpv4c_get_ert_dhcp_svr_udhcp(UINT *pValue)
{
        HAL_DHCPV4C_ERT_DBG((stderr, "%s %d in\n", __func__, __LINE__));

        if (NULL == pValue) {
                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d invalid parameter\n", __FUNCTION__, __LINE__));
                return STATUS_FAILURE;
        } else {
                char query_value[64];
                int ret = STATUS_SUCCESS;
                struct in_addr addr;

                memset(query_value, 0, sizeof(query_value));

                ret = dhcpv4c_sysevent_get_value("ipv4_%s_dhcp_server", query_value, sizeof(query_value));
                if (ret != STATUS_SUCCESS || strlen(query_value) == 0) {
                        return STATUS_FAILURE;
                }

                HAL_DHCPV4C_ERT_DBG((stderr, "%s %d dhcp server===%s===\n", __func__, __LINE__, query_value));
               inet_aton(query_value, &addr);
                *pValue = addr.s_addr;
        }

        return STATUS_SUCCESS;
}

// End of UDHCPC client required APi

#ifdef DEBUG_QUERY_ALL
void query_all();
static int query_all_in_progress = 0;
#endif

INT dhcpv4c_get_ert_lease_time(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pValue)
    {
        return STATUS_FAILURE;
    }
    else
    {
       if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_lease_time(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_lease_time_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_remain_lease_time(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if(pValue==NULL)
    {
       return(STATUS_FAILURE);
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
       return dhcp4c_get_ert_remain_lease_time(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_remain_lease_time_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_remain_renew_time(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pValue)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_remain_renew_time(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_remain_renew_time_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_remain_rebind_time(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pValue)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_remain_rebind_time(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_remain_rebind_time_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_config_attempts(INT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pValue)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_config_attempts(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_config_attempts_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_ifname(CHAR *pName)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pName)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_ifname(pName);
      }
      else
      {
        return dhcpv4c_get_ert_ifname_udhcp(pName);
      }
    }
}

INT dhcpv4c_get_ert_fsm_state(INT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if(pValue==NULL)
    {
       return(STATUS_FAILURE);
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
       return dhcp4c_get_ert_fsm_state(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_fsm_state_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_ip_addr(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pValue)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_ip_addr(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_ip_addr_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_mask(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pValue)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_mask(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_mask_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_gw(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if(pValue==NULL)
    {
       return(STATUS_FAILURE);
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
       return dhcp4c_get_ert_gw(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_gw_udhcp(pValue);
      }
    }
}

INT dhcpv4c_get_ert_dns_svrs(dhcpv4c_ip_list_t *pList)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pList)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_dns_svrs((ipv4AddrList_t*) pList);
      }
      else
      {
        return dhcpv4c_get_ert_dns_svrs_udhcp((ipv4AddrList_t*) pList);
      }
    }
}

INT dhcpv4c_get_ert_dhcp_svr(UINT *pValue)
{
    char udhcpflag[10]="";
    syscfg_get( NULL, "UDHCPEnable", udhcpflag, sizeof(udhcpflag));
    if (NULL == pValue)
    {
        return STATUS_FAILURE;
    }
    else
    {
      if( 0 == strcmp(udhcpflag,"false"))
      {
        return dhcp4c_get_ert_dhcp_svr(pValue);
      }
      else
      {
        return dhcpv4c_get_ert_dhcp_svr_udhcp(pValue);
      }
    }
}

#else
/**********************************************************************************
 *
 *  DHCPV4-Client Subsystem level function definitions
 *
**********************************************************************************/

#ifdef DEBUG_QUERY_ALL
void query_all();
static int query_all_in_progress = 0;
#endif

/* dhcpv4c_get_ert_lease_time() function */
/**
* Description: Gets the E-Router Offered Lease Time
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_lease_time(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_lease_time(pValue);
    }
}
 
/* dhcpv4c_get_ert_remain_lease_time() function */
/**
* Description: Gets the E-Router Remaining Lease Time
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_remain_lease_time(UINT *pValue)
{       
    if(pValue==NULL)
    {
       return(STATUS_FAILURE);
    }
    else
    {
       return dhcp4c_get_ert_remain_lease_time(pValue);
    }
}

/* dhcpv4c_get_ert_remain_renew_time() function */
/**
* Description: Gets the E-Router Interface Remaining Time to Renew
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_remain_renew_time(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_remain_renew_time(pValue);
    }
}

/* dhcpv4c_get_ert_remain_rebind_time() function */
/**
* Description: Gets the E-Router Interface Remaining Time to Rebind
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_remain_rebind_time(UINT *pValue)
{
    if (NULL == pValue) 
    { 
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_remain_rebind_time(pValue);
    }
}

/* dhcpv4c_get_ert_config_attempts() function */
/**
* Description: Gets the E-Router Number of Attemts to Configure.
* Parameters : 
*    pValue - Count.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_config_attempts(INT *pValue)
{
    if (NULL == pValue) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_config_attempts(pValue);
    }
}

/* dhcpv4c_get_ert_ifname() function */
/**
* Description: Gets the E-Router Interface Name.
* Parameters : 
*    pName - Interface Name (e.g. ert0)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_ifname(CHAR *pName)
{
    if (NULL == pName) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_ifname(pName);
    }
}

/* dhcpv4c_get_ert_fsm_state() function */
/**
* Description: Gets the E-Router DHCP State
* Parameters : 
*    pValue - State of the DHCP (RENEW/ACQUIRED etc.)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_fsm_state(INT *pValue)
{
    if(pValue==NULL)
    {    
       return(STATUS_FAILURE);
    }
    else
    {
       return dhcp4c_get_ert_fsm_state(pValue);
    }
}

/* dhcpv4c_get_ert_ip_addr() function */
/**
* Description: Gets the E-Router Interface IP Address
* Parameters : 
*    pValue - IP Address (of the Interface)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_ip_addr(UINT *pValue)
{
    if (NULL == pValue) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_ip_addr(pValue);
    }
}

/* dhcpv4c_get_ert_mask() function */
/**
* Description: Gets the E-Router Subnet Mask.
* Parameters : 
*    pValue - Subnet Mask (bitmask)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_mask(UINT *pValue)
{
    if (NULL == pValue) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_mask(pValue);
    }
}

/* dhcpv4c_get_ert_gw() function */
/**
* Description: Gets the E-Router Gateway IP Address
* Parameters : 
*    pValue - IP Address (of the Gateway)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_gw(UINT *pValue)
{
    if(pValue==NULL)
    {    
       return(STATUS_FAILURE);
    }
    else
    {
       return dhcp4c_get_ert_gw(pValue);
    }
}

/* dhcpv4c_get_ert_dns_svrs() function */
/**
* Description: Gets the E-Router List of DNS Servers
* Parameters : 
*    pList - List of IP Address (of DNS Servers)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_dns_svrs(dhcpv4c_ip_list_t *pList)
{
    if (NULL == pList) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_dns_svrs((ipv4AddrList_t*) pList);
    }
}

/* dhcpv4c_get_ert_dhcp_svr() function */
/**
* Description: Gets the E-Router DHCP Server IP Address
* Parameters : 
*    pValue - IP Address (of DHCP Server)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ert_dhcp_svr(UINT *pValue)
{
    if (NULL == pValue) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ert_dhcp_svr(pValue);
    }
}

#endif
/* dhcpv4c_get_ecm_lease_time() function */
/**
* Description: Gets the ECM Offered Lease Time.
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_lease_time(UINT *pValue)
{
    if (NULL == pValue) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_lease_time(pValue);
    }
}

/* dhcpv4c_get_ecm_remain_lease_time() function */
/**
* Description: Gets the ECM Remaining Lease Time
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_remain_lease_time(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_remain_lease_time(pValue);
    }
}

/* dhcpv4c_get_ecm_remain_renew_time() function */
/**
* Description: Gets the ECM Interface Remaining time to Renew.
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_remain_renew_time(UINT *pValue)
{
    if (NULL == pValue) 
    {    
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_remain_renew_time(pValue);
    }
}

/* dhcpv4c_get_ecm_remain_rebind_time() function */
/**
* Description: Gets the ECM Interface Remaining time to Rebind.
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_remain_rebind_time(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_remain_rebind_time(pValue);
    }
}

/* dhcpv4c_get_ecm_config_attempts() function */
/**
* Description: Gets the ECM Configuration Number of Attemts.
* Parameters : 
*    pValue - Count.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_config_attempts(INT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_config_attempts(pValue);
    }
}

/* dhcpv4c_get_ecm_ifname() function */
/**
* Description: Gets the ECM Interface Name.
* Parameters : 
*    pName - Name of the Interface (e.g doc0)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_ifname(CHAR *pName)
{
    if (NULL == pName) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_ifname(pName);;        
    }
}

/* dhcpv4c_get_ecm_fsm_state() function */
/**
* Description: Gets the ECM DHCP State
* Parameters : 
*    pValue - State of the DHCP (RENEW/ACQUIRED etc)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_fsm_state(INT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_fsm_state(pValue);
    }
}

/* dhcpv4c_get_ecm_ip_addr() function */
/**
* Description: Gets the ECM Interface IP Address
* Parameters : 
*    pValue - IP Address of the Interface.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_ip_addr(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_ip_addr(pValue);
    }
}

/* dhcpv4c_get_ecm_mask() function */
/**
* Description: Gets the ECM Interface Subnet Mask.
* Parameters : 
*    pValue - Subnet Mask (bitmask).
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_mask(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_mask(pValue);
    }
}

/* dhcpv4c_get_ecm_gw() function */
/**
* Description: Gets the ECM Gateway IP Address
* Parameters : 
*    pValue - IP Address of Gateway
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_gw(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_gw(pValue);
    }
}

/* dhcpv4c_get_ecm_dns_svrs() function */
/**
* Description: Gets the ECM List of DNS Servers
* Parameters : 
*    pList - List of IP Addresses (of DNS Servers)
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_dns_svrs(dhcpv4c_ip_list_t *pList)
{
    if (NULL == pList) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_dns_svrs((ipv4AddrList_t*) pList);
    }
}

/* dhcpv4c_get_ecm_dhcp_svr() function */
/**
* Description: Gets the ECM DHCP Server IP Address
* Parameters : 
*    pValue - IP Address 
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_ecm_dhcp_svr(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_ecm_dhcp_svr(pValue);
    }
}


/* dhcpv4c_get_emta_remain_lease_time() function */
/**
* Description: Gets the E-MTA interface Least Time
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_emta_remain_lease_time(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_emta_remain_lease_time(pValue);
    }
}

/* dhcpv4c_get_emta_remain_renew_time() function */
/**
* Description: Gets the E-MTA interface Remaining Time to Renew
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_emta_remain_renew_time(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_emta_remain_renew_time(pValue);
    }
}

/* dhcpv4c_get_emta_remain_rebind_time() function */
/**
* Description: Gets the E-MTA interface Remaining Time to Rebind
* Parameters : 
*    pValue - Value in Seconds.
* @return The status of the operation.
* @retval STATUS_SUCCESS if successful.
* @retval STATUS_FAILURE if any error is detected 
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT dhcpv4c_get_emta_remain_rebind_time(UINT *pValue)
{
    if (NULL == pValue) 
    {
        return STATUS_FAILURE;
    } 
    else 
    {
        return dhcp4c_get_emta_remain_rebind_time(pValue);
    }
}

#ifdef DEBUG_QUERY_ALL
void query_all()
{
   int i;

   unsigned int Value;
   int iValue;
   char Name[100];
   dhcpv4c_ip_list_t List;
   
   unsigned int* pValue = &Value;
   int* piValue = &iValue;
   char* pName = &Name[0];
   dhcpv4c_ip_list_t*  pList = &List;
  
   int result;
   
   query_all_in_progress = 1;
   
   printf("Query all start\n");
   
   result = dhcpv4c_get_ert_lease_time(&Value);
   printf("dhcpv4_get_ert_lease_time - result=%d pValue = %d\n",  result, *pValue);
    
   result = dhcp4c_get_ert_remain_lease_time(pValue); 
   printf("dhcpv4_get_ert_remain_lease_time - result=%d pValue = %d\n",  result, *pValue);
    
   result = dhcpv4c_get_ert_remain_renew_time(pValue);
   printf("dhcpv4_get_ert_remain_renew_time - result=%d pValue = %d\n",  result, *pValue);
    
   result = dhcpv4c_get_ert_remain_rebind_time(pValue);
   printf("dhcpv4_get_ert_remain_rebind_time - result=%d pValue = %d\n",  result, *pValue);
    
   result = dhcpv4c_get_ert_config_attempts(piValue);
   printf("dhcpv4_get_ert_config_attempts - result=%d piValue = %d\n",  result, *piValue);
    
   result = dhcpv4c_get_ert_ifname(pName);
   printf("dhcpv4_get_ert_ifname - result=%d pName = [%s]\n",  result, pName);
    
   result = dhcpv4c_get_ert_fsm_state(piValue);
   printf("dhcpv4_get_ert_fsm_state - result=%d piValue = %d\n",  result, *piValue);
    
   result = dhcpv4c_get_ert_ip_addr(pValue);
   printf("dhcpv4_get_ert_ip_addr - result=%d pValue = %04X\n",  result, *pValue);
    
   result = dhcpv4c_get_ert_mask(pValue);
   printf("dhcpv4_get_ert_mask - result=%d pValue = %04X\n",  result, *pValue);
    
   result = dhcpv4c_get_ert_gw(pValue);
   printf("dhcpv4_get_ert_gw - result=%d pValue = %04X\n",  result, *pValue);
    
   result = dhcpv4c_get_ert_dns_svrs(pList);
   printf("dhcpv4_get_ert_dns_svrs - result=%d num_servers = %d\n",  result, pList->number);
   for (i=0;i<pList->number;i++)
   {
      printf("    server [%d] = %04X\n", i, pList->addrs[i]);
   }
   
   result = dhcpv4c_get_ert_dhcp_svr(pValue);
   printf("dhcpv4_get_ert_dhcp_svr - result=%d pValue = %04X\n",  result, *pValue);
 
   result = dhcpv4c_get_ecm_lease_time(pValue);
   printf("dhcpv4_get_ecm_lease_time - result=%d pValue = %d\n",  result, *pValue); 
    
   result = dhcpv4c_get_ecm_remain_lease_time(pValue);
   printf("dhcpv4_get_ecm_remain_lease_time - result=%d pValue = %d\n",  result, *pValue);  
    
   result = dhcpv4c_get_ecm_remain_renew_time(pValue);
   printf("dhcpv4_get_ecm_remain_renew_time - result=%d pValue = %d\n",  result, *pValue);  
    
   result = dhcpv4c_get_ecm_remain_rebind_time(pValue);
   printf("dhcpv4_get_ecm_remain_rebind_time - result=%d pValue = %d\n",  result, *pValue);  
    
   result = dhcpv4c_get_ecm_config_attempts(piValue);
   printf("dhcpv4_get_ecm_config_attempts - result=%d piValue = %d\n",  result, *piValue);
    
   result = dhcpv4c_get_ecm_ifname(pName);
   printf("dhcpv4_get_ecm_ifname - result=%d pName = [%s]\n",  result, pName);
    
   result = dhcpv4c_get_ecm_fsm_state(piValue);
   printf("dhcpv4_get_ecm_fsm_state - result=%d piValue = %d\n",  result, *piValue);
    
   result = dhcpv4c_get_ecm_ip_addr(pValue);
   printf("dhcpv4_get_ecm_ip_addr - result=%d pValue = %04X\n",  result, *pValue);
    
   result = dhcpv4c_get_ecm_mask(pValue);
   printf("dhcpv4_get_ecm_mask - result=%d pValue = %04X\n",  result, *pValue);
    
   result = dhcpv4c_get_ecm_gw(pValue);
   printf("dhcpv4_get_ecm_gw - result=%d pValue = %04X\n",  result, *pValue);
    
   result = dhcpv4c_get_ecm_dns_svrs(pList); 
   printf("dhcpv4_get_ecm_dns_svrs - result=%d num_servers = %d\n",  result, pList->number);
   for (i=0;i<pList->number;i++)
   {
      printf("    server [%d] = %04X\n", i, pList->addrs[i]);
   }
   
   result = dhcpv4c_get_ecm_dhcp_svr(pValue);
   printf("dhcpv4_get_ecm_dhcp_svr - result=%d pValue = %04X\n",  result, *pValue);
 
   result = dhcpv4c_get_emta_remain_lease_time(pValue);
   printf("dhcpv4_get_emta_remain_lease_time - result=%d pValue = %d\n",  result, *pValue);  
    
   result = dhcpv4c_get_emta_remain_renew_time(pValue);
   printf("dhcpv4_get_ecm_remain_renew_time - result=%d pValue = %d\n",  result, *pValue);  
    
   result = dhcpv4c_get_emta_remain_rebind_time(pValue);
   printf("dhcpv4_get_ecm_remain_rebind_time - result=%d pValue = %d\n",  result, *pValue);  
    
   printf("Query all end\n");
   
   query_all_in_progress = 0;
}

#endif



