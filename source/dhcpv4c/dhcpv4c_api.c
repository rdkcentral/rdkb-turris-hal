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

    copyright:

        Cisco Systems, Inc., 2014
        All Rights Reserved.

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



