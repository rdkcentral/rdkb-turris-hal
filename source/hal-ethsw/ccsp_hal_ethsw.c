 /*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2019 RDK Management
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdbool.h>

#include "ccsp_hal_ethsw.h" 


/**********************************************************************
                    DEFINITIONS
**********************************************************************/

#define  CcspHalEthSwTrace(msg)                     printf("%s - ", __FUNCTION__); printf msg;
#define MAX_BUF_SIZE 1024
#define MACADDRESS_SIZE 6
#define ETH_WAN_INTERFACE  "erouter0"
#define LM_ARP_ENTRY_FORMAT  "%63s %63s %63s %63s %17s %63s"

#define  ETH_WAN_IFNAME   "eth0"

#if defined(FEATURE_RDKB_WAN_MANAGER)
static pthread_t ethsw_tid;
static int hal_init_done = 0;
appCallBack ethWanCallbacks;
#define  ETH_INITIALIZE  "/tmp/ethagent_initialized"
#define  LINK_VALUE_SIZE  50
#define  ETH_WAN_IFNAME   "eth2"
#endif

/**********************************************************************
                            MAIN ROUTINES
**********************************************************************/

CCSP_HAL_ETHSW_ADMIN_STATUS admin_status;

int is_interface_exists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return 1;
    }
        return 0;
}

#if defined(FEATURE_RDKB_WAN_MANAGER)
void *ethsw_thread_main(void *context __attribute__((unused)))
{
   FILE *fp = NULL;
   char command[128] = {0};
   char* buff = NULL, *pLink;
   char previousLinkDetected[10]="no";
   int timeout = 0;
   int file = 0;

   buff = malloc(sizeof(char)*50);
   if(buff == NULL)
    {
        return (void *) 1;
    }

   while(timeout != 180)
    {
       if (file == access(ETH_INITIALIZE, R_OK))
       {
            CcspHalEthSwTrace(("Eth agent initialized \n"));
            break;
       }
       else
       {
           timeout = timeout+1;
           sleep(1);
       }
    }

   while(1)
    {
        memset(buff,0,sizeof(buff));
        snprintf(command,128, "ethtool erouter0 | grep \"Link detected\" | cut -d ':' -f2 | cut -d ' ' -f2");
        fp = popen(command, "r");
          if (fp == NULL)
          {
                continue;
          }
          while (fgets(buff, LINK_VALUE_SIZE, fp) != NULL)
          {
                pLink = strchr(buff, '\n');
                if(pLink)
                    *pLink = '\0';
          }
          pclose(fp);
        if (strcmp(buff, (const char *)previousLinkDetected))
        {
            if (strcmp(buff, "yes") == 0)
	    {
		CcspHalEthSwTrace(("send_link_event: Got Link UP Event\n"));
                ethWanCallbacks.pGWP_act_EthWanLinkUP();    
            }
            else
            {
		 CcspHalEthSwTrace(("send_link_event: Got Link DOWN Event\n"));
                 ethWanCallbacks.pGWP_act_EthWanLinkDown();   
            }
            memset(previousLinkDetected, 0, sizeof(previousLinkDetected));
            strcpy((char *)previousLinkDetected, buff);
        }
        sleep(5);
    }
    if(buff != NULL)
        free(buff);
    return NULL;
}

void GWP_RegisterEthWan_Callback(appCallBack *obj) {
    int rc;

    if (obj == NULL) {
        rc = RETURN_ERR;
    } else {
        ethWanCallbacks.pGWP_act_EthWanLinkUP = obj->pGWP_act_EthWanLinkUP;
        ethWanCallbacks.pGWP_act_EthWanLinkDown = obj->pGWP_act_EthWanLinkDown;
        rc = RETURN_OK;
    }

    return;
}

INT
    GWP_GetEthWanInterfaceName
(
 unsigned char * Interface,
 ULONG           maxSize
 )
{
    //Maxsize param should be minimum 4charecters(eth0) including NULL charecter	
    if( ( Interface == NULL ) || ( maxSize < ( strlen( ETH_WAN_IFNAME ) + 1 ) ) )
    {
        printf("ERROR: Invalid argument. \n");
        return RETURN_ERR;
    }

    snprintf(Interface, maxSize, "%s", ETH_WAN_IFNAME);
    return RETURN_OK;
}
#endif

/* CcspHalEthSwInit :  */
/**
* @description Do what needed to intialize the Eth hal.
* @param None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwInit
    (
        void
    )
{
#if defined(FEATURE_RDKB_WAN_MANAGER)
    int rc;

    if (hal_init_done) {
        return RETURN_OK;
    }

    // Create thread to handle async events and callbacks.
    rc = pthread_create(&ethsw_tid, NULL, ethsw_thread_main, NULL);
    if (rc != 0) {
        return RETURN_ERR;
    }

    hal_init_done = 1;
#endif
       	return  RETURN_OK;
}


/* CcspHalEthSwGetPortStatus :  */
/**
* @description Retrieve the current port status -- link speed, duplex mode, etc.

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param pLinkRate   -- Receives the current link rate, as in CCSP_HAL_ETHSW_LINK_RATE
* @param pDuplexMode -- Receives the current duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE
* @param pStatus     -- Receives the current link status, as in CCSP_HAL_ETHSW_LINK_STATUS

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwGetPortStatus
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        PCCSP_HAL_ETHSW_LINK_RATE   pLinkRate,
        PCCSP_HAL_ETHSW_DUPLEX_MODE pDuplexMode,
        PCCSP_HAL_ETHSW_LINK_STATUS pStatus
    )
{
  char *path;
  path = (char *)malloc(20);
  path="/sys/class/net/eth1";

  int eth_if = is_interface_exists(path);

  if(!admin_status && eth_if)
       *pStatus  = CCSP_HAL_ETHSW_LINK_Up;
  else
       *pStatus   = CCSP_HAL_ETHSW_LINK_Down;


    switch (PortId)
    {
        case CCSP_HAL_ETHSW_EthPort1:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_100Mbps;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Full;
            break;
        }

        case CCSP_HAL_ETHSW_EthPort2:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_1Gbps;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Full;
            break;
        }

        case CCSP_HAL_ETHSW_EthPort3:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
            break;
        }

        case CCSP_HAL_ETHSW_EthPort4:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
            break;
        }

        default:
        {
            CcspHalEthSwTrace(("Unsupported port id %d\n", PortId));
            return  RETURN_ERR;
        }
    }
    return  RETURN_OK;
}


/* CcspHalEthSwGetPortCfg :  */
/**
* @description Retrieve the current port config -- link speed, duplex mode, etc.

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param pLinkRate   -- Receives the current link rate, as in CCSP_HAL_ETHSW_LINK_RATE
* @param pDuplexMode -- Receives the current duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwGetPortCfg
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        PCCSP_HAL_ETHSW_LINK_RATE   pLinkRate,
        PCCSP_HAL_ETHSW_DUPLEX_MODE pDuplexMode
    )
{
    switch (PortId)
    {
        case CCSP_HAL_ETHSW_EthPort1:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_Auto;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort2:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_1Gbps;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Full;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort3:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_100Mbps;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort4:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_10Mbps;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Half;

            break;
        }

        default:
        {
            CcspHalEthSwTrace(("Unsupported port id %d", PortId));
            return  RETURN_ERR;
        }
    }

    return  RETURN_OK;
}


/* CcspHalEthSwSetPortCfg :  */
/**
* @description Set the port configuration -- link speed, duplex mode

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param LinkRate    -- Set the link rate, as in CCSP_HAL_ETHSW_LINK_RATE
* @param DuplexMode  -- Set the duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwSetPortCfg
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        CCSP_HAL_ETHSW_LINK_RATE    LinkRate,
        CCSP_HAL_ETHSW_DUPLEX_MODE  DuplexMode
    )
{
    CcspHalEthSwTrace(("set port %d LinkRate to %d, DuplexMode to %d", PortId, LinkRate, DuplexMode));

    switch (PortId)
    {
        case CCSP_HAL_ETHSW_EthPort1:
        {
            break;
        }

        case CCSP_HAL_ETHSW_EthPort2:
        {
            break;
        }

        case CCSP_HAL_ETHSW_EthPort3:
        {
            break;
        }

        case CCSP_HAL_ETHSW_EthPort4:
        {
            break;
        }

        default:
            CcspHalEthSwTrace(("Unsupported port id %d", PortId));
            return  RETURN_ERR;
    }

    return  RETURN_OK;
}


/* CcspHalEthSwGetPortAdminStatus :  */
/**
* @description Retrieve the current port admin status.

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param pAdminStatus -- Receives the current admin status

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwGetPortAdminStatus
    (
        CCSP_HAL_ETHSW_PORT           PortId,
        PCCSP_HAL_ETHSW_ADMIN_STATUS  pAdminStatus
    )
{
 CcspHalEthSwTrace(("port id %d", PortId));
  *pAdminStatus   = CCSP_HAL_ETHSW_AdminUp;
  return RETURN_OK;
}

/* CcspHalEthSwSetPortAdminStatus :  */
/**
* @description Set the ethernet port admin status

* @param AdminStatus -- set the admin status, as defined in CCSP_HAL_ETHSW_ADMIN_STATUS

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwSetPortAdminStatus
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        CCSP_HAL_ETHSW_ADMIN_STATUS AdminStatus
    )
{
    CcspHalEthSwTrace(("set port %d AdminStatus to %d", PortId, AdminStatus));

    char cmd1[50];
    char cmd2[50];
    int port_num=0;
    FILE *fp = NULL;

    char port_id[150];
    char *val = "/1-1.";
    char *val1 = "/1-1.1.";
    char *p = NULL;

    char *interface = NULL;
    char *path = NULL;
    interface = (char *)malloc(5);
    path = (char *)malloc(20);
    strcpy(path,"/sys/class/net/eth1");

    int eth_if=is_interface_exists(path);

    if(eth_if == 0 )
        return  RETURN_ERR;

    fp= popen("ls -la /sys/class/net/ | awk '/eth1/{portId=$11}   END {print portId}'","r");
    fgets(port_id,sizeof(port_id),fp);
    if (strstr(port_id,val1)){
        p = strstr(port_id,val1);
        p = strtok(p,".");
        p = strtok(NULL,".");
        p = strtok(NULL,"/");
        port_num = atoi(p);
        if (port_num == 2)
                port_num = port_num + 2;
        else
                port_num = port_num;
    }
    else{
        p = strstr(port_id,val);
        p = strtok(p,".");
        p = strtok(NULL,"/");
        port_num = atoi(p);
        port_num = port_num - 1;
    }

    strcpy(interface,"eth1");

    sprintf(cmd1,"ip link set %s up",interface);
    sprintf(cmd2,"ip link set %s down",interface);

    switch (PortId)
    {
        case CCSP_HAL_ETHSW_EthPort1:
        case CCSP_HAL_ETHSW_EthPort2:
        case CCSP_HAL_ETHSW_EthPort3:
        case CCSP_HAL_ETHSW_EthPort4:
        {
            if(port_num==PortId)
            {
                 if(AdminStatus==0)
                 {
                    system(cmd1);
                    admin_status=0;
                 }
                 else
                 {
                     system(cmd2);
                     admin_status=1;
                 }
             }
             break;
        }
        default:
            CcspHalEthSwTrace(("Unsupported port id %d", PortId));
            return  RETURN_ERR;
    }
    return  RETURN_OK;
}


/* CcspHalEthSwSetAgingSpeed :  */
/**
* @description Set the ethernet port configuration -- admin up/down, link speed, duplex mode

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param AgingSpeed  -- integer value of aging speed
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwSetAgingSpeed
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        INT                         AgingSpeed
    )
{
    CcspHalEthSwTrace(("set port %d aging speed to %d", PortId, AgingSpeed));

    return  RETURN_OK;
}


/* CcspHalEthSwLocatePortByMacAddress :  */
/**
* @description Retrieve the port number that the specificed MAC address is associated with (seen)

* @param pMacAddr    -- Specifies the MAC address -- 6 bytes
* @param pPortId     -- Receives the found port number that the MAC address is seen on

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.

*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT
CcspHalEthSwLocatePortByMacAddress
    (
		unsigned char * pMacAddr, 
		INT * pPortId
    )
{
    CcspHalEthSwTrace
        ((
            "%s -- search for MAC address %02u.%02u.%02u.%02u.%02u.%02u",
            __FUNCTION__,
            pMacAddr[0], pMacAddr[1], pMacAddr[2], 
            pMacAddr[3], pMacAddr[4], pMacAddr[5]
        ));

    *pPortId = CCSP_HAL_ETHSW_EthPort4;

    return  RETURN_OK;
}

//For Getting Current Interface Name from corresponding hostapd configuration
void GetInterfaceName(char *interface_name, char *conf_file)
{
        FILE *fp = NULL;
        char path[MAX_BUF_SIZE] = {0},output_string[MAX_BUF_SIZE] = {0},fname[MAX_BUF_SIZE] = {0};
        int count = 0;
        char *interface = NULL;

        fp = fopen(conf_file, "r");
        if(fp == NULL)
        {
                printf("conf_file %s not exists \n", conf_file);
                return;
        }
        fclose(fp);

        sprintf(fname,"%s%s%s","cat ",conf_file," | grep interface=");
        fp = popen(fname,"r");
        if(fp == NULL)
        {
                        printf("Failed to run command in Function %s\n",__FUNCTION__);
                        strcpy(interface_name, "");
                        return;
        }
        if(fgets(path, sizeof(path)-1, fp) != NULL)
        {
                        interface = strchr(path,'=');

                        if(interface != NULL)
                                strcpy(output_string, interface+1);
        }

        for(count = 0;output_string[count]!='\n';count++)
                        interface_name[count] = output_string[count];
        interface_name[count]='\0';

        fprintf(stderr,"Interface name %s \n", interface_name);

        pclose(fp);
}
/* CcspHalExtSw_getAssociatedDevice :  */
/**
* @description Collected the active wired clients information

* @param output_array_size    -- Size of the active wired connected clients
* @param output_struct     -- Structure of  wired clients informations

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_getAssociatedDevice(ULONG *output_array_size, eth_device_t **output_struct)
{
	CHAR buf[MAX_BUF_SIZE] = {0},str[MAX_BUF_SIZE] = {0},interface_name[50] = {0},macAddr[50] = {0};
	FILE *fp = NULL,*fp1 = NULL;
	INT count = 0,str_count = 0;
	ULONG maccount = 0,eth_count = 0;
	INT arr[MACADDRESS_SIZE] = {0};
	UCHAR mac[MACADDRESS_SIZE] = {0};
	CHAR ipAddr[50],stub[50],phyAddr[50],ifName[32],status[32];
	int ret;
	if(output_struct == NULL)
	{
		printf("\nNot enough memory\n");
		return RETURN_ERR;
	}
	if( access( "/tmp/ethernetmac.txt", F_OK ) != -1 ) {
		remove("/tmp/ethernetmac.txt");
	}
	system("cat /nvram/dnsmasq.leases | cut -d ' ' -f2 > /tmp/connected_mac.txt"); //storing the all associated device information in tmp folder
	//storing the private wifi  associated device iformation in tmp folder
	GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	sprintf(buf,"iw dev %s station dump | grep Station | cut -d ' ' -f2 > /tmp/Associated_Devices.txt",interface_name);
	system(buf);
	GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
	sprintf(buf,"iw dev %s station dump | grep Station | cut -d ' ' -f2 >> /tmp/Associated_Devices.txt",interface_name);
	system(buf);

	system("diff /tmp/Associated_Devices.txt /tmp/connected_mac.txt | grep \"^+\" | cut -c2- | sed -n '1!p' > /tmp/ethernet_connected_clients.txt"); //separating the ethernet associated device information from connected_mac test file
	fp=popen("cat /tmp/ethernet_connected_clients.txt | wc -l","r"); // For getting the  ethernet connected mac count
	if(fp == NULL)
		return RETURN_ERR;
	else
	{
		fgets(buf,MAX_BUF_SIZE,fp);
		maccount = atol(buf);
		fprintf(stderr,"ethernet umac is %d \n",maccount);
	}
	pclose(fp);
	eth_device_t *temp=NULL;
	temp = (eth_device_t*)calloc(1, sizeof(eth_device_t)*maccount);
	if(temp == NULL)
	{
		fprintf(stderr,"Not enough memory \n");
		return RETURN_ERR;
	}
	fp=fopen("/tmp/ethernet_connected_clients.txt","r"); // reading the ethernet associated device information
	if(fp == NULL)
	{
		*output_struct = NULL;
		*output_array_size = 0;
		return RETURN_ERR;
	}
	else
	{
		for(count = 0;count < maccount ; count++)
		{
			fgets(str,MAX_BUF_SIZE,fp);	
			for(str_count = 0;str[str_count]!='\n';str_count++)
				macAddr[str_count] = str[str_count];
			macAddr[str_count] = '\0';
			system("ip nei show | grep brlan0 > /tmp/arp_cache");
			fp1=fopen("/tmp/arp_cache","r");
			if(fp1 == NULL)
				return RETURN_ERR;

			while(fgets(buf,sizeof(buf),fp1) != NULL)
			{
				if ( strstr(buf, "FAILED") != 0 )
					continue;
				/*
Sample:
10.0.0.208 dev brlan0 lladdr d4:be:d9:99:7f:47 STALE
10.0.0.107 dev brlan0 lladdr 64:a2:f9:d2:f5:67 REACHABLE
				 */
				ret = sscanf(buf, LM_ARP_ENTRY_FORMAT,
						ipAddr,
						stub,
						ifName,
						stub,
						phyAddr,
						status);  
				if(ret != 6)
					continue;
				if(strcmp(phyAddr,macAddr) == 0)
				{
					memset(buf,0,sizeof(buf));
					if(strcmp(status,"REACHABLE") == 0)
					{
						sprintf(buf,"echo %s >> /tmp/ethernetmac.txt",macAddr);
						system(buf);
						eth_count++;
						break;
					}
					else if((strcmp(status,"STALE") == 0) || (strcmp(status,"DELAY")))
					{
						sprintf(buf,"ping -q -c 1 -W 1  \"%s\"  > /dev/null 2>&1",ipAddr);
						fprintf(stderr,"buf is %s and MACADRRESS %s\n",buf,macAddr);
						if (WEXITSTATUS(system(buf)) == 0)
						{
							fprintf(stderr,"Inside STALE SUCCESS \n");
							memset(buf,0,sizeof(buf));
							sprintf(buf,"echo %s >> /tmp/ethernetmac.txt",macAddr);
							system(buf);
							eth_count++;
							break;
						}
					}
					else
					{
						fprintf(stderr,"Running in different state \n");
						break;
					}
				}
				else
					fprintf(stderr,"MAcAddress is not valid \n");
			}
			fclose(fp1);
		}
	}
	fclose(fp);
	fp=fopen("/tmp/ethernetmac.txt","r");
	if(fp == NULL)
	{
		*output_struct = NULL;
		*output_array_size = 0;
		return RETURN_OK;
	}
	else
	{
		memset(buf,0,sizeof(buf));
		for(count = 0;count < eth_count ; count++)
		{
			fgets(buf,sizeof(buf),fp);
				if(MACADDRESS_SIZE  == sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( int ethclientindex = 0; ethclientindex < 6; ++ethclientindex )
					{
						mac[ethclientindex] = (unsigned char) arr[ethclientindex];
					}
					memcpy(temp[count].eth_devMacAddress,mac,(sizeof(unsigned char))*6);
					fprintf(stderr,"MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].eth_devMacAddress[0],temp[count].eth_devMacAddress[1], temp[count].eth_devMacAddress[2], temp[count].eth_devMacAddress[3], temp[count].eth_devMacAddress[4], temp[count].eth_devMacAddress[5]);
				}
			temp[count].eth_port=1;
			temp[count].eth_vlanid=10;
			temp[count].eth_devTxRate=100;
			temp[count].eth_devRxRate=100;
			temp[count].eth_Active=1;

		}
	}
	fclose(fp);
	*output_struct = temp;
	*output_array_size = eth_count;
	fprintf(stderr,"Connected Active ethernet clients count is %ld \n",*output_array_size);
	return 	RETURN_OK;
}

/* CcspHalExtSw_getEthWanEnable  */
/**
* @description Return the Ethwan Enbale status

* @param enable    -- Having status of WANMode ( Ethernet,DOCSIS)

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_getEthWanEnable(BOOLEAN *enable)
{
	*enable = 1; // Raspberrypi doesn't have docsis support.so, it always return as 1.
	return RETURN_OK;
}

/* CcspHalExtSw_getEthWanPort:  */
/**
* @description Return the ethwan port

* @param port    -- having ethwan port

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_getEthWanPort(UINT *Port)
{
	*Port = 20;
	return RETURN_OK;
}

/* CcspHalExtSw_setEthWanEnable :  */
/**
* @description setting the ethwan enable status

* @enable    -- Switch from ethernet mode to docsis mode or vice-versa

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_setEthWanEnable(BOOLEAN enable)
{
	enable = 0;
	return RETURN_OK;
}


/* CcspHalExtSw_setEthWanPort :  */
/**
* @description  Need to set the ethwan port

* @param port    -- Setting the ethwan port

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_setEthWanPort(UINT Port)
{
	Port = 20;
	return RETURN_OK;
}

bool turrisNet_isInterfaceLinkUp(const char *ifname)
{
	int  skfd;
	struct ifreq intf;
	bool isUp = FALSE;

	if(ifname == NULL) {
		return FALSE;
	}

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return FALSE;
	}

	strcpy(intf.ifr_name, ifname);

	if (ioctl(skfd, SIOCGIFFLAGS, &intf) == -1) {
		isUp = 0;
	} else {
		isUp = (intf.ifr_flags & IFF_RUNNING) ? TRUE : FALSE;
	}

	close(skfd);
	return isUp;
}

INT GWP_GetEthWanLinkStatus()
{
	INT status = 0;
	status = turrisNet_isInterfaceLinkUp(ETH_WAN_INTERFACE) ? TRUE : FALSE;
	return status;
}

