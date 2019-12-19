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

#define HAL_NETLINK_IMPL

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include "wifi_hal.h"

#ifdef HAL_NETLINK_IMPL
#include <errno.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#endif

#define MAC_ALEN 6

#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define IF_NAMESIZE 10
#define CONFIG_PREFIX "/nvram/hostapd"

#ifndef AP_PREFIX
#define AP_PREFIX	"wlan"
#endif

#ifndef RADIO_PREFIX
#define RADIO_PREFIX	"wifi"
#endif

#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024

#define WIFI_DEBUG 

#ifdef WIFI_DEBUG
#define wifi_dbg_printf printf
#define WIFI_ENTRY_EXIT_DEBUG printf
#else
#define wifi_dbg_printf(format,args...) printf("")
#define WIFI_ENTRY_EXIT_DEBUG(format,args...) printf("")
#endif

#define HOSTAPD_CONF_0 "/nvram/hostapd0.conf"   //private-wifi-2g
#define HOSTAPD_CONF_1 "/nvram/hostapd1.conf"   //private-wifi-5g
#define HOSTAPD_CONF_4 "/nvram/hostapd4.conf"   //public-wifi-2g
#define HOSTAPD_CONF_5 "/nvram/hostapd5.conf"   //public-wifi-5g
#define DEF_HOSTAPD_CONF_0 "/usr/ccsp/wifi/hostapd0.conf"
#define DEF_HOSTAPD_CONF_1 "/usr/ccsp/wifi/hostapd1.conf"
#define DEF_HOSTAPD_CONF_4 "/usr/ccsp/wifi/hostapd4.conf"
#define DEF_HOSTAPD_CONF_5 "/usr/ccsp/wifi/hostapd5.conf"
#define DEF_RADIO_PARAM_CONF "/usr/ccsp/wifi/radio_param_def.cfg"
#define LM_DHCP_CLIENT_FORMAT   "%63d %17s %63s %63s"

#define BW_FNAME "/nvram/bw_file.txt"

#define PS_MAX_TID 16

static wifi_radioQueueType_t _tid_ac_index_get[PS_MAX_TID] = {
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 0 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 1 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 2 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 3 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 4 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 5 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 6 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 7 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 8 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 9 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 10 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 11 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 12 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 13 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 14 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 15 */
};

typedef unsigned long long  u64;

/* Enum to define WiFi Bands */
typedef enum
{
    band_invalid = -1,
    band_2_4 = 0,
    band_5 = 1,
} wifi_band;

#ifdef HAL_NETLINK_IMPL
typedef struct {
    int id;
    struct nl_sock* socket;
    struct nl_cb* cb;
} Netlink;

static int mac_addr_aton(unsigned char *mac_addr, char *arg)
{
    unsigned int mac_addr_int[6]={};
    sscanf(arg, "%x:%x:%x:%x:%x:%x", mac_addr_int+0, mac_addr_int+1, mac_addr_int+2, mac_addr_int+3, mac_addr_int+4, mac_addr_int+5);
    mac_addr[0] = mac_addr_int[0];
    mac_addr[1] = mac_addr_int[1];
    mac_addr[2] = mac_addr_int[2];
    mac_addr[3] = mac_addr_int[3];
    mac_addr[4] = mac_addr_int[4];
    mac_addr[5] = mac_addr_int[5];
    return 0;
}

static void mac_addr_ntoa(char *mac_addr, unsigned char *arg)
{
    unsigned int mac_addr_int[6]={};
    mac_addr_int[0] = arg[0];
    mac_addr_int[1] = arg[1];
    mac_addr_int[2] = arg[2];
    mac_addr_int[3] = arg[3];
    mac_addr_int[4] = arg[4];
    mac_addr_int[5] = arg[5];
    snprintf(mac_addr, 20, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr_int[0], mac_addr_int[1],mac_addr_int[2],mac_addr_int[3],mac_addr_int[4],mac_addr_int[5]);
    return;
}

static int ieee80211_frequency_to_channel(int freq)
{
    if (freq == 2484)
        return 14;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq <= 45000)
        return (freq - 5000) / 5;
    else if (freq >= 58320 && freq <= 64800)
        return (freq - 56160) / 2160;
    else
        return 0;
}

static int initSock80211(Netlink* nl) {
    nl->socket = nl_socket_alloc();
    if (!nl->socket) {
        fprintf(stderr, "Failing to allocate the  sock\n");
        return -ENOMEM;
    }

    nl_socket_set_buffer_size(nl->socket, 8192, 8192);

    if (genl_connect(nl->socket)) {
        fprintf(stderr, "Failed to connect\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOLINK;
    }

    nl->id = genl_ctrl_resolve(nl->socket, "nl80211");
    if (nl->id< 0) {
        fprintf(stderr, "interface not found.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOENT;
    }

    nl->cb = nl_cb_alloc(NL_CB_DEFAULT);
    if ((!nl->cb)) {
        fprintf(stderr, "Failed to allocate netlink callback.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return ENOMEM;
    }

    return nl->id;
}

static int nlfree(Netlink *nl)
{
    nl_cb_put(nl->cb);
    nl_close(nl->socket);
    nl_socket_free(nl->socket);
    return 0;
}

static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED }
};

static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
};

static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
};

typedef struct _wifi_channelStats_loc {
    INT array_size;
    INT  ch_number;
    BOOL ch_in_pool;
    INT  ch_noise;
    BOOL ch_radar_noise;
    INT  ch_max_80211_rssi;
    INT  ch_non_80211_noise;
    INT  ch_utilization;
    ULLONG ch_utilization_total;
    ULLONG ch_utilization_busy;
    ULLONG ch_utilization_busy_tx;
    ULLONG ch_utilization_busy_rx;
    ULLONG ch_utilization_busy_self;
    ULLONG ch_utilization_busy_ext;
} wifi_channelStats_t_loc;

typedef struct wifi_device_info {
    INT  wifi_devIndex;
    UCHAR wifi_devMacAddress[6];
    CHAR wifi_devIPAddress[64];
    BOOL wifi_devAssociatedDeviceAuthentiationState;
    INT  wifi_devSignalStrength;
    INT  wifi_devTxRate;
    INT  wifi_devRxRate;
} wifi_device_info_t;

#endif

//For 5g Alias Interfaces
static BOOL priv_flag = TRUE;
static BOOL pub_flag = TRUE;
static BOOL Radio_flag = TRUE;
//wifi_setApBeaconRate(1, beaconRate);

struct params
{
    char * name;
    char * value;
};

static int wifi_hostapdRead(char *conf_file, char *param ,char *output, int output_size)
{
    char cmd[MAX_CMD_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE]={'\0'};
    int ret = 0;
    sprintf(cmd, "cat %s | grep \"^%s=\" | cut -d \"=\"  -f 2 | head -n1 | tr -d \"\\n\"", conf_file, param);
    ret = _syscmd(cmd,buf,sizeof(buf));
    if ((ret != 0) && (strlen(buf) == 0))
        return -1;
    strncpy(output,buf,output_size);
    return 0;
}

static int wifi_hostapdWrite(char *conf_file, struct params *list,int item_count)
{
    char cmd[MAX_CMD_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE]={'\0'};
    int ret = 0;
    for(int i=0;i<item_count;i++)
    {
        wifi_hostapdRead(conf_file, list[i].name, buf,MAX_BUF_SIZE);
        if (strlen(buf) == 0) {
            //Insert
            sprintf(cmd, "echo \"%s=%s\" >> %s", list[i].name, list[i].value, conf_file);
        } else {
            //Update
            sprintf(cmd, "sed -i \"s/^%s=.*/%s=%s/\" %s", list[i].name,list[i].name,list[i].value,conf_file);
        }
        ret = _syscmd(cmd,buf,sizeof(buf));
        if (ret != 0)
            return -1;
    }
    return 0;
}

int GetInterfaceNameFromIdx(int radio_index, char *interface_name)
{
    char config_file[MAX_BUF_SIZE] = {0};
    sprintf(config_file,"%s%d.conf", CONFIG_PREFIX,radio_index);
    return GetInterfaceName(config_file, interface_name);
}

//For Getting Current Interface Name from corresponding hostapd configuration
void GetInterfaceName(char *interface_name, char *conf_file)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_hostapdRead(conf_file,"interface",interface_name,IF_NAMESIZE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return 0;
}

INT File_Reading(CHAR *file, char *Value)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
	char buf[MAX_CMD_SIZE] = {0}, copy_buf[MAX_CMD_SIZE] ={0};
	int count = 0;

	fp = popen(file,"r");
	if(fp == NULL)
	{
			return RETURN_ERR;
	}

	if(fgets(buf,sizeof(buf) -1,fp) != NULL)
	{
			for(count=0;buf[count]!='\n';count++)
					copy_buf[count]=buf[count];
			copy_buf[count]='\0';
	}
	strcpy(Value,copy_buf);
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Restarting the hostapd process
void restarthostapd_all(char *hostapd_configuration)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[512] = {0};
	sprintf(buf,"%s%s%s","ps -eaf | grep ",hostapd_configuration," | grep -v grep | awk '{print $1}' | xargs kill -9");
	system(buf);
	system("sleep 3");
	sprintf(buf,"%s%s","/usr/sbin/hostapd -B ",hostapd_configuration);
	system(buf);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartHostapd_5G(INT radioIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	if(radioIndex == 1)
		system("ps -eaf | grep hostapd1.conf | grep -v grep | awk '{print $1}' | xargs kill -9");
	else if(radioIndex == 5)
		system("ps -eaf | grep hostapd5.conf | grep -v grep | awk '{print $1}' | xargs kill -9");

	system("rmmod rtl8812au && rmmod 88x2bu");
	system("sleep 3");
	system("modprobe rtl8812au && modprobe 88x2bu");
	system("sleep 5");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartHostapd_2G()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	system("ps -eaf | grep hostapd4.conf | grep -v grep | awk '{print $1}' | xargs kill -9");
	system("rmmod 8192eu");
	system("sleep 3");
	system("modprobe 8192eu");
	system("sleep 5");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartPrivateWifi_2G()
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[512] = {0};
	char interface_name[512] = {0},rpi_board_status[512] = {0};
	int count = 0;
	system("ps -eaf | grep hostapd0.conf | grep -v grep | awk '{print $1}' | xargs kill -9");
    system("sleep 2");
	_syscmd("cat /proc/device-tree/model | cut -d ' ' -f5-6",buf,sizeof(buf));

	for(count = 0;buf[count]!='\n';count++)
        rpi_board_status[count] = buf[count]; //ajusting the size
    
	rpi_board_status[count] = '\0';
	
	if(strcmp(rpi_board_status,"B Plus") == 0)
	{
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		sprintf(buf,"%s%s%s","ifconfig ",interface_name," down");		
		system(buf);
	}
	else
	{
        system("rmmod brcmfmac");
        system("sleep 3");
        system("modprobe brcmfmac");
        system("sleep 5");
	}
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    FILE *f;
    char *ptr = retBuf;
    int bufSize=retBufSize, bufbytes=0, readbytes=0;

    if((f = popen(cmd, "r")) == NULL) {
        fprintf(stderr,"\npopen %s error\n", cmd);
        return RETURN_ERR;
    }

    while(!feof(f))
    {
        *ptr = 0;
		if(bufSize>=128) {
		bufbytes=128;
		} else {
		bufbytes=bufSize-1;
		}
		
    	fgets(ptr,bufbytes,f); 
		readbytes=strlen(ptr);
        
		if( readbytes== 0)        
            break;
        
		bufSize-=readbytes;
        ptr += readbytes;
    }
    pclose(f);
    retBuf[retBufSize-1]=0;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
static int writeBandWidth(int radioIndex,char *bw_value)
{
	char buf[MAX_BUF_SIZE];
	char cmd[MAX_CMD_SIZE];
	sprintf(cmd,"sed -i 's/^SET_BW%d=.*$/SET_BW%d=%s/' %s",radioIndex,radioIndex,bw_value,BW_FNAME);
	_syscmd(cmd,buf,sizeof(buf));
	return RETURN_OK;
}

static int readBandWidth(int radioIndex,char *bw_value)
{
	char buf[MAX_BUF_SIZE];
	char cmd[MAX_CMD_SIZE];
	sprintf(cmd,"grep 'SET_BW%d=' %s | sed 's/^.*=//'",radioIndex,BW_FNAME);
	_syscmd(cmd,buf,sizeof(buf));
	if(NULL!=strstr(buf,"20MHz"))
	{
			strcpy(bw_value,"20MHz");
	}
	else if(NULL!=strstr(buf,"40MHz"))
	{
			strcpy(bw_value,"40MHz");
	}
	else
	{
		return RETURN_ERR;
	}
	return RETURN_OK;
}
/**************************************************************************/
/*! \fn void add_ifnames_in_bridge()
 **************************************************************************
 *  \brief This function add given interfaces in given bridges
 *  \param[in] bridge name,interface list seperated by comma',' or space' '
 *  \return void
 **************************************************************************/
static INT add_ifnames_in_bridge(char *bridge,char *ifnames_list)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char *list = ifnames_list;
    char command[MAX_BUF_SIZE] = "";
    char out[MAX_BUF_SIZE] = "";
    char *temp;

    sprintf(command,"ifconfig %s",bridge);

    if(RETURN_ERR == _syscmd(command,out,MAX_BUF_SIZE))
    {
        return RETURN_ERR;
    }
    if(strlen(out) == 0)
    {
      fprintf(stderr,"\nbridge interface is not Ready!!!\n");
      return RETURN_ERR;
    }

    temp = strtok(list,", ");
    while(temp != NULL)
    {
       /*adding interface in bridge*/
        sprintf(command, "brctl addif %s %s", bridge,temp);
        system(command);
        temp = strtok(NULL,", ");
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
/**************************************************************************/
/*! \fn static INT get_param_value(char *parameter, char *output)
 **************************************************************************
 *  \brief This function will get parameter value for passed parameter name
 *  \param[in] parameter- name of parameter
 *  \param[out] value- value of passed parameter
 *  \return (RETURN_OK/RETURN_ERR)
 **************************************************************************/
static INT get_param_value(char *parameter, char *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__); 
    FILE *f;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    char *param,*value;
    f = fopen(DEF_RADIO_PARAM_CONF, "r");
    if (f == NULL) {
        perror("fopen");
        wifi_dbg_printf("\n[%s]:Failed to open file %s\n",__func__,DEF_RADIO_PARAM_CONF);
        return RETURN_ERR;
    }
    while ((nread = getline(&line, &len, f)) != -1) {
        param = strtok(line,"=");
        value = strtok(NULL,"=");
        if( strcmp( parameter,param ) == 0 )
        {
            value[strlen(value)-1]='\0';
            strcpy(output,value);
        }
     }
     free(line);
     fclose(f);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/**************************************************************************/
/*! \fn statis INT prepare_hostapd_conf()
 **************************************************************************
 *  \brief This function will prepare hostapd conf in nvram from default conf
 *  \return (RETURN_OK/RETURN_ERR)
 **************************************************************************/
static INT prepare_hostapd_conf()
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[128];
    /* check  /usr/ccsp/wifi/hostapd0.conf, /usr/ccsp/wifi/hostapd0.conf , /usr/ccsp/wifi/hostapd4.conf,/usr/ccsp/wifi/hostapd5.conf exists or not */
	if(( access(DEF_HOSTAPD_CONF_0, F_OK) != -1 ) && ( access(DEF_HOSTAPD_CONF_1, F_OK) != -1 ) && ( access(DEF_HOSTAPD_CONF_4, F_OK) != -1 ) && ( access(DEF_HOSTAPD_CONF_5, F_OK) != -1 ))
	{
		wifi_dbg_printf("\n[%s]: Default files %s and %s presents!!\n",__func__,DEF_HOSTAPD_CONF_0,DEF_HOSTAPD_CONF_1);
	}
	else
	{
		wifi_dbg_printf("\n[%s]: Default files %s and %s not presents!!\n",__func__,DEF_HOSTAPD_CONF_0,DEF_HOSTAPD_CONF_1);
		return RETURN_ERR;
	}
    /* check  /nvram/hostapd0.conf exists or not */
	if( access(HOSTAPD_CONF_0, F_OK) != -1 )
	{
		wifi_dbg_printf("\n[%s]: %s file allready exits!!\n",__func__,HOSTAPD_CONF_0);
	}
	else
	{
		wifi_dbg_printf("\n[%s]: %s file does not exits. Preparing from %s file\n",__func__,HOSTAPD_CONF_0,DEF_HOSTAPD_CONF_0);
		sprintf(cmd, "cp %s %s",DEF_HOSTAPD_CONF_0,HOSTAPD_CONF_0);
		system(cmd);
	}

    /* check  /nvram/hostapd1.conf exists or not */
	if( access(HOSTAPD_CONF_1, F_OK) != -1 )
	{
		wifi_dbg_printf("\n[%s]: %s file allready exits!!\n",__func__,HOSTAPD_CONF_1);
	}
	else
	{
		wifi_dbg_printf("\n[%s]: %s file does not exits. Preparing from %s file\n",__func__,HOSTAPD_CONF_1,DEF_HOSTAPD_CONF_1);
		sprintf(cmd, "cp %s %s",DEF_HOSTAPD_CONF_1,HOSTAPD_CONF_1);
		system(cmd);
	}

    /* check  /nvram/hostapd4.conf exists or not */
	if( access(HOSTAPD_CONF_4, F_OK) != -1 )
	{
		wifi_dbg_printf("\n[%s]: %s file allready exits!!\n",__func__,HOSTAPD_CONF_4);
	}
	else
	{
		wifi_dbg_printf("\n[%s]: %s file does not exits. Preparing from %s file\n",__func__,HOSTAPD_CONF_4,DEF_HOSTAPD_CONF_4);
		sprintf(cmd, "cp %s %s",DEF_HOSTAPD_CONF_4,HOSTAPD_CONF_4);
		system(cmd);
	}

    /* check  /nvram/hostapd5.conf exists or not */
	if( access(HOSTAPD_CONF_5, F_OK) != -1 )
	{
		wifi_dbg_printf("\n[%s]: %s file allready exits!!\n",__func__,HOSTAPD_CONF_5);
	}
	else
	{
		wifi_dbg_printf("\n[%s]: %s file does not exits. Preparing from %s file\n",__func__,HOSTAPD_CONF_5,DEF_HOSTAPD_CONF_5);
		sprintf(cmd, "cp %s %s",DEF_HOSTAPD_CONF_5,HOSTAPD_CONF_5);
		system(cmd);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc)
{
    // TODO Implement me!
    return;
}

INT wifi_setApBeaconRate(INT radioIndex,CHAR *beaconRate)
{
	return 0;
}

INT wifi_getApBeaconRate(INT radioIndex, CHAR *beaconRate)
{
	return 0;
}

INT wifi_setLED(INT radioIndex, BOOL enable)
{
   return 0;
}

/**********************************************************************************
 *
 *  Wifi Subsystem level function prototypes 
 *
**********************************************************************************/
//---------------------------------------------------------------------------------------------------
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string)   //RDKB   
{
	snprintf(output_string, 64, "%d.%d.%d", WIFI_HAL_MAJOR_VERSION, WIFI_HAL_MINOR_VERSION, WIFI_HAL_MAINTENANCE_VERSION);
	return RETURN_OK;
}


/* wifi_factoryReset() function */
/**
* @description Clears internal variables to implement a factory reset of the Wi-Fi 
* subsystem. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryReset()
{
	char cmd[128];
	/*delete running hostapd conf files*/
	wifi_dbg_printf("\n[%s]: deleting hostapd conf file %s and %s",__func__,HOSTAPD_CONF_0,HOSTAPD_CONF_1);
	sprintf(cmd, "rm -rf %s %s",HOSTAPD_CONF_0,HOSTAPD_CONF_1);
	system(cmd);
	/*create new configuraion file from default configuration*/
	if(RETURN_ERR == prepare_hostapd_conf())
	{
		return RETURN_ERR;
	}
	return RETURN_OK;
}

/* wifi_factoryResetRadios() function */
/**
* @description Restore all radio parameters without touching access point parameters. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
*
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadios()
{	
	if((RETURN_OK == wifi_factoryResetRadio(0)) && (RETURN_OK == wifi_factoryResetRadio(1)))
	{
		return RETURN_OK;
	}
	return RETURN_ERR;
}


/* wifi_factoryResetRadio() function */
/**
* @description Restore selected radio parameters without touching access point parameters
*
* @param radioIndex - Index of Wi-Fi Radio channel
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
INT wifi_factoryResetRadio(int radioIndex) 	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(radioIndex == 0)
        system("cp /etc/hostapd-2G.conf /nvram/hostapd0.conf");
    else if(radioIndex == 1)
        system("cp /etc/hostapd-5G.conf /nvram/hostapd1.conf");
    else
         return RETURN_ERR;

    system("systemctl restart hostapd.service");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/* wifi_initRadio() function */
/**
* Description: This function call initializes the specified radio.
*  Implementation specifics may dictate the functionality since 
*  different hardware implementations may have different initilization requirements.
* Parameters : radioIndex - The index of the radio. First radio is index 0. 2nd radio is index 1   - type INT
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
INT wifi_initRadio(INT radioIndex)
{
  //TODO: Initializes the wifi subsystem (for specified radio)

  return RETURN_OK;
}
void macfilter_init()
{
    char count[4]={'\0'};
    char buf[253]={'\0'};
    char tmp[19]={'\0'};
    int dev_count,block,mac_entry=0;
    char res[4]={'\0'};
    char acl_file_path[64] = {'\0'};
    FILE *fp = NULL;
    int index=0;
    char iface[10]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};


    sprintf(acl_file_path,"/tmp/mac_filter.sh");

    fp=fopen(acl_file_path,"w+");
    sprintf(buf,"#!/bin/sh \n");
    fprintf(fp,"%s\n",buf);

    system("chmod 0777 /tmp/mac_filter.sh");

    for(index=0;index<=1;index++)
    {
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,index);
        wifi_hostapdRead(config_file,"interface",iface,64);
        sprintf(buf,"syscfg get %dcountfilter",index);
        _syscmd(buf,count,sizeof(count));
        mac_entry=atoi(count);

        sprintf(buf,"syscfg get %dblockall",index);
        _syscmd(buf,res,sizeof(res));
        block = atoi(res);

        //Allow only those macs mentioned in ACL
        if(block==1)
        {
             sprintf(buf,"iptables -N  WifiServices%d\n iptables -I INPUT 21 -j WifiServices%d\n",index,index);
             fprintf(fp,"%s\n",buf);
             for(dev_count=1;dev_count<=mac_entry;dev_count++)
             {
                 sprintf(buf,"syscfg get %dmacfilter%d",index,dev_count);
                 _syscmd(buf,tmp,sizeof(tmp));
                 fprintf(stderr,"MAcs to be Allowed  *%s*  ###########\n",tmp);
                 sprintf(buf,"iptables -I WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j RETURN",index,iface,tmp);
                 fprintf(fp,"%s\n",buf);
             }
             sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac ! --mac-source %s -j DROP",index,iface,tmp);
             fprintf(fp,"%s\n",buf);
       }

       //Block all the macs mentioned in ACL
       else if(block==2)
       {
             sprintf(buf,"iptables -N  WifiServices%d\n iptables -I INPUT 21 -j WifiServices%d\n",index,index);
             fprintf(fp,"%s\n",buf);

             for(dev_count=1;dev_count<=mac_entry;dev_count++)
             {
                  sprintf(buf,"syscfg get %dmacfilter%d",index,dev_count);
                  _syscmd(buf,tmp,sizeof(tmp));
                  fprintf(stderr,"MAcs to be blocked  *%s*  ###########\n",tmp);
                  sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j DROP",index,iface,tmp);
                  fprintf(fp,"%s\n",buf);
             }
       }
    }
    fclose(fp);
   return 0;
}

// Initializes the wifi subsystem (all radios)
INT wifi_init()                            //RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char interface[MAX_BUF_SIZE]={'\0'};
    char bridge_name[MAX_BUF_SIZE]={'\0'};
    INT len=0;

    macfilter_init();

	/* preparing hostapd configuration*/
	if(RETURN_ERR == prepare_hostapd_conf())
	{
		return RETURN_ERR;
	}

    if( ( RETURN_ERR == _syscmd("syscfg get lan_ifname",bridge_name,sizeof(bridge_name)) ) || 
        ( RETURN_ERR == _syscmd("iwconfig | grep -r \"IEEE 802.11\" | cut -d \" \" -f1 | tr '\n' ' '",interface,sizeof(interface)) ) )
    {
		return RETURN_ERR;
    }

    system("/usr/sbin/iw reg set US");
    system("systemctl start hostapd.service");
    sleep(2);//sleep to wait for hostapd to start

    if((strlen(bridge_name) > 0) && (strlen(interface) > 0) )
    {
          /* Removing '\n' from bridge_name because syscfg get lan_ifname returns bridge name terminating with '\n'*/
          len=strlen(bridge_name);
          if(bridge_name[len-1]=='\n')
          bridge_name[len-1]='\0';

          if(RETURN_ERR == add_ifnames_in_bridge(bridge_name,interface))
          {
              fprintf(stderr,"\nFailed to radio add interface in bridge\n");
              return RETURN_ERR;
          }
    }
    else
    {
        fprintf(stderr,"\n***Either bridge or Radio interfaces list are Empty***\n");
        return RETURN_ERR;
    }
    #ifdef USE_HOSTAPD_STRUCT
    read_hostapd_all_aps();
    #endif
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/* wifi_reset() function */
/**
* Description: Resets the Wifi subsystem.  This includes reset of all AP varibles.
*  Implementation specifics may dictate what is actualy reset since 
*  different hardware implementations may have different requirements.
* Parameters : None
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
INT wifi_reset()
{
	//TODO: resets the wifi subsystem, deletes all APs
  return RETURN_OK;
}

/* wifi_down() function */
/**
* @description Turns off transmit power for the entire Wifi subsystem, for all radios.
* Implementation specifics may dictate some functionality since 
* different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_down()
{
	//TODO: turns off transmit power for the entire Wifi subsystem, for all radios
  return RETURN_OK;
}


/* wifi_createInitialConfigFiles() function */
/**
* @description This function creates wifi configuration files. The format
* and content of these files are implementation dependent.  This function call is 
* used to trigger this task if necessary. Some implementations may not need this 
* function. If an implementation does not need to create config files the function call can 
* do nothing and return RETURN_OK.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_createInitialConfigFiles()
{
	//TODO: creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)

	return RETURN_OK;
}

// outputs the country code to a max 64 character string
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string)
{
	if (NULL == output_string) {
		return RETURN_ERR;
	} else {
		snprintf(output_string, 64, "841");
		return RETURN_OK;
	}
}

INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode)
{
	//Set wifi config. Wait for wifi reset to apply
	return RETURN_OK;
}

/**********************************************************************************
 *
 *  Wifi radio level function prototypes
 *
**********************************************************************************/

//Get the total number of radios in this wifi subsystem
INT wifi_getRadioNumberOfEntries(ULONG *output) //Tr181
{
        if (NULL == output)
		return RETURN_ERR;

	*output=2;
	return RETURN_OK;
}

//Get the total number of SSID entries in this wifi subsystem 
INT wifi_getSSIDNumberOfEntries(ULONG *output) //Tr181
{
	if (NULL == output)
                return RETURN_ERR;

	*output=16;
	return RETURN_OK;
}

//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)      //RDKB
{
        char config_file[MAX_BUF_SIZE] = {0};
        char cmd[MAX_CMD_SIZE] = {0};
        char buf[MAX_BUF_SIZE] = {0};
        char ifname[IF_NAMESIZE] = {0};
        int ret = 0;

        if (NULL == output_bool)
                return RETURN_ERR;

        // Check only supported radios
        if (!((radioIndex == 0) || (radioIndex == 1)))
                return RETURN_ERR;

        ret = GetInterfaceNameFromIdx(radioIndex, ifname);
        if (ret != 0)
                return RETURN_ERR;

        sprintf(cmd,"ifconfig %s%d | grep RUNNING ", AP_PREFIX, radioIndex);
        _syscmd(cmd,buf,sizeof(buf));
        if(strlen(buf)>0)
               *output_bool=TRUE;

        //TODO: check if hostapd with config is running

        *output_bool = FALSE;
        return RETURN_OK;
}

#if 0
//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)	//RDKB
{
    char cmd[MAX_CMD_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE]={'\0'};
    INT  wlanIndex;

    if( 0 == radioIndex ) // For 2.4 GHz
        wlanIndex = wifi_getApIndexForWiFiBand(band_2_4);
    else
        wlanIndex = wifi_getApIndexForWiFiBand(band_5);

    if (NULL == output_bool) 
    {
        return RETURN_ERR;
    } else {
        sprintf(cmd,"ifconfig|grep wlan%d", wlanIndex);
        _syscmd(cmd,buf,sizeof(buf));
        if(strlen(buf)>0)
            *output_bool=1;
        else
            *output_bool=0;
        return RETURN_OK;
    }
}
#endif
INT wifi_setRadioEnable(INT radioIndex, BOOL enable)            //RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char IfName[MAX_BUF_SIZE]={'\0'};
	char HConf_file[MAX_BUF_SIZE]={'\0'};
	char buf[MAX_BUF_SIZE]={'\0'};
	char cmd[MAX_CMD_SIZE]={'\0'};
	char ssid_cur_value[50] ={0};
	BOOL GetssidEnable;

	wifi_getSSIDEnable(radioIndex,&GetssidEnable);
	if(radioIndex == 0)
	{
		sprintf(buf,"%s%d%s","echo ",GetssidEnable," > /tmp/Get2gssidEnable.txt");
		system("rm /tmp/Get2gRadioEnable.txt");
		sprintf(cmd,"%s%d%s","echo ",enable," > /tmp/Get2gRadioEnable.txt");
	}
	else if(radioIndex == 1)
	{
		sprintf(buf,"%s%d%s","echo ",GetssidEnable," > /tmp/Get5gssidEnable.txt");
		system("rm /tmp/Get5gRadioEnable.txt");
		sprintf(cmd,"%s%d%s","echo ",enable," > /tmp/Get5gRadioEnable.txt");
	}
	system(buf);
	system(cmd);

	sprintf(HConf_file,"%s%d%s","/nvram/hostapd",radioIndex,".conf");
	GetInterfaceName(IfName,HConf_file);    	
	if(enable == FALSE)
	{
		sprintf(cmd,"%s%s%s","ifconfig ",IfName," down");
		system(cmd);
	}
	else
	{
		sprintf(cmd,"%s%s%s","ps eaf | grep ",HConf_file," | grep -v grep | awk '{print $1}' | xargs kill -9");
		system(cmd);
		sprintf(cmd,"%s%s","/usr/sbin/hostapd -B ",HConf_file);
		if(radioIndex == 0)
			wifi_RestartPrivateWifi_2G();
		if(radioIndex == 1) 
			wifi_RestartHostapd_5G(radioIndex);
		system("sleep 5");
		if((radioIndex == 0) || (radioIndex == 1))  //if((SSID.Enable == TRUE ) && (Radio.Enable == TRUE)) then bring's up SSID
		{
			if((enable == TRUE) && (GetssidEnable == TRUE))
			{
				system(cmd);
			}
			if(radioIndex == 1)
			{
				File_Reading("cat /tmp/GetPub5gssidEnable.txt",&ssid_cur_value);
                               /* GetInterfaceName(IfName,"/nvram/hostapd5.conf");
                                sprintf(cmd,"%s%s%s","ifconfig ",IfName," | grep UP | tr -s ' ' | cut -d ' ' -f2");
                                _syscmd(cmd,buf,sizeof(buf));
                                if((strlen(buf)>0) && (strcmp(ssid_cur_value,"1") == 0))*/
                                if(strcmp(ssid_cur_value,"1") == 0)
                                {
                                        restarthostapd_all("/nvram/hostapd5.conf");
                                }
			}
			return RETURN_OK;
		}
#if 0
		else if ((radioIndex == 4) || (radioIndex == 5))
		{
			system(cmd);
			if(radioIndex == 5)
			{
				GetInterfaceName(IfName,"/nvram/hostapd1.conf");
				sprintf(cmd,"%s%s%s","ifconfig ",IfName," | grep UP | tr -s ' ' | cut -d ' ' -f2");
				_syscmd(cmd,buf,sizeof(buf));
				if(strlen(buf)>0)
				{
					system("ps -eaf | grep hostapd1.conf | grep -v grep | awk '{print $1}' | xargs kill -9");
					system("sleep 3");
					system("/usr/sbin/hostapd -B /nvram/hostapd1.conf");
				}
			}
		}
#endif
		return RETURN_OK;
	}
}
#if 0
//Set the Radio enable config parameter
INT wifi_setRadioEnable(INT radioIndex, BOOL enable)		//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[MAX_CMD_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE]={'\0'};
    INT  wlanIndex;

    if( 0 == radioIndex ) // For 2.4 GHz
        wlanIndex = wifi_getApIndexForWiFiBand(band_2_4);
    else
        wlanIndex = wifi_getApIndexForWiFiBand(band_5);

    if(enable == TRUE)
        sprintf(cmd,"ifconfig wlan%d up", wlanIndex);
    else
        sprintf(cmd,"ifconfig wlan%d down", wlanIndex);
    
    wifi_dbg_printf("\ncmd=%s",cmd);
    _syscmd(cmd,buf,sizeof(buf));
    //Set wifi config. Wait for wifi reset to apply
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
#endif

//Get the Radio enable status
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool)	//RDKB
{

    if (NULL == output_bool) {
        return RETURN_ERR;
    } else {
        wifi_getRadioEnable(radioIndex, output_bool);
    }
    return RETURN_OK;
}

//Get the Radio Interface name from platform, eg "wifi0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, "%s%d", RADIO_PREFIX, radioIndex);
	return RETURN_OK;
}

//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string)        //RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[1024] =  {0};
	char buf[1024] = {0};
	char tmp_buf[512] = {0};
	char HConf_file[MAX_BUF_SIZE] = {'\0'};
	int count = 0;
	char interface_name[50] = {0};
	FILE *fp = NULL;
	ULONG MaxBitRate = 0;

	if (NULL == output_string)
		return RETURN_ERR;

	sprintf(HConf_file,"%s%d%s","/nvram/hostapd",radioIndex,".conf");
	GetInterfaceName(interface_name,HConf_file);

	sprintf(cmd,"%s%s%s%s%s","iwconfig ",interface_name," | grep ",interface_name," | wc -l");
	_syscmd(cmd,buf,sizeof(buf));
	for(count = 0;buf[count]!='\n';count++)
		tmp_buf[count] = buf[count]; //ajusting the size
	tmp_buf[count] = '\0';

	if(strcmp(tmp_buf,"1") == 0)
	{
		sprintf(cmd,"%s%s%s","iwconfig ",interface_name," | grep 'Bit Rate' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1,2");
		_syscmd(cmd,buf,sizeof(buf));
		//strcpy(output_string,buf);
	}
	else
		strcpy(output_string,"0");

	if(strlen(buf) > 0)
	{
		for(count = 0;buf[count]!='\n';count++)
			tmp_buf[count] = buf[count]; //ajusting the size
		tmp_buf[count] = '\0';
		strcpy(output_string,tmp_buf);
	}
	else
	{
		wifi_getRadioOperatingChannelBandwidth(radioIndex,&buf);
		if((strcmp(buf,"20MHz") == 0) && (radioIndex == 0))
			strcpy(output_string,"144 Mb/s");
		else if((strcmp(buf,"20MHz") == 0) && (radioIndex == 1))
			strcpy(output_string,"54 Mb/s");
		else if((strcmp(buf,"40MHz") == 0) && (radioIndex == 1))
			strcpy(output_string,"300 Mb/s");
	}

	/*if (strstr(tmp_buf, "Mb/s")) {
	//216.7 Mb/s
	MaxBitRate = strtof(tmp_buf,0);
	} else if (strstr(tmp_buf, "Gb/s")) {
	//1.3 Gb/s
	MaxBitRate = strtof(tmp_buf,0) * 1000;
	} else {
	//Auto or Kb/s
	MaxBitRate = 0;
	}
	sprintf(output_string,"%lu",MaxBitRate);*/

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
#if 0
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[64];
    char buf[1024];
    int apIndex;
	
    if (NULL == output_string) 
		return RETURN_ERR;
	
    apIndex=(radioIndex==0)?0:1;

    snprintf(cmd, sizeof(cmd), "iwconfig %s%d | grep \"Bit Rate\" | cut -d':' -f2 | cut -d' ' -f1,2", AP_PREFIX, apIndex);
    _syscmd(cmd,buf, sizeof(buf));

    snprintf(output_string, 64, "%s", buf);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
#endif


//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)	//RDKB
{
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char buf[MAX_BUF_SIZE]={'\0'};
        char str[MAX_BUF_SIZE]={'\0'};
        char cmd[MAX_CMD_SIZE]={'\0'};
        char *ch=NULL;
        char *ch2=NULL;

        if (NULL == output_string)
	        return RETURN_ERR;


		sprintf(cmd,"grep 'channel=' %s%d.conf",CONFIG_PREFIX,radioIndex);
        
   		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
	    {
    	    printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
	        return RETURN_ERR;
	    }
        ch=strchr(buf,'\n');
        *ch='\0';
        ch=strchr(buf,'=');
        if(ch==NULL)
          return RETURN_ERR;

	
        ch++;

 /* prepend 0 for channel with single digit. for ex, 6 would be 06  */
        strcpy(buf,"0");
       if(strlen(ch) == 1)
           ch=strcat(buf,ch);


		sprintf(cmd,"grep 'interface=' %s%d.conf",CONFIG_PREFIX,radioIndex);

        if(_syscmd(cmd,str,64) ==  RETURN_ERR)
        {
                wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
                return RETURN_ERR;
		}

		
		ch2=strchr(str,'\n');
		//replace \n with \0
		*ch2='\0';
        ch2=strchr(str,'=');
        if(ch2==NULL)
        {
        	wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
       		return RETURN_ERR;
        }
        else
         wifi_dbg_printf("%s",ch2+1);

		
        ch2++;


        sprintf(cmd,"iwlist %s frequency|grep 'Channel %s'",ch2,ch);

        memset(buf,'\0',sizeof(buf));
        if(_syscmd(cmd,buf,sizeof(buf))==RETURN_ERR)
		{
			wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
			return RETURN_ERR;
		}
		if (strstr(buf,"2.4") != NULL )
			strcpy(output_string,"2.4GHz");
		else if(strstr(buf,"5.") != NULL )
			strcpy(output_string,"5GHz");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
	
}

//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) //Tr181
{

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char buf[MAX_BUF_SIZE]={'\0'};
        char str[MAX_BUF_SIZE]={'\0'};
        char cmd[MAX_CMD_SIZE]={'\0'};
        char *ch=NULL;
        char *ch2=NULL;
	char ch1[5]="0";

	sprintf(cmd,"grep 'channel=' %s%d.conf",CONFIG_PREFIX,radioIndex);
        
	if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
        {
                printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
	        return RETURN_ERR;
        }
	
        ch=strchr(buf,'\n');
        *ch='\0';
	ch=strchr(buf,'=');
        if(ch==NULL)
          return RETURN_ERR;
	ch++;
	
	if(strlen(ch)==1)
	{
	   	strcat(ch1,ch);

	}
	else
	{
		strcpy(ch1,ch);
	}



	sprintf(cmd,"grep 'interface=' %s%d.conf",CONFIG_PREFIX,radioIndex);
        if(_syscmd(cmd,str,64) ==  RETURN_ERR)
        {
                wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
                return RETURN_ERR;
		}

		
		ch2=strchr(str,'\n');
		//replace \n with \0
		*ch2='\0';
        ch2=strchr(str,'=');
        if(ch2==NULL)
        {
        	wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
       		return RETURN_ERR;
        }
        else
         wifi_dbg_printf("%s",ch2+1);
	ch2++;
		
       

        sprintf(cmd,"iwlist %s frequency|grep 'Channel %s'",ch2,ch1);
        memset(buf,'\0',sizeof(buf));
        if(_syscmd(cmd,buf,sizeof(buf))==RETURN_ERR)
	{
		wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
		return RETURN_ERR;
	}


	if(strstr(buf,"2.4")!=NULL)
	{
		strcpy(output_string,"2.4GHz");
	}
	if(strstr(buf,"5.")!=NULL)
        {
                strcpy(output_string,"5GHz");
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"a,n,ac");
	return RETURN_OK;
}

//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char string[50] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    if ((NULL == output_string) && (NULL == gOnly) && (NULL == nOnly) && (NULL == acOnly)) 
        return RETURN_ERR;
    
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file,"hw_mode",output_string,32);

    wifi_dbg_printf("\noutput_string=%s\n",output_string);
    if (NULL == output_string) 
    {
        wifi_dbg_printf("\nwifi_hostapdRead returned NULL\n");
        return RETURN_ERR;
    }
    if(strcmp(output_string,"g")==0)
    {
        wifi_dbg_printf("\nG\n");
        *gOnly=TRUE;
        *nOnly=FALSE;
        *acOnly=FALSE;
    }
    else if(strcmp(output_string,"n")==0)
    {
        wifi_dbg_printf("\nN\n");
        *gOnly=FALSE;
        *nOnly=TRUE;
        *acOnly=FALSE;
    }
    else if(strcmp(output_string,"ac")==0)
    {
        wifi_dbg_printf("\nac\n");
        *gOnly=FALSE;
        *nOnly=FALSE;
        *acOnly=TRUE;
    }
	/* hostapd-5G.conf has "a" as hw_mode */
    else if(strcmp(output_string,"a")==0)
    {
        wifi_dbg_printf("\na\n");
        *gOnly=FALSE;
        *nOnly=FALSE;
        *acOnly=FALSE;
    }
    else
        wifi_dbg_printf("\nInvalid Mode %s\n", output_string);

    //for a,n mode
    if(radioIndex == 1)
    {
        wifi_hostapdRead(config_file,"ieee80211n",string,50);
        if(strcmp(string,"1")==0)
        {
             strncpy(output_string, "n", 1);
             *nOnly=FALSE;
        }
    }

    wifi_dbg_printf("\nReturning from getRadioStandard\n");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Set the radio operating mode, and pure mode flag. 
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag)	//RDKB
{
        WIFI_ENTRY_EXIT_DEBUG("Inside %s_%s_%d_%d:%d\n",__func__,channelMode,nOnlyFlag,gOnlyFlag,__LINE__);  
        if (strcmp (channelMode,"11A") == 0)
        {
		writeBandWidth(radioIndex,"20MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
                printf("\nChannel Mode is 802.11a (5GHz)\n");
        }
        else if (strcmp (channelMode,"11NAHT20") == 0)
        {
                writeBandWidth(radioIndex,"20MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
                printf("\nChannel Mode is 802.11n-20MHz(5GHz)\n");
        }
        else if (strcmp (channelMode,"11NAHT40PLUS") == 0)
        {
                writeBandWidth(radioIndex,"40MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
                printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
        }
        else if (strcmp (channelMode,"11NAHT40MINUS") == 0)
        {
                writeBandWidth(radioIndex,"40MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
                printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
        }
        else if (strcmp (channelMode,"11ACVHT20") == 0)
        {
                writeBandWidth(radioIndex,"20MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
                printf("\nChannel Mode is 802.11ac-20MHz(5GHz)\n");
        }
        else if (strcmp (channelMode,"11ACVHT40PLUS") == 0)
        {
                writeBandWidth(radioIndex,"40MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
                printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
        }
        else if (strcmp (channelMode,"11ACVHT40MINUS") == 0)
        {
                writeBandWidth(radioIndex,"40MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
                printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
        }
        else if (strcmp (channelMode,"11ACVHT80") == 0)
        {
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"80MHz");
                printf("\nChannel Mode is 802.11ac-80MHz(5GHz)\n");
        }
        else if (strcmp (channelMode,"11ACVHT160") == 0)
        {
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"160MHz");
                printf("\nChannel Mode is 802.11ac-160MHz(5GHz)\n");
        }      
        else if (strcmp (channelMode,"11B") == 0)
	{
 	        writeBandWidth(radioIndex,"20MHz");
          	wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11b(2.4GHz)\n");
	}
	else if (strcmp (channelMode,"11G") == 0)
	{
 	        writeBandWidth(radioIndex,"20MHz");
          	wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11g(2.4GHz)\n");
	}
	else if (strcmp (channelMode,"11NGHT20") == 0)
	{
 		writeBandWidth(radioIndex,"20MHz");
 		wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
		printf("\nChannel Mode is 802.11n-20MHz(2.4GHz)\n");
	}
        else if (strcmp (channelMode,"11NGHT40PLUS") == 0)
        {
                writeBandWidth(radioIndex,"40MHz");
	        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
                printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
        }
        else if (strcmp (channelMode,"11NGHT40MINUS") == 0)
        {
                writeBandWidth(radioIndex,"40MHz");
                wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
                printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
        }
        else 
        {
                return RETURN_ERR;
        }
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}


//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)	//RDKB
{
#if 0
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex==0)?"1,2,3,4,6,7,8,9,10,11":"36,40");
#endif
	char IFName[50] ={0};
        char buf[MAX_BUF_SIZE] = {0};
        char cmd[MAX_CMD_SIZE] = {0};
        int count = 0;
        if (NULL == output_string)
               return RETURN_ERR;

//      snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
        if(radioIndex == 0)
	{
                GetInterfaceName(IFName,"/nvram/hostapd0.conf");
                sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep 2'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | sed 's/^0//g' | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
	}
        else if(radioIndex == 1)
	{
                GetInterfaceName(IFName,"/nvram/hostapd1.conf");
                sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep '5\\.[1-9]' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
	}
        _syscmd(cmd, buf, sizeof(buf));
	if(strlen(buf) > 0)
		strcpy(output_string,buf);
	else
		strcpy(output_string,"0");
	return RETURN_OK;
}

//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string)	//RDKB
{
	char IFName[50] ={0};
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	int count = 0;
	if (NULL == output_string)
		return RETURN_ERR;

	//	snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
	if(radioIndex == 0)
	{
		GetInterfaceName(IFName,"/nvram/hostapd0.conf");
		sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep 2'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | sed 's/^0//g' | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
	}
	else if(radioIndex == 1)
	{
		GetInterfaceName(IFName,"/nvram/hostapd1.conf");
		sprintf(cmd,"%s %s %s","iwlist",IFName,"channel  | grep Channel | grep -v 'Current Frequency' | grep 5'\\.[1-9]' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 |tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
	}
	_syscmd(cmd,buf, sizeof(buf));
	if(strlen(buf) > 0)
		strcpy(output_string,buf);
	else
		strcpy(output_string,"0");

	return RETURN_OK;
}

//Get the running channel number 
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[1024] =  {0};
    char buf[4] = {0};

    char HConf_file[MAX_BUF_SIZE] = {'\0'};
    char interface_name[50] = {0};


    if (NULL == output_ulong)
    {
        return RETURN_ERR;
    }

    sprintf(HConf_file,"%s%d%s","/nvram/hostapd",radioIndex,".conf");
    GetInterfaceName(interface_name,HConf_file);

    sprintf(cmd,"%s%s%s","iw dev ",interface_name," info | grep 'channel' | cut -d ' ' -f2");
    _syscmd(cmd,buf,sizeof(buf));

    if(buf != NULL)
        *output_ulong=atol(buf);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Storing the previous channel value
INT wifi_storeprevchanval(INT radioIndex)
{
	char buf[256] = {0};
	char output[4]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
	wifi_hostapdRead(config_file,"channel",output,64);
	if(radioIndex == 0)
		sprintf(buf,"%s%s%s","echo ",output," > /var/prevchanval2G_AutoChannelEnable");
	else if(radioIndex == 1)
		sprintf(buf,"%s%s%s","echo ",output," > /var/prevchanval5G_AutoChannelEnable");
	system(buf);
	Radio_flag = FALSE;
	return RETURN_OK;
}
//Set the running channel number 
INT wifi_setRadioChannel(INT radioIndex, ULONG channel)	//RDKB	//AP only
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char str_channel[4]={'\0'};
    struct params list;
    char config_file[MAX_BUF_SIZE] = {0};

    list.name = "channel";

    if(Radio_flag == TRUE)
        wifi_storeprevchanval(radioIndex);  //for autochannel

    if(radioIndex == 0)
    {
	switch(channel)
	{
	    case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12:
                sprintf(str_channel,"%ld", channel);
                list.value = str_channel;
                break;
            default:
                return RETURN_ERR;
        }
    }
    else if(radioIndex == 1)
    {
        switch(channel)
        {
            case 36: case 40: case 44: case 48: case 52: case 56: case 60: case 64: case 144: case 149: case 153: case 157: case 161: case 165: case 169:
                sprintf(str_channel,"%ld", channel);
                list.value = str_channel;
                break;
            default:
                return RETURN_ERR;
        }
    }
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdWrite(config_file,&list,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
    //Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
 }
//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) //RDKB
{
	//Set to wifi config only. Wait for wifi reset to apply.
	char buf[256] = {0};
	char str_channel[256] = {0};
	int count = 0;
	ULONG Value = 0;
	FILE *fp = NULL;
	if(enable == TRUE)
	{
		if(radioIndex == 0)
		{
			//	_syscmd("cat /var/prevchanval2G_AutoChannelEnable", buf, sizeof(buf));
			fp = fopen("/var/prevchanval2G_AutoChannelEnable","r");
		}
		else if(radioIndex == 1)
		{
			//	_syscmd("cat /var/prevchanval5G_AutoChannelEnable", buf, sizeof(buf));
			fp = fopen("/var/prevchanval5G_AutoChannelEnable","r");
		}
		if(fp == NULL) //first time boot-up
		{
			if(radioIndex == 0)
				Value = 6;
			else if(radioIndex == 1)
				Value = 36;
		}
		else
		{
			if(fgets(buf,sizeof(buf),fp) != NULL)
			{
				for(count = 0;buf[count]!='\n';count++)
					str_channel[count] = buf[count];
				str_channel[count] = '\0';		
				Value = atol(str_channel);
				printf("%sValue is %ld \n",__FUNCTION__,Value);
			pclose(fp);
			}
		}
		Radio_flag = FALSE;//for storing previous channel value
		wifi_setRadioChannel(radioIndex,Value);
		return RETURN_OK;
	}
	return RETURN_ERR;
}

INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool) 	//RDKB
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=FALSE;
	return RETURN_OK;
}

INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool)		//RDKB
{	
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=FALSE;
	return RETURN_OK;
}

INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable)            //RDKB
{    
    //Set to wifi config only. Wait for wifi reset to apply.
    return RETURN_OK;
}

INT wifi_setApEnableOnLine(ULONG wlanIndex,BOOL enable)
{
   return RETURN_OK;
}

INT wifi_factoryResetAP(int apIndex)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //factory reset is not done for now on Turris
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//To set Band Steering AP group
//To-do
INT wifi_setBandSteeringApGroup(char *ApGroup) {
	return RETURN_OK;
}

INT wifi_setApDTIMInterval(INT apIndex, INT dtimInterval)
{
   return RETURN_OK;
}

//Check if the driver support the Dfs
INT wifi_getRadioDfsSupport(INT radioIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=FALSE;	
	return RETURN_OK;
}

//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
//The value of this parameter is a comma seperated list of channel number
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool)			//RDKB
{
	if (NULL == output_pool) 
		return RETURN_ERR;
	snprintf(output_pool, 256, "1,2,3,4,5,6,7,8,9,10,11");
	return RETURN_OK;
}

INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool)			//RDKB
{
	//Set to wifi config. And apply instantly.
	return RETURN_OK;
}

INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds, INT *output_dwell_milliseconds)
{
	if (NULL == output_interval_seconds || NULL == output_dwell_milliseconds) 
		return RETURN_ERR;
	*output_interval_seconds=1800;
	*output_dwell_milliseconds=40;
	return RETURN_OK;
}

INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds, INT dwell_milliseconds)
{
	//Set to wifi config. And apply instantly.
	return RETURN_OK;
}

//Get the Dfs enable status
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=FALSE;	
	return RETURN_OK;
}

//Set the Dfs enable status
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enable)	//Tr181
{
	return RETURN_ERR;
}

//Check if the driver support the AutoChannelRefreshPeriod
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=FALSE;		//not support
	return RETURN_OK;
}

//Get the ACS refresh period in seconds
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) //Tr181
{
	if (NULL == output_ulong) 
		return RETURN_ERR;
	*output_ulong=300;	
	return RETURN_OK;
}

//Set the ACS refresh period in seconds
INT wifi_setRadioDfsRefreshPeriod(INT radioIndex, ULONG seconds) //Tr181
{
	return RETURN_ERR;
}

//Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char output_buf[8]={0};
    char bw_value[10];
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file,"vht_oper_chwidth",output_buf,64);
    readBandWidth(radioIndex,bw_value);

    if (NULL == output_string)
        return RETURN_ERR;

    if(strstr (output_buf,"0") != NULL )
    {
        strcpy(output_string,bw_value);
    }
    else if (strstr (output_buf,"1") != NULL)
    {
        strcpy(output_string,"80MHz");
    }
    else if (strstr (output_buf,"2") != NULL)
    {
        strcpy(output_string,"160MHz");
    }
    else if (strstr (output_buf,"3") != NULL)
    {
        strcpy(output_string,"80+80");
    }
    else
    {
        strcpy(output_string,"Auto");
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181	//AP only
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    params.name = "vht_oper_chwidth";
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == output_string)
        return RETURN_ERR;

    if(strcmp(output_string,"20MHz") == 0)  // This piece of code only support for wifi hal api's validation
        params.value="0";
    else if(strcmp(output_string,"40MHz") == 0)
	params.value="0";
    else if(strcmp(output_string,"80MHz") == 0)
	params.value="1";
    else if(strcmp(output_string,"160MHz") == 0)
	params.value="2";
    else if(strcmp(output_string,"80+80") == 0)
	params.value="3";
    else
    {
        printf("Invalid Bandwidth \n");
	return RETURN_ERR;
    }

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdWrite(config_file,&params,1);

    if(radioIndex == 1)
    {
        params.name= "ieee80211n";
	if(strcmp(output_string,"20MHz") == 0)
	    output_string="0";
	else if(strcmp(output_string,"40MHz") == 0)
	    output_string="1";

	params.value = output_string;
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
	wifi_hostapdWrite(config_file,&params,1);
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Getting current radio extension channel
INT wifi_halgetRadioExtChannel(CHAR *file,CHAR *Value)
{
        CHAR buf[150] = {0};
        CHAR cmd[150] = {0};
        sprintf(cmd,"%s%s%s","cat ",file," | grep -w ht_capab=");
        _syscmd(cmd, buf, sizeof(buf));
        if(NULL != strstr(buf,"HT40+"))
                strcpy(Value,"AboveControlChannel");
        else if(NULL != strstr(buf,"HT40-"))
                 strcpy(Value,"BelowControlChannel");
        return RETURN_OK;
}

//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) //Tr181
{
        if (NULL == output_string)
                return RETURN_ERR;
//      snprintf(output_string, 64, (radioIndex==0)?"":"BelowControlChannel");
        CHAR Value[100] = {0};
        if(radioIndex == 0)
                strcpy(Value,"Auto"); //so far rpi(2G) supports upto 150Mbps (i,e 20MHZ)
        else if(radioIndex == 1)//so far rpi(5G) supports upto 300mbps (i,e 20MHz/40MHz)
        {
                wifi_getRadioOperatingChannelBandwidth(radioIndex,Value);
                if(strcmp(Value,"40MHz") == 0)
                        wifi_halgetRadioExtChannel("/nvram/hostapd1.conf",Value);
		else
                        strcpy(Value,"Auto");
        }
        strcpy(output_string,Value);

        return RETURN_OK;
}

//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) //Tr181	//AP only
{        
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};
    char ext_channel[127]={'\0'};

    params.name = "ht_capab";

    if(radioIndex == 0)
    {
        if((NULL!= strstr(string,"Above")) || (NULL!= strstr(string,"Below")))
        strcpy(ext_channel,"\[HT40\]\[SHORT-GI-20\]\[DSSS_CCK-40\]");
    }
    else if(radioIndex  == 1)
    {
        if(NULL!= strstr(string,"Above"))
            strcpy(ext_channel,"\[HT40\]\[SHORT-GI-20\]\[HT40+\]"); //special characters that's why '\' is used
        else if(NULL!= strstr(string,"Below"))
            strcpy(ext_channel,"\[HT40\]\[SHORT-GI-20\]\[HT40-\]");
    }

    params.value = ext_channel;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdWrite(config_file,&params,1);

    //Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the guard interval value. eg "400nsec" or "800nsec" 
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string)	//Tr181
{
	//save config and apply instantly
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex==0)?"400nsec":"400nsec");
	return RETURN_OK;
}

//Set the guard interval value. 
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string)	//Tr181
{
	//Apply setting instantly
	return RETURN_ERR;
}

//Get the Modulation Coding Scheme index, eg: "-1", "1", "15"
INT wifi_getRadioMCS(INT radioIndex, INT *output_int) //Tr181
{
	if (NULL == output_int) 
		return RETURN_ERR;
	if (radioIndex==0)	
		*output_int=1;
	else
		*output_int=3;
	return RETURN_OK;
}

//Set the Modulation Coding Scheme index
INT wifi_setRadioMCS(INT radioIndex, INT MCS) //Tr181
{
	return RETURN_ERR;
}

//Get supported Transmit Power list, eg : "0,25,50,75,100"
//The output_list is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) //Tr181
{
        if (NULL == output_list)
                return RETURN_ERR;
        snprintf(output_list, 64,"0,25,50,75,100");
        return RETURN_OK;
}

//Get current Transmit Power, eg "75", "100"
//The transmite power level is in units of full power for this radio.
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong)	//RDKB
{
	char cmd[128]={0};
	char buf[256]={0};
	INT apIndex;
	//save config and apply instantly
	
	if (NULL == output_ulong) 
		return RETURN_ERR;
	
	//zqiu:TODO:save config
	apIndex=(radioIndex==0)?0:1;
	
	snprintf(cmd, sizeof(cmd),  "iwlist %s%d txpower | grep Tx-Power | cut -d'=' -f2", AP_PREFIX, index);
	_syscmd(cmd, buf, sizeof(buf));
	*output_ulong = atol(buf);
	
	return RETURN_OK;
}

//Set Transmit Power
//The transmite power level is in units of full power for this radio.
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower)	//RDKB
{
	char cmd[128]={0};
	char buf[256]={0};
	INT apIndex;	
		
	apIndex=(radioIndex==0)?0:1;
	
	snprintf(cmd, sizeof(cmd),  "iwconfig %s%d txpower %lu", AP_PREFIX, apIndex, TransmitPower);
	_syscmd(cmd, buf, sizeof(buf));	
	
	return RETURN_OK;
}

//get 80211h Supported.  80211h solves interference with satellites and radar using the same 5 GHz frequency band
INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported)  //Tr181
{
	if (NULL == Supported) 
		return RETURN_ERR;
	*Supported=FALSE;	
	return RETURN_OK;
}

//Get 80211h feature enable
INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) //Tr181
{
	if (NULL == enable) 
		return RETURN_ERR;
	*enable=FALSE;	
	return RETURN_OK;
}

//Set 80211h feature enable
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable)  //Tr181
{
	return RETURN_ERR;
}

//Indicates the Carrier Sense ranges supported by the radio. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output)  //P3
{
	if (NULL == output) 
		return RETURN_ERR;
	*output=100;	
	return RETURN_OK;
}

//The RSSI signal level at which CS/CCA detects a busy condition. This attribute enables APs to increase minimum sensitivity to avoid detecting busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output)	//P3
{
	if (NULL == output) 
		return RETURN_ERR;
	*output=-99;	
	return RETURN_OK;
}

INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold)	//P3
{
	return RETURN_ERR;
}


//Time interval between transmitting beacons (expressed in milliseconds). This parameter is based ondot11BeaconPeriod from [802.11-2012].
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output)
{
	if (NULL == output) 
		return RETURN_ERR;
	*output=100;	
	return RETURN_OK;
}
 
INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod)
{
	return RETURN_ERR;
}

//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.	
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char *temp;
    char temp_output[128];
    char temp_TransmitRates[512];
    char config_file[MAX_BUF_SIZE] = {0};

    if (NULL == output)
        return RETURN_ERR;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file,"basic_rates",output,64);

    strcpy(temp_TransmitRates,output);
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates," ");
    while(temp!=NULL)
    {
        temp[strlen(temp)-1]=0;
        if((temp[0]=='5') && (temp[1]=='\0'))
        {
            temp="5.5";
        }
        strcat(temp_output,temp);
        temp = strtok(NULL," ");
        if(temp!=NULL)
        {
            strcat(temp_output,",");
        }
    }
    strcpy(output,temp_output);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates)
{
    char *temp;
    char temp1[128];
    char temp_output[128];
    char temp_TransmitRates[128];
    char set[128];
    char sub_set[128];
    int set_count=0,subset_count=0;
    int set_index=0,subset_index=0;
    char *token;
    int flag=0, i=0;
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == TransmitRates)
        return RETURN_ERR;
    strcpy(sub_set,TransmitRates);

    //Allow only supported Data transmit rate to be set
    wifi_getRadioSupportedDataTransmitRates(radioIndex,set);
    token = strtok(sub_set,",");
    while( token != NULL  )  /* split the basic rate to be set, by comma */
    {
        sub_set[subset_count]=atoi(token);
        subset_count++;
        token=strtok(NULL,",");
    }
    token=strtok(set,",");
    while(token!=NULL)   /* split the supported rate by comma */
    {
        set[set_count]=atoi(token);
        set_count++;
        token=strtok(NULL,",");
    }
    for(subset_index=0;subset_index < subset_count;subset_index++) /* Compare each element of subset and set */
    {
        for(set_index=0;set_index < set_count;set_index++)
        {
            flag=0;
            if(sub_set[subset_index]==set[set_index])
                break;
            else
                flag=1; /* No match found */
        }
        if(flag==1)
            return RETURN_ERR; //If value not found return Error
    }
    strcpy(temp_TransmitRates,TransmitRates);

    for(i=0;i<strlen(temp_TransmitRates);i++)
    {
    //if (((temp_TransmitRates[i]>=48) && (temp_TransmitRates[i]<=57)) | (temp_TransmitRates[i]==32))
        if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) | (temp_TransmitRates[i]==' ') | (temp_TransmitRates[i]=='.') | (temp_TransmitRates[i]==','))
        {
            continue;
        }
        else
        {
            return RETURN_ERR;
        }
    }
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates,",");
    while(temp!=NULL)
    {
        strcpy(temp1,temp);
        if(radioIndex==1)
        {
            if((strcmp(temp,"1")==0) | (strcmp(temp,"2")==0) | (strcmp(temp,"5.5")==0))
            {
                return RETURN_ERR;
            }
        }
    
        if(strcmp(temp,"5.5")==0)
        {
            strcpy(temp1,"55");
        }
        else
        {
            strcat(temp1,"0");
        }
        strcat(temp_output,temp1);
        temp = strtok(NULL,",");
        if(temp!=NULL)
        {
            strcat(temp_output," ");
        }
    }
    strcpy(TransmitRates,temp_output);

    params.name= "basic_rates";
    params.value =TransmitRates;

    wifi_dbg_printf("\n%s:",__func__);
    wifi_dbg_printf("\nparams.value=%s\n",params.value);
    wifi_dbg_printf("\n******************Transmit rates=%s\n",TransmitRates);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//passing the hostapd configuration file and get the virtual interface of xfinity(2g)
INT GetInterfaceName_virtualInterfaceName_2G(char interface_name[50])
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	FILE *fp = NULL;
	char path[256] = {0}, output_string[256] = {0};
	int count = 0;
	char *interface = NULL;

	fp = popen("cat /nvram/hostapd0.conf | grep -w bss", "r");
	if (fp == NULL)
	{
		printf("Failed to run command in Function %s\n", __FUNCTION__);
		return RETURN_ERR;
	}
	if (fgets(path, sizeof(path) - 1, fp) != NULL)
	{
		interface = strchr(path, '=');

		if (interface != NULL)
		{
			strcpy(output_string, interface + 1);
			for (count = 0; output_string[count] != '\n' || output_string[count] != '\0'; count++)
				interface_name[count] = output_string[count];

			interface_name[count] = '\0';
		}
	}
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT wifi_halGetIfStatsNull(wifi_radioTrafficStats2_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	output_struct->radio_BytesSent = 0;
	output_struct->radio_BytesReceived = 0;
	output_struct->radio_PacketsSent = 0;
	output_struct->radio_PacketsReceived = 0;
	output_struct->radio_ErrorsSent = 0;
	output_struct->radio_ErrorsReceived = 0;
	output_struct->radio_DiscardPacketsSent = 0;
	output_struct->radio_DiscardPacketsReceived = 0;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}


INT wifi_halGetIfStats(char *ifname, wifi_radioTrafficStats2_t *pStats)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	CHAR buf[MAX_CMD_SIZE] = {0};
	CHAR Value[MAX_BUF_SIZE] = {0};
	FILE *fp = NULL;

	if (ifname == NULL || strlen(ifname) <= 1)
		return RETURN_OK;

	snprintf(buf, sizeof(buf), "ifconfig -a %s > /tmp/Radio_Stats.txt", ifname);
	system(buf);

	fp = fopen("/tmp/Radio_Stats.txt", "r");
	if(fp == NULL)
	{
		printf("/tmp/Radio_Stats.txt not exists \n");
		return RETURN_ERR;
	}
	fclose(fp);
	
	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_PacketsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_PacketsSent = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_BytesReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_BytesSent = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_ErrorsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_ErrorsSent = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_DiscardPacketsReceived = strtoul(Value, NULL, 10);

	sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf, Value);
	pStats->radio_DiscardPacketsSent = strtoul(Value, NULL, 10);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

INT GetIfacestatus(CHAR *interface_name, CHAR *status)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	CHAR buf[MAX_CMD_SIZE] = {0};
	FILE *fp = NULL;
	INT count = 0;

	if (interface_name != NULL && (strlen(interface_name) > 1) && status != NULL)
	{
		sprintf(buf, "%s%s%s%s%s", "ifconfig -a ", interface_name, " | grep ", interface_name, " | wc -l");
		File_Reading(buf, status);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;
}

//Get detail radio traffic static info
INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *output_struct) //Tr181
{

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	if (NULL == output_struct)
		return RETURN_ERR;

#if 0	
	//ifconfig radio_x	
	output_struct->radio_BytesSent=250;	//The total number of bytes transmitted out of the interface, including framing characters.
	output_struct->radio_BytesReceived=168;	//The total number of bytes received on the interface, including framing characters.
	output_struct->radio_PacketsSent=25;	//The total number of packets transmitted out of the interface.
	output_struct->radio_PacketsReceived=20; //The total number of packets received on the interface.

	output_struct->radio_ErrorsSent=0;	//The total number of outbound packets that could not be transmitted because of errors.
	output_struct->radio_ErrorsReceived=0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
	output_struct->radio_DiscardPacketsSent=0; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->radio_DiscardPacketsReceived=0; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
	
	output_struct->radio_PLCPErrorCount=0;	//The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.	
	output_struct->radio_FCSErrorCount=0;	//The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
	output_struct->radio_InvalidMACCount=0;	//The number of packets that were received with a detected invalid MAC header error.
	output_struct->radio_PacketsOtherReceived=0;	//The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
	output_struct->radio_NoiseFloor=-99; 	//The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
	output_struct->radio_ChannelUtilization=35; //Percentage of time the channel was occupied by the radios own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
	output_struct->radio_ActivityFactor=2; //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_CarrierSenseThreshold_Exceeded=20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_RetransmissionMetirc=0; //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage
	
	output_struct->radio_MaximumNoiseFloorOnChannel=-1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
	output_struct->radio_MinimumNoiseFloorOnChannel=-1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_MedianNoiseFloorOnChannel=-1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_StatisticsStartTime=0; 	    //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.
	
	return RETURN_OK;
#endif

	CHAR private_interface_name[MAX_BUF_SIZE] = {0}, public_interface_name[MAX_BUF_SIZE] = {0};
	CHAR private_interface_status[MAX_BUF_SIZE] = {0}, public_interface_status[MAX_BUF_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	wifi_radioTrafficStats2_t private_radioTrafficStats = {0}, public_radioTrafficStats = {0};

	if (radioIndex == 0) //2.4GHz ?
	{

		GetInterfaceName(private_interface_name, "/nvram/hostapd0.conf");

		GetIfacestatus(private_interface_name, private_interface_status);

		sprintf(cmd, "%s", "cat /nvram/hostapd0.conf | grep bss=");
		File_Reading(cmd, buf);

		if (buf[0] == '#') //TP-link
		{
			GetInterfaceName(public_interface_name, "/nvram/hostapd4.conf");
		}
		else //Tenda
		{
			GetInterfaceName_virtualInterfaceName_2G(public_interface_name);
		}

		GetIfacestatus(public_interface_name, public_interface_status);

		printf("private_interface_name %s private_interface_status %s \n", private_interface_name, private_interface_status);
		printf("public_interface_name %s public_interface_status %s \n", public_interface_name, public_interface_status);

		if (strcmp(private_interface_status, "1") == 0)
			wifi_halGetIfStats(private_interface_name, &private_radioTrafficStats);
		else
			wifi_halGetIfStatsNull(&private_radioTrafficStats);

		if (strcmp(public_interface_status, "1") == 0)
			wifi_halGetIfStats(public_interface_name, &public_radioTrafficStats);
		else
			wifi_halGetIfStatsNull(&public_radioTrafficStats);
	}
	else if (radioIndex == 1) //5GHz ?
	{
		GetInterfaceName(private_interface_name, "/nvram/hostapd1.conf");
		GetIfacestatus(private_interface_name, private_interface_status);

		GetInterfaceName(public_interface_name, "/nvram/hostapd5.conf");
		GetIfacestatus(public_interface_name, public_interface_status);

		if (strcmp(private_interface_status, "1") == 0)
			wifi_halGetIfStats(private_interface_name, &private_radioTrafficStats);
		else
			wifi_halGetIfStatsNull(&private_radioTrafficStats);

		if (strcmp(public_interface_status, "1") == 0)
			wifi_halGetIfStats(public_interface_name, &public_radioTrafficStats);
		else
			wifi_halGetIfStatsNull(&public_radioTrafficStats);
	}

	output_struct->radio_BytesSent = private_radioTrafficStats.radio_BytesSent + public_radioTrafficStats.radio_BytesSent;
	output_struct->radio_BytesReceived = private_radioTrafficStats.radio_BytesReceived + public_radioTrafficStats.radio_BytesReceived;
	output_struct->radio_PacketsSent = private_radioTrafficStats.radio_PacketsSent + public_radioTrafficStats.radio_PacketsSent;
	output_struct->radio_PacketsReceived = private_radioTrafficStats.radio_PacketsReceived + public_radioTrafficStats.radio_PacketsReceived;
	output_struct->radio_ErrorsSent = private_radioTrafficStats.radio_ErrorsSent + public_radioTrafficStats.radio_ErrorsSent;
	output_struct->radio_ErrorsReceived = private_radioTrafficStats.radio_ErrorsReceived + public_radioTrafficStats.radio_ErrorsReceived;
	output_struct->radio_DiscardPacketsSent = private_radioTrafficStats.radio_DiscardPacketsSent + public_radioTrafficStats.radio_DiscardPacketsSent;
	output_struct->radio_DiscardPacketsReceived = private_radioTrafficStats.radio_DiscardPacketsReceived + public_radioTrafficStats.radio_DiscardPacketsReceived;

	output_struct->radio_PLCPErrorCount = 0;				  //The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.
	output_struct->radio_FCSErrorCount = 0;					  //The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
	output_struct->radio_InvalidMACCount = 0;				  //The number of packets that were received with a detected invalid MAC header error.
	output_struct->radio_PacketsOtherReceived = 0;			  //The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
	output_struct->radio_NoiseFloor = -99;					  //The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
	output_struct->radio_ChannelUtilization = 35;			  //Percentage of time the channel was occupied by the radio\92s own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
	output_struct->radio_ActivityFactor = 2;				  //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_CarrierSenseThreshold_Exceeded = 20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_RetransmissionMetirc = 0;			  //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage

	output_struct->radio_MaximumNoiseFloorOnChannel = -1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
	output_struct->radio_MinimumNoiseFloorOnChannel = -1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_MedianNoiseFloorOnChannel = -1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_StatisticsStartTime = 0;		  //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

	return RETURN_OK;
}

//Set radio traffic static Measureing rules
INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) //Tr181
{
	//zqiu:  If the RadioTrafficStats process running, and the new value is different from old value, the process needs to be reset. The Statistics date, such as MaximumNoiseFloorOnChannel, MinimumNoiseFloorOnChannel and MedianNoiseFloorOnChannel need to be reset. And the "StatisticsStartTime" must be reset to the current time. Units in Seconds
	//       Else, save the MeasuringRate and MeasuringInterval for future usage
	
	return RETURN_OK;
}

//To start or stop RadioTrafficStats
INT wifi_setRadioTrafficStatsRadioStatisticsEnable(INT radioIndex, BOOL enable) 
{
	//zqiu:  If the RadioTrafficStats process running
	//          	if(enable)
	//					return RETURN_OK.
	//				else
	//					Stop RadioTrafficStats process
	//       Else 
	//				if(enable)
	//					Start RadioTrafficStats process with MeasuringRate and MeasuringInterval, and reset "StatisticsStartTime" to the current time, Units in Seconds
	//				else
	//					return RETURN_OK.
		
	return RETURN_OK;
}


//Clients associated with the AP over a specific interval.  The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm end of the range.  Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included in the respective bin.  The bin associated with the client?s current received signal level MUST be incremented when a client associates with the AP.   Additionally, the respective bins associated with each connected client?s current received signal level MUST be incremented at the interval defined by "Radio Statistics Measuring Rate".  The histogram?s bins MUST NOT be incremented at any other time.  The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by "Radio Statistics Measuring Interval".  The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval?. If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of data, it MUST return -1. Units dBm
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) //Tr181
{
	//zqiu: Please ignor signalIndex.
	if (NULL == SignalLevel) 
		return RETURN_ERR;
	*SignalLevel=(radioIndex==0)?-19:-19;
	return RETURN_OK;
}

//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applyRadioSettings(INT radioIndex) 
{
	return RETURN_OK;
}

//Get the radio index assocated with this SSID entry
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex) 
{
	if (NULL == radioIndex) 
		return RETURN_ERR;
	*radioIndex=ssidIndex%2;
	return RETURN_OK;
}

//Get SSID enable configuration parameters (not the SSID enable status)
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	return wifi_getApEnable(ssidIndex, output_bool);
}

//Set SSID enable configuration parameters
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) //Tr181
{
	return wifi_setApEnable(ssidIndex, enable);
}

//Get the SSID enable status
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[MAX_CMD_SIZE]={0};
	char buf[MAX_BUF_SIZE]={0};
	BOOL output_bool;
	if (NULL == output_string)
		return RETURN_ERR;
	else
	{
		wifi_getApEnable(ssidIndex,&output_bool);
	}

	if(output_bool == 1) 
		snprintf(output_string, 32, "Enabled");
	else
		snprintf(output_string, 32, "Disabled");

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// Outputs a 32 byte or less string indicating the SSID name.  Sring buffer must be preallocated by the caller.
INT wifi_getSSIDName(INT apIndex, CHAR *output)
{
    char config_file[MAX_BUF_SIZE] = {0};
    if (NULL == output) 
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"ssid",output,32);
    wifi_dbg_printf("\n[%s]: SSID Name is : %s",__func__,output); 
    if(output==NULL)
        return RETURN_ERR;
    else
        return RETURN_OK;
}
        
// Set a max 32 byte string and sets an internal variable to the SSID name          
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char str[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *ch;
    struct params params;
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == ssid_string)
        return RETURN_ERR;

    params.name = "ssid";
    params.value = ssid_string;
    printf("\n%s\n",__func__);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the BSSID 
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[128]={0};

    if (NULL == output_string)
        return RETURN_ERR;

    sprintf(cmd, "iw dev %s%d info |grep addr | awk '{printf $2}'", AP_PREFIX, ssidIndex);
    _syscmd(cmd, output_string, 32);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the MAC address associated with this Wifi SSID
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) //Tr181
{
    wifi_getBaseBSSID(ssidIndex,output_string);
    return RETURN_OK;
}

//Get the basic SSID traffic static info
//Apply SSID and AP (in the case of Acess Point devices) to the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applySSIDSettings(INT ssidIndex)
{
    return RETURN_OK;
}

//Start the wifi scan and get the result into output buffer for RDKB to parser. The result will be used to manage endpoint list
//HAL funciton should allocate an data structure array, and return to caller with "neighbor_ap_array"
INT wifi_getNeighboringWiFiDiagnosticResult2(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size) //Tr181	
{
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	INT status = RETURN_ERR;
	UINT index;
	wifi_neighbor_ap2_t *pt=NULL;
	char cmd[128]={0};
	char buf[8192]={0};
	
	sprintf(cmd, "iwlist %s%d scan",AP_PREFIX,(radioIndex==0)?0:1);	//suppose ap0 mapping to radio0
    _syscmd(cmd, buf, sizeof(buf));
	
	
	*output_array_size=2;
	//zqiu: HAL alloc the array and return to caller. Caller response to free it.
	*neighbor_ap_array=(wifi_neighbor_ap2_t *)calloc(sizeof(wifi_neighbor_ap2_t), *output_array_size);
	for (index = 0, pt=*neighbor_ap_array; index < *output_array_size; index++, pt++) {
		strcpy(pt->ap_SSID,"");
		strcpy(pt->ap_BSSID,"");
		strcpy(pt->ap_Mode,"");
		pt->ap_Channel=1;
		pt->ap_SignalStrength=0;
		strcpy(pt->ap_SecurityModeEnabled,"");
		strcpy(pt->ap_EncryptionMode,"");
		strcpy(pt->ap_OperatingFrequencyBand,"");
		strcpy(pt->ap_SupportedStandards,"");
		strcpy(pt->ap_OperatingStandards,"");
		strcpy(pt->ap_OperatingChannelBandwidth,"");
		pt->ap_BeaconPeriod=1;
		pt->ap_Noise=0;
		strcpy(pt->ap_BasicDataTransferRates,"");
		strcpy(pt->ap_SupportedDataTransferRates,"");
		pt->ap_DTIMPeriod=1;
		pt->ap_ChannelUtilization=0;
	}

	status = RETURN_OK;
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return status;
}

//>> Deprecated: used for old RDKB code. 
INT wifi_getRadioWifiTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	INT status = RETURN_ERR;
	output_struct->wifi_PLCPErrorCount = 0;
	output_struct->wifi_FCSErrorCount = 0;
	output_struct->wifi_InvalidMACCount = 0;
	output_struct->wifi_PacketsOtherReceived = 0;
	output_struct->wifi_Noise = 0;
	status = RETURN_OK;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return status;
}

INT wifi_getBasicTrafficStats(INT apIndex, wifi_basicTrafficStats_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[MAX_BUF_SIZE] = {0};
	char interface_status[MAX_BUF_SIZE] = {0};
	char Value[MAX_BUF_SIZE] = {0};
	char buf[MAX_CMD_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	FILE *fp = NULL;

	if (NULL == output_struct) {
		return RETURN_ERR;
	}

	memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

	if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
	{
		if(apIndex == 0) //private_wifi for 2.4G
		{
			GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		}
		else if(apIndex == 1) //private_wifi for 5G
		{
			GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
		}
		else if(apIndex == 4) //public_wifi for 2.4G
		{
			sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
			if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
			{
				return RETURN_ERR;
			}
			if(buf[0] == '#')//tp-link
				GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
			else//tenda
				GetInterfaceName_virtualInterfaceName_2G(interface_name);
		}
		else if(apIndex == 5) //public_wifi for 5G
		{
			GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
		}

		GetIfacestatus(interface_name, interface_status);

		if(0 != strcmp(interface_status, "1"))
			return RETURN_ERR;

		snprintf(cmd, sizeof(cmd), "ifconfig %s > /tmp/SSID_Stats.txt", interface_name);
		system(cmd);

		fp = fopen("/tmp/SSID_Stats.txt", "r");
		if(fp == NULL)
		{
			printf("/tmp/SSID_Stats.txt not exists \n");
			return RETURN_ERR;
		}
		fclose(fp);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_PacketsReceived = strtoul(Value, NULL, 10);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_PacketsSent = strtoul(Value, NULL, 10);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_BytesReceived = strtoul(Value, NULL, 10);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_BytesSent = strtoul(Value, NULL, 10);

		/* There is no specific parameter from caller to associate the value wifi_Associations */
		//sprintf(cmd, "iw dev %s station dump | grep Station | wc -l", interface_name);
		//_syscmd(cmd, buf, sizeof(buf));
		//sscanf(buf,"%lu", &output_struct->wifi_Associations);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	char interface_name[MAX_BUF_SIZE] = {0};
	char interface_status[MAX_BUF_SIZE] = {0};
	char Value[MAX_BUF_SIZE] = {0};
	char buf[MAX_CMD_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	FILE *fp = NULL;

	if (NULL == output_struct) {
		return RETURN_ERR;
	}

	memset(output_struct, 0, sizeof(wifi_trafficStats_t));

	if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
	{
		if(apIndex == 0) //private_wifi for 2.4G
		{
			GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		}
		else if(apIndex == 1) //private_wifi for 5G
		{
			GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
		}
		else if(apIndex == 4) //public_wifi for 2.4G
		{
			sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
			if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
			{
				return RETURN_ERR;
			}
			if(buf[0] == '#')//tp-link
				GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
			else//tenda
				GetInterfaceName_virtualInterfaceName_2G(interface_name);
		}
		else if(apIndex == 5) //public_wifi for 5G
		{
			GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
		}

		GetIfacestatus(interface_name, interface_status);

		if(0 != strcmp(interface_status, "1"))
			return RETURN_ERR;

		snprintf(cmd, sizeof(cmd), "ifconfig %s > /tmp/SSID_Stats.txt", interface_name);
		system(cmd);

		fp = fopen("/tmp/SSID_Stats.txt", "r");
		if(fp == NULL)
		{
			printf("/tmp/SSID_Stats.txt not exists \n");
			return RETURN_ERR;
		}
		fclose(fp);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_ErrorsReceived = strtoul(Value, NULL, 10);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_ErrorsSent = strtoul(Value, NULL, 10);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_DiscardedPacketsReceived = strtoul(Value, NULL, 10);

		sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
		File_Reading(buf, Value);
		output_struct->wifi_DiscardedPacketsSent = strtoul(Value, NULL, 10);
	}

	output_struct->wifi_UnicastPacketsSent = 0;
	output_struct->wifi_UnicastPacketsReceived = 0;
	output_struct->wifi_MulticastPacketsSent = 0;
	output_struct->wifi_MulticastPacketsReceived = 0;
	output_struct->wifi_BroadcastPacketsSent = 0;
	output_struct->wifi_BroadcastPacketsRecevied = 0;
	output_struct->wifi_UnknownPacketsReceived = 0;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getSSIDTrafficStats(INT apIndex, wifi_ssidTrafficStats_t *output_struct)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	INT status = RETURN_ERR;

	output_struct->wifi_RetransCount=0;
	output_struct->wifi_FailedRetransCount=0;
	output_struct->wifi_RetryCount=0;
	output_struct->wifi_MultipleRetryCount=0;
	output_struct->wifi_ACKFailureCount=0;
	output_struct->wifi_AggregatedPacketCount=0;

	status = RETURN_OK;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return status;
}

INT wifi_getNeighboringWiFiDiagnosticResult(wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size)
{
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	INT status = RETURN_ERR;
	UINT index;
	wifi_neighbor_ap_t *pt=NULL;
	
	*output_array_size=2;
	//zqiu: HAL alloc the array and return to caller. Caller response to free it.
	*neighbor_ap_array=(wifi_neighbor_ap_t *)calloc(sizeof(wifi_neighbor_ap_t), *output_array_size);
	for (index = 0, pt=*neighbor_ap_array; index < *output_array_size; index++, pt++) {
		strcpy(pt->ap_Radio,"");
		strcpy(pt->ap_SSID,"");
		strcpy(pt->ap_BSSID,"");
		strcpy(pt->ap_Mode,"");
		pt->ap_Channel=1;
		pt->ap_SignalStrength=0;
		strcpy(pt->ap_SecurityModeEnabled,"");
		strcpy(pt->ap_EncryptionMode,"");
		strcpy(pt->ap_OperatingFrequencyBand,"");
		strcpy(pt->ap_SupportedStandards,"");
		strcpy(pt->ap_OperatingStandards,"");
		strcpy(pt->ap_OperatingChannelBandwidth,"");
		pt->ap_BeaconPeriod=1;
		pt->ap_Noise=0;
		strcpy(pt->ap_BasicDataTransferRates,"");
		strcpy(pt->ap_SupportedDataTransferRates,"");
		pt->ap_DTIMPeriod=1;
		pt->ap_ChannelUtilization = 1;
	}

	status = RETURN_OK;
  	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return status;
}

//----------------- AP HAL -------------------------------

//>> Deprecated: used for old RDKB code.
INT wifi_getAllAssociatedDeviceDetail(INT apIndex, ULONG *output_ulong, wifi_device_t **output_struct)
{
	if (NULL == output_ulong || NULL == output_struct) {
		return RETURN_ERR;
	} else {
		*output_ulong = 0;
		*output_struct = NULL;
		return RETURN_OK;
	}
}

#ifdef HAL_NETLINK_IMPL
static int AssoDevInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    char mac_addr[20];
    static int count=0;
    int rate=0;

    wifi_device_info_t *out = (wifi_device_info_t*)arg;

    nla_parse(tb,
              NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }


    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    //devIndex starts from 1
    if( ++count == out->wifi_devIndex )
    {
        mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
        //Getting the mac addrress
        mac_addr_aton(out->wifi_devMacAddress,mac_addr);

        if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
            fprintf(stderr, "failed to parse nested rate attributes!");
            return;
        }

        if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
            if(rinfo[NL80211_RATE_INFO_BITRATE])
                rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
                out->wifi_devTxRate = rate/10;
        }

        if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy)) {
            fprintf(stderr, "failed to parse nested rate attributes!");
            return;
        }

        if(sinfo[NL80211_STA_INFO_RX_BITRATE]) {
            if(rinfo[NL80211_RATE_INFO_BITRATE])
                rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
                out->wifi_devRxRate = rate/10;
        }
        if(sinfo[NL80211_STA_INFO_SIGNAL_AVG])
            out->wifi_devSignalStrength = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);

        out->wifi_devAssociatedDeviceAuthentiationState = 1;
        count = 0; //starts the count for next cycle
        return NL_STOP;
    }

    return NL_SKIP;

}
#endif

INT wifi_getAssociatedDeviceDetail(INT apIndex, INT devIndex, wifi_device_t *output_struct)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char if_name[10];

    wifi_device_info_t info;
    info.wifi_devIndex = devIndex;

    snprintf(if_name,sizeof(if_name),"wlan%d",apIndex);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                NLM_F_DUMP,
                NL80211_CMD_GET_STATION,
                0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_send_auto(nl.socket, msg);
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,AssoDevInfo_callback,&info);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);

    output_struct->wifi_devAssociatedDeviceAuthentiationState = (wifi_device_t*)info.wifi_devAssociatedDeviceAuthentiationState;
    output_struct->wifi_devRxRate = (wifi_device_t*)info.wifi_devRxRate;
    output_struct->wifi_devTxRate = (wifi_device_t*)info.wifi_devTxRate;
    output_struct->wifi_devSignalStrength = (wifi_device_t*)info.wifi_devSignalStrength;
    memcpy(&output_struct->wifi_devMacAddress,&info.wifi_devMacAddress,sizeof(wifi_device_t));
    return RETURN_OK;
#else
    //iw utility to retrieve station information
#define ASSODEVFILE "/tmp/AssociatedDevice_Stats.txt"
#define SIGNALFILE "/tmp/wifi_signalstrength.txt"
#define MACFILE "/tmp/wifi_AssoMac.txt"
#define TXRATEFILE "/tmp/wifi_txrate.txt"
#define RXRATEFILE "/tmp/wifi_rxrate.txt"
    FILE *file = NULL;
    char if_name[10] = {'\0'};
    char pipeCmd[256] = {'\0'};
    char line[256];
    int count,device = 0;

    snprintf(if_name,sizeof(if_name),"wlan%d",apIndex);

    sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", if_name, if_name);
    file = popen(pipeCmd, "r");

    if(file == NULL)
        return RETURN_ERR; //popen failed

    fgets(line, sizeof line, file);
    device = atoi(line);

    if(device == 0)
        return RETURN_ERR; //No devices are connected

    sprintf(pipeCmd,"iw dev %s station dump > "ASSODEVFILE, if_name);
    system(pipeCmd);

    system("cat "ASSODEVFILE" | grep 'signal avg' | cut -d ' ' -f2 | cut -d ':' -f2 | cut -f 2 | tr -s '\n' > "SIGNALFILE);

    system("cat  "ASSODEVFILE" | grep Station | cut -d ' ' -f 2  > "MACFILE);

    system("cat  "ASSODEVFILE" | grep 'tx bitrate' | cut -d ' ' -f2 | cut -d ':' -f2 |  cut -f 2 | tr -s '\n' | cut -d '.' -f1 > "TXRATEFILE);

    system("cat  "ASSODEVFILE" | grep 'rx bitrate' | cut -d ' ' -f2 | cut -d ':' -f2 |  cut -f 2 | tr -s '\n' | cut -d '.' -f1 > "RXRATEFILE);

    //devIndex starts from 1, ++count
    if((file = fopen(SIGNALFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devSignalStrength = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_signalstrength.txt failed");

    if((file = fopen(MACFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                sscanf(line, "%02x:%02x:%02x:%02x:%02x:%02x",&output_struct->wifi_devMacAddress[0],&output_struct->wifi_devMacAddress[1],&output_struct->wifi_devMacAddress[2],&output_struct->wifi_devMacAddress[3],&output_struct->wifi_devMacAddress[4],&output_struct->wifi_devMacAddress[5]);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_AssoMac.txt failed");

    if((file = fopen(TXRATEFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devTxRate = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_txrate.txt failed");

    if((file = fopen(RXRATEFILE, "r")) != NULL)
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devRxRate = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_rxrate.txt failed");

    output_struct->wifi_devAssociatedDeviceAuthentiationState = 1;

    return RETURN_OK;
#endif
}

INT wifi_kickAssociatedDevice(INT apIndex, wifi_device_t *device)
{
	if (NULL == device) {
		return RETURN_ERR;
	} else {
		return RETURN_OK;
	}
}
//<<


//--------------wifi_ap_hal-----------------------------
//enables CTS protection for the radio used by this AP
INT wifi_setRadioCtsProtectionEnable(INT apIndex, BOOL enable)
{
	//save config and Apply instantly
	return RETURN_ERR;
}

// enables OBSS Coexistence - fall back to 20MHz if necessary for the radio used by this ap
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable)
{
	//save config and Apply instantly
	return RETURN_ERR;
}

//P3 // sets the fragmentation threshold in bytes for the radio used by this ap
INT wifi_setRadioFragmentationThreshold(INT apIndex, UINT threshold)
{
	char cmd[64];
	char buf[512];
	//save config and apply instantly
	
    //zqiu:TODO: save config
    if (threshold > 0)  {
        snprintf(cmd, sizeof(cmd),  "iwconfig %s%d frag %d", AP_PREFIX, apIndex, threshold);
    } else {
        snprintf(cmd, sizeof(cmd),  "iwconfig %s%d frag off", AP_PREFIX, apIndex );
    }
    _syscmd(cmd,buf, sizeof(buf));
	
	return RETURN_OK;
}

// enable STBC mode in the hardwarwe, 0 == not enabled, 1 == enabled 
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable)
{
	//Save config and Apply instantly
	return RETURN_ERR;
}

// outputs A-MSDU enable status, 0 == not enabled, 1 == enabled 
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool)
{
	return RETURN_ERR;
}

// enables A-MSDU in the hardware, 0 == not enabled, 1 == enabled           
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable)
{
	//Apply instantly
	return RETURN_ERR;
}

//P2  // outputs the number of Tx streams
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int)
{
	return RETURN_ERR;
}

//P2  // sets the number of Tx streams to an enviornment variable
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams)  
{
	//save to wifi config, wait for wifi reset or wifi_pushTxChainMask to apply
	return RETURN_ERR;
}

//P2  // outputs the number of Rx streams
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int)
{
	if (NULL == output_int) 
		return RETURN_ERR;
	*output_int=1;		
	return RETURN_OK;	
}

//P2  // sets the number of Rx streams to an enviornment variable
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams)
{
	//save to wifi config, wait for wifi reset or wifi_pushRxChainMask to apply
	return RETURN_ERR;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantSupported(INT radioIndex, BOOL *output_bool)    
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=TRUE;		
	return RETURN_OK;	
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool)    
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=TRUE;		
	return RETURN_OK;	
}

//Set radio RDG enable setting
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio ADDBA enable setting
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool)	
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=TRUE;		
	return RETURN_OK;	
}

//Set radio ADDBA enable setting
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio auto block ack enable setting
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool)	
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=TRUE;		
	return RETURN_OK;	
}

//Set radio auto block ack enable setting
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio 11n pure mode enable support
INT wifi_getRadio11nGreenfieldSupported(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=TRUE;		
	return RETURN_OK;	
}

//Get radio 11n pure mode enable setting
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=TRUE;		
	return RETURN_OK;	
}

//Set radio 11n pure mode enable setting
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio IGMP snooping enable setting
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool)		
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=TRUE;		
	return RETURN_OK;	
}

//Set radio IGMP snooping enable setting
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable)	
{
	return RETURN_ERR;
}

//Get the Reset count of radio
INT wifi_getRadioResetCount(INT radioIndex, ULONG *output_int) 
{

	if (NULL == output_int) 
		return RETURN_ERR;
	if (radioIndex==0)	
		*output_int=1;
	else
		*output_int=3;
	return RETURN_OK;
}


//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------

// creates a new ap and pushes these parameters to the hardware
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid)
{
    char buf[1024];
    char cmd[128];
    
	if (NULL == essid) {
		return RETURN_ERR;
	} 
		
    snprintf(cmd,sizeof(cmd), "wlanconfig %s%d create wlandev %s%d wlanmode ap", AP_PREFIX, apIndex, RADIO_PREFIX, radioIndex);
    _syscmd(cmd, buf, sizeof(buf));

    snprintf(cmd,sizeof(cmd), "iwconfig %s%d essid %s mode master", AP_PREFIX, apIndex, essid);
    _syscmd(cmd, buf, sizeof(buf));

	wifi_pushSsidAdvertisementEnable(apIndex, !hideSsid);    
    
    snprintf(cmd,sizeof(cmd), "ifconfig %s%d txqueuelen 1000", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
		
	return RETURN_OK;
	
}

// deletes this ap entry on the hardware, clears all internal variables associaated with this ap
INT wifi_deleteAp(INT apIndex)
{	
	char buf[1024];
    char cmd[128];
    
    snprintf(cmd,sizeof(cmd),  "wlanconfig %s%d destroy", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

	wifi_removeApSecVaribles(apIndex);

	return RETURN_OK;
}

// Outputs a 16 byte or less name assocated with the AP.  String buffer must be pre-allocated by the caller
INT wifi_getApName(INT apIndex, CHAR *output_string)
{
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 16, "%s%d", AP_PREFIX, apIndex);
	/*char HConf_file[MAX_BUF_SIZE] = {'\0'};
	char IfName[MAX_BUF_SIZE] = {'\0'};
	char cmd[MAX_CMD_SIZE] = {'\0'};
	if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
	{
        sprintf(HConf_file,"%s%d%s","/nvram/hostapd",apIndex,".conf");
	GetInterfaceName(IfName,HConf_file);
	strcpy(output_string,IfName);	
	}*/
	return RETURN_OK;
}     
       
// Outputs the index number in that corresponds to the SSID string
INT wifi_getIndexFromName(CHAR *inputSsidString, INT *ouput_int)
{
    CHAR *pos=NULL;

    *ouput_int = -1;
	pos=strstr(inputSsidString, AP_PREFIX);
	if(pos) 
	{
		sscanf(pos+strlen(AP_PREFIX),"%d", ouput_int);
		return RETURN_OK;
	} 
	return RETURN_ERR;
}

// Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i"
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string)
{
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == output_string)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file, "wpa", buf, 64);
    if((strcmp(buf,"3")==0))
        snprintf(output_string, 32, "WPAand11i");
    else if((strcmp(buf,"2")==0))
        snprintf(output_string, 32, "11i");
    else if((strcmp(buf,"1")==0))
        snprintf(output_string, 32, "WPA");
    else
        snprintf(output_string, 32, "None");

    return RETURN_OK;
}

// Sets the beacon type enviornment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString)
{
    char config_file[MAX_BUF_SIZE] = {0};
    struct params list;

    if (NULL == beaconTypeString)
        return RETURN_ERR;
    list.name = "wpa";
    list.value = "0";

    if((strcmp(beaconTypeString,"WPAand11i")==0))
        list.value="3";
    else if((strcmp(beaconTypeString,"11i")==0))
        list.value="2";
    else if((strcmp(beaconTypeString,"WPA")==0))
        list.value="1";

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file,&list,1);
    //save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
    return RETURN_OK;
}

// sets the beacon interval on the hardware for this AP
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval) 
{
	//save config and apply instantly
	return RETURN_ERR;
}

INT wifi_setDTIMInterval(INT apIndex, INT dtimInterval)
{
	//save config and apply instantly
	return RETURN_ERR;
}

// Get the packet size threshold supported.
INT wifi_getApRtsThresholdSupported(INT apIndex, BOOL *output_bool)
{
	//save config and apply instantly
	if (NULL == output_bool) 
		return RETURN_ERR;
	*output_bool=FALSE;
	return RETURN_OK;
}

// sets the packet size threshold in bytes to apply RTS/CTS backoff rules. 
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold)
{
	char cmd[128];
	char buf[512];
    
    if (threshold > 0) {
        snprintf(cmd, sizeof(cmd), "iwconfig %s%d rts %d", AP_PREFIX, apIndex, threshold);
    } else {
        snprintf(cmd, sizeof(cmd), "iwconfig %s%d rts off", AP_PREFIX, apIndex);
    }
    _syscmd(cmd,buf, sizeof(buf));
	
	return RETURN_OK;
}

// outputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptionMode(INT apIndex, CHAR *output_string)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params;
    char buf[32];
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == output_string)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"wpa",buf,32);

    if(strcmp(buf,"0")==0)
    {
        printf("wpa_mode is %s ......... \n",buf);
        snprintf(output_string, 32, "None");
        return RETURN_OK;
    }

    if((strcmp(buf,"3")==0))
        params.name = "rsn_pairwise";
    else if((strcmp(buf,"2")==0))
        params.name = "rsn_pairwise";
    else if((strcmp(buf,"1")==0))
        params.name = "wpa_pairwise";

    memset(output_string,'\0',32);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,params.name,output_string,32);
    wifi_dbg_printf("\n%s output_string=%s",__func__,output_string);

    if(strcmp(output_string,"TKIP") == 0)
        strncpy(output_string,"TKIPEncryption", strlen("TKIPEncryption"));
    else if(strcmp(output_string,"CCMP") == 0)
        strncpy(output_string,"AESEncryption", strlen("AESEncryption"));
    else if(strcmp(output_string,"TKIP CCMP") == 0)
        strncpy(output_string,"TKIPandAESEncryption", strlen("TKIPandAESEncryption"));

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// sets the encyption mode enviornment variable.  Valid string format is "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char output_string[32];
    char config_file[MAX_BUF_SIZE] = {0};

    memset(output_string,'\0',32);
    wifi_getApWpaEncryptionMode(apIndex,output_string);

    if(strcmp(encMode, "TKIPEncryption") == 0)
        params.value = "TKIP";
    else if(strcmp(encMode,"AESEncryption") == 0)
        params.value = "CCMP";
    else if(strcmp(encMode,"TKIPandAESEncryption") == 0)
        params.value = "TKIP CCMP";

    if((strcmp(output_string,"WPAand11i")==0))
    {
        params.name = "wpa_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file,&params,1);

        params.name,"rsn_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file,&params,1);

        return RETURN_OK;
    }
    else if((strcmp(output_string,"11i")==0))
    {
        params.name = "rsn_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file,&params,1);
        return RETURN_OK;
    }
    else if((strcmp(output_string,"WPA")==0))
    {
        params.name = "wpa_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file,&params,1);
        return RETURN_OK;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// deletes internal security varable settings for this ap
INT wifi_removeApSecVaribles(INT apIndex)
{
	//TODO: remove the entry in hostapd config file
    //snprintf(cmd,sizeof(cmd), "sed -i 's/\\/nvram\\/etc\\/wpa2\\/WSC_%s%d.conf//g' /tmp/conf_filename", AP_PREFIX, apIndex);
    //_syscmd(cmd, buf, sizeof(buf));
	
    //snprintf(cmd,sizeof(cmd), "sed -i 's/\\/tmp\\//sec%s%d//g' /tmp/conf_filename", AP_PREFIX, apIndex);
    //_syscmd(cmd, buf, sizeof(buf));
	return RETURN_ERR;
}

// changes the hardware settings to disable encryption on this ap 
INT wifi_disableApEncryption(INT apIndex) 
{
	//Apply instantly
	return RETURN_ERR;
}

// set the authorization mode on this ap
// mode mapping as: 1: open, 2: shared, 4:auto
INT wifi_setApAuthMode(INT apIndex, INT mode)
{
	//Apply instantly
	return RETURN_ERR;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"                     
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
    //save to wifi config, and wait for wifi restart to apply
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    int ret;
    char config_file[MAX_BUF_SIZE] = {0};

    if(authMode ==  NULL)
        return RETURN_ERR;

    wifi_dbg_printf("\n%s AuthMode=%s",__func__,authMode);
    strncpy(params.name,"wpa_key_mgmt",strlen("wpa_key_mgmt"));

    if((strcmp(authMode,"PSKAuthentication") == 0) || (strcmp(authMode,"SharedAuthentication") == 0))
        strcpy(params.value,"WPA-PSK");
    else if(strcmp(authMode,"EAPAuthentication") == 0)
        strcpy(params.value,"WPA-EAP");
    else if(strcmp(authMode,"None") == 0) //Donot change in case the authMode is None
        return RETURN_OK;			  //This is taken careof in beaconType

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    ret=wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return ret;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_getApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
    //save to wifi config, and wait for wifi restart to apply
    char AuthenticationMode[50] = {0};
    int wpa_val;
    char BeaconType[50] = {0};
    char buf[32];
    char config_file[MAX_BUF_SIZE] = {0};

    *authMode = 0;
    wifi_getApBeaconType(apIndex,BeaconType);
    printf("%s____%s \n",__FUNCTION__,BeaconType);

    if(strcmp(BeaconType,"None") == 0)
        strcpy(authMode,"None");
    else
    {
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdRead(config_file,"wpa_key_mgmt",authMode,sizeof(authMode));
        wifi_dbg_printf("\n[%s]: AuthMode Name is : %s",__func__,authMode);
        if(strcmp(authMode,"WPA-PSK") == 0)
	        strcpy(authMode,"SharedAuthentication");
        else if(strcmp(authMode,"WPA-EAP") == 0)
            strcpy(authMode,"EAPAuthentication");
    }

    return RETURN_OK;
}

// Outputs the number of stations associated per AP
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
    char cmd[128]={0};
    char buf[128]={0};
		
    sprintf(cmd, "iw dev %s%d station dump | grep Station | wc -l", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    sscanf(buf,"%lu", output_ulong);

    return RETURN_OK;
}

// manually removes any active wi-fi association with the device specified on this ap
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac) 	
{
    char buf[126]={'\0'};

    sprintf(buf,"hostapd_cli -p /var/run/hostapd%d disassociate %s",apIndex,client_mac);
    system(buf);

    return RETURN_OK;
}

// outputs the radio index for the specified ap. similar as wifi_getSsidRadioIndex
INT wifi_getApRadioIndex(INT apIndex, INT *output_int) 
{
	*output_int=apIndex%2;
	return RETURN_OK;
}

// sets the radio index for the specific ap            
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex)                
{
	//set to config only and wait for wifi reset to apply settings
	return RETURN_ERR;
}

// Get the ACL MAC list per AP
INT wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size) 
{
        char acl_file_path[64] = {'\0'};
        char acl_list_buff[2048] = {'\0'};
        FILE *fp = NULL;

        sprintf(acl_file_path,"/tmp/wifi_acl_list_%d",apIndex);
        if((fp=fopen(acl_file_path,"r"))!=NULL){
                fscanf(fp,"%s",acl_list_buff);
                fclose(fp);
        }
        snprintf(macArray, buf_size, "%s\n",acl_list_buff);
        return RETURN_OK;
}
	
// Get the list of stations assocated per AP
INT wifi_getApDevicesAssociated(INT apIndex, CHAR *macArray, UINT buf_size) 
{
    FILE *fp;
    char mac[258]= {'\0'};
    char buf[258]= {'\0'};
    char tmp[258]= {'\0'};
    char *token=NULL;

    sprintf(buf,"iw dev %s%d station dump | grep Station  | cut -d ' ' -f2", AP_PREFIX,apIndex);
    fp=popen(buf,"r");

    while(fgets(mac,sizeof(mac),fp) != NULL)
    {
        token=strtok(mac,"\n");
        while(token!=NULL)
        {
            sprintf(token,"%s,",token);
            strcat(tmp,token);
            token=strtok(NULL,"\n");
        }
    }
    strcpy(macArray,tmp);

    return RETURN_OK;
}

// adds the mac address to the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress) 
{
        //Apply instantly               
        char acl_file_path[64] = {'\0'};
        FILE *fp = NULL;
        char tmp_buff[2048] = {'\0'};
        sprintf(acl_file_path,"/tmp/wifi_acl_list_%d",apIndex);

        if((fp=fopen(acl_file_path,"r"))==NULL){
                fp = fopen(acl_file_path,"w");
                if(fp){
                        fprintf(fp,"%s,",DeviceMacAddress);
                        fclose(fp);
                }
        }
        else{
                fscanf(fp,"%s",tmp_buff);
                fclose(fp);
                if(strcasestr(tmp_buff, DeviceMacAddress)==NULL){
                        fp = fopen(acl_file_path,"a");
                        if(fp){
                                fprintf(fp,"%s,",DeviceMacAddress);
                                fclose(fp);
                        }
                }
        }

        return RETURN_OK;
}

// deletes the mac address from the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)        
{
        //Apply instantly
        char acl_file_path[64] = {'\0'};
        char acl_list_buff[2048] = {'\0'};
        char tmp_buff[2048] = {'\0'};
        char buf[56]={'\0'};
        char mac_num[3]={'\0'};
        FILE *fp,*fr = NULL;
        char *ptr_dev = NULL, *ptr_acl_list = NULL;
        int     acl_list_len, ptr_dev_len;

        sprintf(acl_file_path,"/tmp/wifi_acl_list_%d",apIndex);
        if((fp=fopen(acl_file_path,"r"))!=NULL){
                printf("Del starrt\n");
                fscanf(fp,"%s",acl_list_buff);
                fclose(fp);

                acl_list_len = strlen(acl_list_buff);
                printf("acl_list_len = %d \n",acl_list_len);
                ptr_dev = strcasestr(acl_list_buff, DeviceMacAddress);
                if(ptr_dev != NULL){
                        ptr_dev_len = strlen(ptr_dev);
                        printf("ptr_dev_len =%d\n",ptr_dev_len);
                        strncpy(tmp_buff, acl_list_buff, (acl_list_len-ptr_dev_len));
                        printf("tmp_buff =%s\n",tmp_buff);
                        strcat(tmp_buff,(ptr_dev+18));
                         printf("tmp_buff 2nd=%s\n",tmp_buff);
                }
                fp = fopen(acl_file_path,"w");
                if(fp){
                        fprintf(fp,"%s",tmp_buff);
                        fclose(fp);
                }
       }
        return RETURN_OK;

}

// outputs the number of devices in the filter list
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint)   
{
	if (NULL == output_uint) 
		return RETURN_ERR;
	*output_uint=0;
	return RETURN_ERR;   
}
INT apply_rules(INT apIndex, CHAR *client_mac,CHAR *action,CHAR *interface)
{
        char cmd[128]={'\0'};
        char buf[128]={'\0'};

        if(strcmp(action,"DENY")==0)
        {
            sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j DROP",apIndex,interface,client_mac);
            system(buf);
            return RETURN_OK;
        }

        if(strcmp(action,"ALLOW")==0)
        {
            sprintf(buf,"iptables -I WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j RETURN",apIndex,interface,client_mac);
            system(buf);
            return RETURN_OK;
        }

        return RETURN_ERR;

}

// enable kick for devices on acl black list    
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable)    
{
    char aclArray[512]={0}, *acl=NULL;
    char assocArray[512]={0}, *asso=NULL;
    char buf[256]={'\0'};
    char action[10]={'\0'};
    FILE *fr=NULL;
    char interface[10]={'\0'};
	char config_file[MAX_BUF_SIZE] = {0};

    wifi_getApAclDevices( apIndex, aclArray, sizeof(aclArray));
    wifi_getApDevicesAssociated( apIndex, assocArray, sizeof(assocArray));
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"interface",interface,64);

    sprintf(buf,"iptables -F  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -D INPUT  -j WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -X  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -N  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -I INPUT 21 -j WifiServices%d",apIndex);
    system(buf);
       
    if ( enable == TRUE )
	{
        int device_count=0;
        strcpy(action,"DENY");
        //kick off the MAC which is in ACL array (deny list)
        acl = strtok (aclArray,",");
        while (acl != NULL) {
                if(strlen(acl)>=17)
                {
                        apply_rules(apIndex, acl,action,interface);
                        device_count++;
                        //Register mac to be blocked ,in syscfg.db persistent storage 
                        sprintf(buf,"syscfg set %dmacfilter%d %s",apIndex,device_count,acl);
                        system(buf);
                        sprintf(buf,"syscfg set %dcountfilter %d",apIndex,device_count);
                        system(buf);
                        system("syscfg commit");
 
                        wifi_kickApAssociatedDevice(apIndex, acl);
                }
                acl = strtok (NULL, ",");
        }
    }
	else
	{
        int device_count=0;
        char cmdmac[20]={'\0'};
        strcpy(action,"ALLOW");
        //kick off the MAC which is not in ACL array (allow list)
        acl = strtok (aclArray,",");
        while (acl != NULL) {
            if(strlen(acl)>=17)
            {
                apply_rules(apIndex, acl,action,interface);
                device_count++;
                //Register mac to be Allowed ,in syscfg.db persistent storage 
                sprintf(buf,"syscfg set %dmacfilter%d %s",apIndex,device_count,acl);
                system(buf);
                sprintf(buf,"syscfg set %dcountfilter %d",apIndex,device_count);
                system(buf);
                sprintf(cmdmac,"%s",acl);
            }
            acl = strtok (NULL, ",");
        }
        sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac ! --mac-source %s -j DROP",apIndex,interface,cmdmac);
        system(buf);
 
        //Disconnect the mac which is not in ACL
        asso = strtok (assocArray,",");
        while (asso != NULL) {
            if(strlen(asso)>=17 && !strcasestr(aclArray, asso))
                wifi_kickApAssociatedDevice(apIndex, asso);
            asso = strtok (NULL, ",");
        }
    }

    return RETURN_OK;
}

INT wifi_setPreferPrivateConnection(BOOL enable)
{
        fprintf(stderr,"%s Value of %d",__FUNCTION__,enable);
        char interface_name[100] = {0},ssid_cur_value[50] = {0};
        char buf[1024] = {0};
        if(enable == TRUE)
        {
                GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
                sprintf(buf,"ifconfig %s down" ,interface_name);
                system(buf);
                memset(buf,0,sizeof(buf));
                GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
                sprintf(buf,"ifconfig %s down" ,interface_name);
                system(buf);
        }
        else
        {
                File_Reading("cat /tmp/Get5gssidEnable.txt",&ssid_cur_value);
                if(strcmp(ssid_cur_value,"1") == 0)
                {
                        wifi_RestartHostapd_5G(1);
                        restarthostapd_all("/nvram/hostapd1.conf");
                }
                memset(ssid_cur_value,0,sizeof(ssid_cur_value));
                File_Reading("cat /tmp/GetPub2gssidEnable.txt",&ssid_cur_value);
                if(strcmp(ssid_cur_value,"1") == 0)
                {
                        wifi_RestartHostapd_2G();
                        restarthostapd_all("/nvram/hostapd4.conf");
                }
                memset(ssid_cur_value,0,sizeof(ssid_cur_value));
                File_Reading("cat /tmp/GetPub5gssidEnable.txt",&ssid_cur_value);
                if(strcmp(ssid_cur_value,"1") == 0)
                        restarthostapd_all("/nvram/hostapd5.conf");
        }
        return RETURN_OK;
}


// sets the mac address filter control mode.  0 == filter disabled, 1 == filter as whitelist, 2 == filter as blacklist
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
       char buf[256]={'\0'};

       if(apIndex==0 || apIndex==1)
       {
           //set the filtermode
           sprintf(buf,"syscfg set %dblockall %d",apIndex,filterMode);
           system(buf);
           system("syscfg commit");

           if(filterMode==0)
           {
              sprintf(buf,"iptables -F  WifiServices%d",apIndex);
              system(buf);
              return RETURN_OK;
           }
       }
       return RETURN_OK;

}

// enables internal gateway VLAN mode.  In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.  VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE. 
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled)
{
	return RETURN_ERR;
}      

// gets the vlan ID for this ap from an internal enviornment variable
INT wifi_getApVlanID(INT apIndex, INT *output_int)
{
	if(apIndex=0) {
		*output_int=100;
		return RETURN_OK;
	}
	return RETURN_ERR;
}   

// sets the vlan ID for this ap to an internal enviornment variable
INT wifi_setApVlanID(INT apIndex, INT vlanId)
{
	//save the vlanID to config and wait for wifi reset to apply (wifi up module would read this parameters and tag the AP with vlan id)
	return RETURN_ERR;
}   

// gets bridgeName, IP address and Subnet. bridgeName is a maximum of 32 characters,
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{	
    snprintf(bridgeName, 32, "br-home");
    snprintf(IP, 64, "192.168.1.1");
    snprintf(subnet, 64, "255.255.255.0");

    return RETURN_ERR;
}

//sets bridgeName, IP address and Subnet to internal enviornment variables. bridgeName is a maximum of 32 characters, 
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{	
    //save settings, wait for wifi reset or wifi_pushBridgeInfo to apply. 
    return RETURN_ERR;
}

// reset the vlan configuration for this ap
INT wifi_resetApVlanCfg(INT apIndex)
{
	//TODO: remove existing vlan for this ap
    
    //Reapply vlan settings
    wifi_pushBridgeInfo(apIndex);
	
	return RETURN_ERR;
}

// creates configuration variables needed for WPA/WPS.  These variables are implementation dependent and in some implementations these variables are used by hostapd when it is started.  Specific variables that are needed are dependent on the hostapd implementation. These variables are set by WPA/WPS security functions in this wifi HAL.  If not needed for a particular implementation this function may simply return no error.
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg)
{	
	return RETURN_ERR;
}

// starts hostapd, uses the variables in the hostapd config with format compatible with the specific hostapd implementation
INT wifi_startHostApd()
{
	char cmd[128] = {0};
	char buf[1028] = {0};

#if 0
	_syscmd("iwconfig wlan0|grep 802.11a",buf,sizeof(buf));
	if(strlen(buf) > 0)
	{
		system("sed -i 's/interface=wlan0/interface=wlan1/g' /nvram/hostapd0.conf");
		system("sed -i 's/interface=wlan1/interface=wlan0/g' /nvram/hostapd1.conf");
		_syscmd("hostapd -B /nvram/hostapd0.conf /nvram/hostapd1.conf",buf,sizeof(buf));
	}
	else
	{
		system("sed -i 's/interface=wlan1/interface=wlan0/g' /nvram/hostapd0.conf");
		system("sed -i 's/interface=wlan0/interface=wlan1/g' /nvram/hostapd1.conf");
		memset(buf,'\0',sizeof(buf));
		_syscmd("iwconfig wlan1",buf,sizeof(buf));
		if(strlen(buf)== 0)
		{	
			_syscmd("hostapd -B /nvram/hostapd0.conf",buf,sizeof(buf));
		}
		else
		{
			_syscmd("hostapd -B /nvram/hostapd0.conf /nvram/hostapd1.conf",buf,sizeof(buf));
		}
	}
#endif
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	system("systemctl start hostapd.service");
        system("echo 1 > /tmp/Get2gssidEnable.txt");
        system("echo 1 > /tmp/Get5gssidEnable.txt");
        system("echo 1 > /tmp/GetPub2gssidEnable.txt");
        system("echo 1 > /tmp/GetPub5gssidEnable.txt");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}


 // stops hostapd	
INT wifi_stopHostApd()                                        
{
    char cmd[128] = {0};
    char buf[128] = {0};

    sprintf(cmd,"systemctl stop hostapd-global");
    _syscmd(cmd, buf, sizeof(buf));

    return RETURN_OK;
}

// restart hostapd dummy function
INT wifi_restartHostApd()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	system("systemctl restart hostapd-global");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}

// sets the AP enable status variable for the specified ap.
INT wifi_setApEnable(INT apIndex, BOOL enable)
{
    char config_file[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    int ret = 0;

    if (enable == TRUE) {
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        //Hostapd will bring up this interface
        sprintf(cmd, "hostapd_cli -i global raw ADD bss_config=%s%d:%s", AP_PREFIX, apIndex, config_file);
        _syscmd(cmd, buf, sizeof(buf));
    }
    else {
        sprintf(cmd, "hostapd_cli -i global raw REMOVE %s%d", AP_PREFIX, apIndex);
        _syscmd(cmd, buf, sizeof(buf));
        sprintf(cmd, "ip link set %s%d down", AP_PREFIX, apIndex);
        _syscmd(cmd, buf, sizeof(buf));
    }
    //Store the AP enable settings and wait for wifi up to apply
    return RETURN_OK;
}

// Outputs the setting of the internal variable that is set by wifi_setEnable().  
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
	char cmd[MAX_CMD_SIZE] = {'\0'};
	char HConf_file[MAX_BUF_SIZE] = {'\0'};
	char path[MAX_BUF_SIZE] = {'\0'};
	char IfName[MAX_BUF_SIZE] = {'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	char tmp_status[MAX_BUF_SIZE] = {'\0'};
	int count = 0;
        FILE *fp = NULL;
	if((!output_bool) || (apIndex < 0))
		return RETURN_ERR;

	//retValue = wifi_getRadioEnable(apIndex, output_bool);
	if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
	{
		sprintf(HConf_file,"%s%d%s","/nvram/hostapd",apIndex,".conf");
		GetInterfaceName(IfName,HConf_file);
		if (NULL == output_bool)
		{
			return RETURN_ERR;
		} else {
			sprintf(cmd,"%s%s%s","ifconfig ",IfName," | grep RUNNING | tr -s ' ' | cut -d ' ' -f4");
			_syscmd(cmd,buf,sizeof(buf));
			if(strlen(buf)>0)
			{
				*output_bool=1;
				return RETURN_OK;
			}
			else
			{
				if(apIndex == 0)
					fp = fopen("/tmp/Get2gssidEnable.txt","r");
				else if(apIndex == 1)
					fp = fopen("/tmp/Get5gssidEnable.txt","r");
				else if(apIndex == 4)
					fp = fopen("/tmp/GetPub2gssidEnable.txt","r");
				else if(apIndex == 5)
					fp = fopen("/tmp/GetPub5gssidEnable.txt","r");
				if(fp == NULL)
				{
					*output_bool = 0;
					return RETURN_OK;
				}
				if(fgets(path, sizeof(path)-1, fp) != NULL)
				{
					for(count=0;path[count]!='\n';count++)
						tmp_status[count]=path[count];
					tmp_status[count]='\0';
				}
				fclose(fp);
				if(strcmp(tmp_status,"0") == 0)
					*output_bool = 0;
				else
					*output_bool = 1;
				return RETURN_OK;
			}
		}
	}
	else
	{
		if((apIndex > 5 ) && (apIndex < 17))
			return RETURN_OK;
		else
			return RETURN_ERR;
	}
}
// Outputs the AP "Enabled" "Disabled" status from driver 
INT wifi_getApStatus(INT apIndex, CHAR *output_string) 
{
	char cmd[128] = {0};
	char buf[128] = {0};
	INT  wlanIndex;
	BOOL output_bool;
	if ( NULL == output_string)
	{
		return RETURN_ERR;
	}
	else
	{
		wifi_getApEnable(apIndex,&output_bool);
	}

	if(output_bool == 1) 
		snprintf(output_string, 32, "Up");
	else
		snprintf(output_string, 32, "Disable");
	return RETURN_OK;
}

#if 0
// Outputs the AP "Enabled" "Disabled" status from driver 
INT wifi_getApStatus(INT apIndex, CHAR *output_string) 
{
	char cmd[128] = {0};
	char buf[128] = {0};
	INT  wlanIndex;


	if( 0 == apIndex ) // For 2.4 GHz
		wlanIndex = wifi_getApIndexForWiFiBand(band_2_4);
	else
		wlanIndex = wifi_getApIndexForWiFiBand(band_5);

	sprintf(cmd,"iwconfig  | grep wlan%d", wlanIndex);
	_syscmd(cmd, buf, sizeof(buf));
	
	if(strlen(buf)>3)
		snprintf(output_string, 32, "Up");
	else
		snprintf(output_string, 32, "Disable");
	return RETURN_OK;
}
#endif

//Indicates whether or not beacons include the SSID name.
// outputs a 1 if SSID on the AP is enabled, else ouputs 0
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output_bool) 
{
    //get the running status
    char output[128] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    if(!output_bool)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"ignore_broadcast_ssid",output,64);
    wifi_dbg_printf("\n[%s]: ignore_broadcast_ssid Name is : %s",__func__,output);

    if(output==NULL)
        return RETURN_ERR;

    if(strcmp(output,"1") == 0)
        *output_bool=FALSE;
    else
        *output_bool=TRUE;

    return RETURN_OK;
}

// sets an internal variable for ssid advertisement.  Set to 1 to enable, set to 0 to disable
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable) 
{
    //store the config, apply instantly
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char str[MAX_BUF_SIZE]={'\0'};
    char string[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *ch;
    struct params params;
    char config_file[MAX_BUF_SIZE] = {0};

    if(enable == TRUE)
        strcpy(string,"0");
    else
        strcpy(string,"1");

    params.name = "ignore_broadcast_ssid";
    params.value = string;
    printf("\n%s\n",__func__);

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//The maximum number of retransmission for a packet. This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
INT wifi_getApRetryLimit(INT apIndex, UINT *output_uint)
{
	//get the running status
	if(!output_uint)
		return RETURN_ERR;
	*output_uint=16;	
	return RETURN_OK;	
}

INT wifi_setApRetryLimit(INT apIndex, UINT number)
{
	//apply instantly
	return RETURN_ERR;
}

//Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
INT wifi_getApWMMCapability(INT apIndex, BOOL *output)
{
	if(!output)
		return RETURN_ERR;
	*output=TRUE;	
	return RETURN_OK;	
}

//Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD). Note: U-APSD support implies WMM support.
INT wifi_getApUAPSDCapability(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if(!output)
		return RETURN_ERR;
	*output=TRUE;	
	return RETURN_OK;
}

//Whether WMM support is currently enabled. When enabled, this is indicated in beacon frames.
INT wifi_getApWmmEnable(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if(!output)
		return RETURN_ERR;
	*output=TRUE;	
	return RETURN_OK;
}

// enables/disables WMM on the hardwawre for this AP.  enable==1, disable == 0    
INT wifi_setApWmmEnable(INT apIndex, BOOL enable)
{
	//Save config and apply instantly. 
	return RETURN_ERR;
}

//Whether U-APSD support is currently enabled. When enabled, this is indicated in beacon frames. Note: U-APSD can only be enabled if WMM is also enabled.
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if(!output)
		return RETURN_ERR;
	*output=TRUE;	
	return RETURN_OK;
}

// enables/disables Automatic Power Save Delivery on the hardwarwe for this AP
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable)
{
	//save config and apply instantly. 
	return RETURN_ERR;
}   

// Sets the WMM ACK polity on the hardware. AckPolicy false means do not acknowledge, true means acknowledge
INT wifi_setApWmmOgAckPolicy(INT apIndex, INT class, BOOL ackPolicy)  //RDKB
{
	//save config and apply instantly. 
	return RETURN_ERR;
}

//The maximum number of devices that can simultaneously be connected to the access point. A value of 0 means that there is no specific limit.			
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output_uint)
{
	//get the running status from driver
	if(!output_uint)
		return RETURN_ERR;
	*output_uint=5;	
	return RETURN_OK;
}

INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number)
{
	//store to wifi config, apply instantly
	return RETURN_ERR;
}

//The HighWatermarkThreshold value that is lesser than or equal to MaxAssociatedDevices. Setting this parameter does not actually limit the number of clients that can associate with this access point as that is controlled by MaxAssociatedDevices.	MaxAssociatedDevices or 50. The default value of this parameter should be equal to MaxAssociatedDevices. In case MaxAssociatedDevices is 0 (zero), the default value of this parameter should be 50. A value of 0 means that there is no specific limit and Watermark calculation algorithm should be turned off.			
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output_uint)
{
	//get the current threshold
	if(!output_uint)
		return RETURN_ERR;
	*output_uint=50;	
	return RETURN_OK;
}

INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold)
{
	//store the config, reset threshold, reset AssociatedDevicesHighWatermarkThresholdReached, reset AssociatedDevicesHighWatermarkDate to current time
	return RETURN_ERR;
}		

//Number of times the current total number of associated device has reached the HighWatermarkThreshold value. This calculation can be based on the parameter AssociatedDeviceNumberOfEntries as well. Implementation specifics about this parameter are left to the product group and the device vendors. It can be updated whenever there is a new client association request to the access point.	
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output_uint)
{
	if(!output_uint)
		return RETURN_ERR;
	*output_uint=3;	
	return RETURN_OK;
}

//Maximum number of associated devices that have ever associated with the access point concurrently since the last reset of the device or WiFi module.	
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output_uint)
{
	if(!output_uint)
		return RETURN_ERR;
	*output_uint=3;	
	return RETURN_OK;
}

//Date and Time at which the maximum number of associated devices ever associated with the access point concurrenlty since the last reset of the device or WiFi module (or in short when was X_COMCAST-COM_AssociatedDevicesHighWatermark updated). This dateTime value is in UTC.	
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds)
{
	if(!output_in_seconds)
		return RETURN_ERR;
	*output_in_seconds=0;	
	return RETURN_OK;
}

//Comma-separated list of strings. Indicates which security modes this AccessPoint instance is capable of supporting. Each list item is an enumeration of: None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output)
{
	if(!output)
		return RETURN_ERR;
	snprintf(output, 128, "None,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise");
	return RETURN_OK;
}		

//The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char securityType[32];
        char authMode[32];

        if(!output)
                return RETURN_ERR;

        wifi_getApBeaconType(apIndex, securityType);
        wifi_getApBasicAuthenticationMode(apIndex, authMode);

        if (strncmp(securityType,"None", strlen("None")) == 0) {
                strcpy(output,"None");
        } else if (strncmp(securityType,"WPAand11i", strlen("WPAand11i")) == 0) {
                if(strncmp(authMode,"EAPAuthentication", strlen("EAPAuthentication")) == 0) {
                        snprintf(output, 128, "WPA-WPA2-Enterprise");
                } else {
                        snprintf(output, 128, "WPA-WPA2-Personal");
                }
        } else if (strncmp(securityType,"WPA", strlen("WPA")) == 0) {
                if(strncmp(authMode,"EAPAuthentication", strlen("EAPAuthentication")) == 0) {
                        snprintf(output, 128, "WPA-Enterprise");
                } else {
                        snprintf(output, 128, "WPA-Personal");
                }
        } else if (strncmp(securityType,"11i", strlen("11i")) == 0) {
                if(strncmp(authMode,"EAPAuthentication", strlen("EAPAuthentication")) == 0) {
                        snprintf(output, 128, "WPA2-Enterprise");
                } else {
                        snprintf(output, 128, "WPA2-Personal");
                }
        } else {
                strcpy(output,"None");
        }
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}
  
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode)
{
	//store settings and wait for wifi up to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char securityType[32];
        char authMode[32];

        if(!encMode)
                return RETURN_ERR;

        printf("%s: apIndex %d, encMode %s\n",__func__, apIndex, encMode);

        if (strcmp(encMode, "None")==0) {
                strcpy(securityType,"None");
                strcpy(authMode,"None");
        } else if (strcmp(encMode, "WPA-WPA2-Personal")==0) {
                strcpy(securityType,"WPAand11i");
                strcpy(authMode,"PSKAuthentication");
        } else if (strcmp(encMode, "WPA-WPA2-Enterprise")==0) {
                strcpy(securityType,"WPAand11i");
                strcpy(authMode,"EAPAuthentication");
        } else if (strcmp(encMode, "WPA-Personal")==0) {
                strcpy(securityType,"WPA");
                strcpy(authMode,"PSKAuthentication");
        } else if (strcmp(encMode, "WPA-Enterprise")==0) {
                strcpy(securityType,"WPA");
                strcpy(authMode,"EAPAuthentication");
        } else if (strcmp(encMode, "WPA2-Personal")==0) {
                strcpy(securityType,"11i");
                strcpy(authMode,"PSKAuthentication");
        } else if (strcmp(encMode, "WPA2-Enterprise")==0) {
                strcpy(securityType,"11i");
                strcpy(authMode,"EAPAuthentication");
        } else {
                strcpy(securityType,"None");
                strcpy(authMode,"None");
        }
        wifi_setApBeaconType(apIndex, securityType);
        wifi_setApBasicAuthenticationMode(apIndex, authMode);
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}   


//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
// output_string must be pre-allocated as 64 character string by caller
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string)
{	
    char buf[32];
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"wpa",buf,64);

    if(output_string==NULL)
        return RETURN_ERR;

    if(strcmp(buf,"0")==0)
    {
        printf("wpa_mode is %s ......... \n",buf);
        return RETURN_ERR;
    }

    wifi_dbg_printf("\nFunc=%s\n",__func__);
    if(NULL == output_string)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"wpa_passphrase",output_string,64);
    wifi_dbg_printf("\noutput_string=%s\n",output_string);

    return RETURN_OK;
}

// sets an enviornment variable for the psk. Input string preSharedKey must be a maximum of 64 characters
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey)        
{	
    //save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
    struct params params={'\0'};
    int ret;
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == preSharedKey)
        return RETURN_ERR;

    params.name = "wpa_passphrase";

    if(strlen(preSharedKey)<8 || strlen(preSharedKey)>63)
    {
        wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
	    return RETURN_ERR;
    }
    else
    {
        params.value = preSharedKey;
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
	    ret=wifi_hostapdWrite(config_file,&params,1);
	    return ret;
    }
}

//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
// outputs the passphrase, maximum 63 characters
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string)
{	
    wifi_dbg_printf("\nFunc=%s\n",__func__);
    char buf[32];
    char config_file[MAX_BUF_SIZE] = {0};

    if (NULL == output_string)
          return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"wpa",buf,64);

    if(strcmp(buf,"0")==0)
    {
           printf("wpa_mode is %s ......... \n",buf);
           return RETURN_ERR;
    }

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"wpa_passphrase",output_string,64);
    wifi_dbg_printf("\noutput_string=%s\n",output_string);

    return RETURN_OK;
}

// sets the passphrase enviornment variable, max 63 characters
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase)
{	
    //save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
    struct params params={'\0'};
    int ret;
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == passPhrase)
        return RETURN_ERR;

    params.name = "wpa_passphrase";

    if(strlen(passPhrase)<8 || strlen(passPhrase)>63)
    {
        wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
        return RETURN_ERR;
    }
    else
    {
        params.value = passPhrase;
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        ret=wifi_hostapdWrite(config_file,&params,1);
        return ret;
    }
}

//When set to true, this AccessPoint instance's WiFi security settings are reset to their factory default values. The affected settings include ModeEnabled, WEPKey, PreSharedKey and KeyPassphrase.
INT wifi_setApSecurityReset(INT apIndex)
{
	//apply instantly
	return RETURN_ERR;
}

//The IP Address and port number of the RADIUS server used for WLAN security. RadiusServerIPAddr is only applicable when ModeEnabled is an Enterprise type (i.e. WPA-Enterprise, WPA2-Enterprise or WPA-WPA2-Enterprise).
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
	if(!IP_output || !Port_output || !RadiusSecret_output)
		return RETURN_ERR;
	snprintf(IP_output, 64, "75.56.77.78");
	*Port_output=123;
	snprintf(RadiusSecret_output, 64, "12345678");
	return RETURN_OK;
}

INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
	//store the paramters, and apply instantly
	return RETURN_ERR;
}

INT wifi_getApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
	if(!IP_output || !Port_output || !RadiusSecret_output)
		return RETURN_ERR;
	snprintf(IP_output, 64, "75.56.77.78");
	*Port_output=123;
	snprintf(RadiusSecret_output, 64, "12345678");
	return RETURN_OK;
}

INT wifi_setApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
	//store the paramters, and apply instantly
	return RETURN_ERR;
}

//RadiusSettings
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output)
{
	if(!output)
		return RETURN_ERR;
	
	output->RadiusServerRetries=3; 				//Number of retries for Radius requests.
	output->RadiusServerRequestTimeout=5; 		//Radius request timeout in seconds after which the request must be retransmitted for the # of retries available.	
	output->PMKLifetime=28800; 					//Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs).	
	output->PMKCaching=FALSE; 					//Enable or disable caching of PMK.	
	output->PMKCacheInterval=300; 				//Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes).	
	output->MaxAuthenticationAttempts=3; 		//Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature.
	output->BlacklistTableTimeout=600; 			//Time interval in seconds for which a client will continue to be blacklisted once it is marked so.	
	output->IdentityRequestRetryInterval=5; 	//Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.	
	output->QuietPeriodAfterFailedAuthentication=5;  	//The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it.	
	//snprintf(output->RadiusSecret, 64, "12345678");		//The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.
	
	return RETURN_OK;
}

INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input)	
{
	//store the paramters, and apply instantly
	return RETURN_ERR;
}

//Enables or disables WPS functionality for this access point.
// outputs the WPS enable state of this ap in output_bool 
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	if(!output_bool)
		return RETURN_ERR;
	if((apIndex == 0 ) || (apIndex == 1))
        {
		sprintf(cmd,"cat /nvram/hostapd%d.conf | grep wps_state | cut -d '=' -f1",apIndex);
	}
	_syscmd(cmd,buf, sizeof(buf));	
	if(strlen(buf)>0)
	{
		if(buf[0] == '#')
		{
			*output_bool=FALSE;
		}
		else
		{
			*output_bool=TRUE;
		}
	}
	return RETURN_OK;
}        

// sets the WPS enable enviornment variable for this ap to the value of enableValue, 1==enabled, 0==disabled     
INT wifi_setApWpsEnable(INT apIndex, BOOL enableValue)
{
	char buf[MAX_BUF_SIZE] = {0};
	char Hconf[MAX_BUF_SIZE] = {0};
	//store the paramters, and wait for wifi up to apply
	if((apIndex == 0 ) || (apIndex == 1))
	{
		sprintf(Hconf,"/nvram/hostapd%d.conf",apIndex);
		if(enableValue == FALSE)
		{
			sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wps_state=2/ s/^/","#/",'"',Hconf);
		}
		else
		{
			sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wps_state=2/ s/^#*//",'"',Hconf);
		}
		system(buf);
		if(apIndex == 0)
		{
			wifi_RestartPrivateWifi_2G();
		}
		else
		{
			wifi_RestartHostapd_5G(apIndex);
		}
		restarthostapd_all(Hconf);		
	}
	return RETURN_OK;
}        

//Comma-separated list of strings. Indicates WPS configuration methods supported by the device. Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output)
{
	if(!output)
		return RETURN_ERR;
	snprintf(output, 128, "Label,Display,PushButton,Keypad");
	return RETURN_OK;
}			

//Comma-separated list of strings. Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter. Indicates WPS configuration methods enabled on the device.
// Outputs a common separated list of the enabled WPS config methods, 64 bytes max
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output)
{
	if(!output)
		return RETURN_ERR;
	//snprintf(output, 128, "PushButton,PIN");
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	if((apIndex == 0) || (apIndex == 1))
	{
		sprintf(cmd,"cat /nvram/hostapd%d.conf | grep config_methods | cut -d '=' -f2 | sed 's/ /,/g' | sed 's/,$/ /g'",apIndex);

		_syscmd(cmd,buf, sizeof(buf));
		if(strlen(buf) > 0)
		{
			//	strcpy(output,buf);
			if(strstr(buf, "label")!=NULL)
				strcat(output, "Label,");
			if(strstr(buf, "display")!=NULL)
				strcat(output, "Display,");
			if(strstr(buf, "push_button")!=NULL)
				strcat(output, "PushButton,");
			if(strstr(buf, "keypad")!=NULL)
				strcat(output, "Keypad,");
			if(strlen(output))
				output[strlen(output)-1] = '\0';

		}
		return RETURN_OK;
	}
}

// sets an enviornment variable that specifies the WPS configuration method(s).  methodString is a comma separated list of methods USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString)
{
	//apply instantly. No setting need to be stored. 
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char Hconf[MAX_CMD_SIZE] = {0};
	char local_config_methods[MAX_BUF_SIZE] = {0};
	sprintf(Hconf,"/nvram/hostapd%d.conf",apIndex);
	if(strstr(methodString, "PushButton"))
	{
		if(strlen(local_config_methods) == 0)
			strcat(local_config_methods, "push_button");
		else
			strcat(local_config_methods, " push_button");

	}

	if(strstr(methodString, "Keypad"))
	{
		if(strlen(local_config_methods) == 0)
			strcat(local_config_methods, "keypad");
		else
			strcat(local_config_methods, " keypad");
	}

	if(strstr(methodString, "Label"))
	{
		if(strlen(local_config_methods) == 0)
			strcat(local_config_methods, "label");
		else
			strcat(local_config_methods, " label");

	}

	if(strstr(methodString, "Display"))
	{
		if(strlen(local_config_methods) == 0)
			strcat(local_config_methods, "display");
		else
			strcat(local_config_methods, " display");
	}

	if((apIndex == 0) || (apIndex == 1))
	{
		sprintf(buf,"sed -i '/config_methods=/d' %s",Hconf);
		sleep(2);
		system(buf);
		if(strcmp(local_config_methods,"push_button") == 0)
			sprintf(buf,"echo config_methods=%s >> /nvram/hostapd%d.conf",local_config_methods,apIndex);
		else if(strcmp(local_config_methods,"keypad label display") == 0)
			sprintf(buf,"echo config_methods=%s >> /nvram/hostapd%d.conf",local_config_methods,apIndex);
		else if(strcmp(local_config_methods,"push_button keypad label display") == 0)
			sprintf(buf,"echo config_methods=%s >> /nvram/hostapd%d.conf",local_config_methods,apIndex);
		system(buf);
		if(apIndex == 0)
		{
			wifi_RestartPrivateWifi_2G();
		}
		else
		{
			wifi_RestartHostapd_5G(apIndex);
		}
		restarthostapd_all(Hconf);
		return RETURN_OK;
	}
}

// outputs the pin value, ulong_pin must be allocated by the caller
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	if(!output_ulong)
		return RETURN_ERR;
	if((apIndex == 0) || (apIndex == 1))
	{
		sprintf(cmd,"cat /nvram/hostapd%d.conf | grep ap_pin | cut -d '=' -f2",apIndex);
		_syscmd(cmd,buf, sizeof(buf));
		if(strlen(buf) > 0)
			*output_ulong=atoi(buf);
	}
	return RETURN_OK;
}

// set an enviornment variable for the WPS pin for the selected AP. Normally, Device PIN should not be changed.
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin)
{
	//set the pin to wifi config and hostpad config. wait for wifi reset or hostapd reset to apply
	char ap_pin[MAX_BUF_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	char Hconf[MAX_BUF_SIZE] = {0};
	ULONG prev_pin = 0;
	sprintf(ap_pin, "%ld", pin); 
	wifi_getApWpsDevicePIN(apIndex,&prev_pin);
	sprintf(Hconf,"hostapd%d.conf",apIndex);
	if((apIndex == 0) || (apIndex == 1))
	{
		sprintf(buf,"%s%ld%s%ld%s%s","sed -i 's/ap_pin=",prev_pin,"/ap_pin=",pin,"/g' /nvram/",Hconf);
	}
	system(buf);
	if(apIndex == 0)
	{
		wifi_RestartPrivateWifi_2G();
	}
	else
	{
		wifi_RestartHostapd_5G(apIndex);
	}
	sprintf(Hconf,"/nvram/hostapd%d.conf",apIndex);
	restarthostapd_all(Hconf);

	return RETURN_OK;
}    

// Output string is either Not configured or Configured, max 32 characters
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string)
{
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[64];
	char buf[512]={0};
	char *pos=NULL;

	snprintf(output_string, 64, "Not configured");
	if((apIndex == 0) || (apIndex == 1))
	{

	sprintf(cmd, "hostapd_cli -p /var/run/hostapd%d get_config",apIndex);
	_syscmd(cmd,buf, sizeof(buf));
	
	if((pos=strstr(buf, "wps_state="))!=NULL) {
		if (strstr(pos, "configured")!=NULL)
			snprintf(output_string, 64, "Configured");
	}
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// sets the WPS pin for this AP
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin)
{
	char cmd[64];
	char buf[256]={0};
	BOOL enable;

	if((apIndex == 0) || (apIndex == 1))
	{
	wifi_getApEnable(apIndex, &enable);
	if (!enable) 
		return RETURN_ERR; 

	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable) 
		return RETURN_ERR; 

	snprintf(cmd, 64, "hostapd_cli -p /var/run/hostapd%d wps_pin any %s",apIndex, pin);
	_syscmd(cmd,buf, sizeof(buf));
	
	if((strstr(buf, "OK"))!=NULL) 
		return RETURN_OK;
	else
		return RETURN_ERR;
	}
	return RETURN_ERR;
}

// This function is called when the WPS push button has been pressed for this AP
INT wifi_setApWpsButtonPush(INT apIndex)
{
	char cmd[64];
	char buf[256]={0};
	BOOL enable;

	if((apIndex == 0) || (apIndex == 1))
	{
	wifi_getApEnable(apIndex, &enable);
	if (!enable) 
		return RETURN_ERR; 

	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable) 
		return RETURN_ERR; 

	snprintf(cmd, 64, "hostapd_cli -p /var/run/hostapd%d wps_pbc",apIndex);
	_syscmd(cmd,buf, sizeof(buf));
	
	if((strstr(buf, "OK"))!=NULL) 
		return RETURN_OK;
	else
		return RETURN_ERR;
	}
	return RETURN_ERR;
}

// cancels WPS mode for this AP
INT wifi_cancelApWPS(INT apIndex)
{
	char cmd[64];
	char buf[256]={0};
	BOOL enable;

	if((apIndex == 0) || (apIndex == 1))
        {
        wifi_getApEnable(apIndex, &enable);
        if (!enable)
                return RETURN_ERR;

        wifi_getApWpsEnable(apIndex, &enable);
        if (!enable)
                return RETURN_ERR;

	snprintf(cmd, 64, "hostapd_cli -p /var/run/hostapd%d wps_cancel",apIndex);
	_syscmd(cmd,buf, sizeof(buf));
	
	if((strstr(buf, "OK"))!=NULL) 
		return RETURN_OK;
	else
		return RETURN_ERR;
	}
	return RETURN_ERR;
}                                 

//Device.WiFi.AccessPoint.{i}.AssociatedDevice.*
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *f;
	int read_flag=0, auth_temp=0, mac_temp=0,i=0;
	char cmd[256], buf[2048];
	char *param , *value, *line=NULL;
	size_t len = 0;
	ssize_t nread;
	wifi_associated_dev_t *dev=NULL;
	*associated_dev_array = NULL;
	sprintf(cmd, "hostapd_cli -p /var/run/hostapd%d all_sta | grep AUTHORIZED | wc -l" , apIndex);
	_syscmd(cmd,buf,sizeof(buf));
	*output_array_size = atoi(buf);

	if (*output_array_size <= 0)
		return RETURN_OK;

	dev=(wifi_associated_dev_t *) calloc (*output_array_size, sizeof(wifi_associated_dev_t));
	*associated_dev_array = dev;
	sprintf(cmd, "hostapd_cli -p /var/run/hostapd%d all_sta > /tmp/connected_devices.txt" , apIndex);
	_syscmd(cmd,buf,sizeof(buf));
	f = fopen("/tmp/connected_devices.txt", "r");
	if (f==NULL)
	{
		*output_array_size=0;
		return RETURN_ERR;
	}
	while ((nread = getline(&line, &len, f)) != -1)
	{
		param = strtok(line,"=");
		value = strtok(NULL,"=");

		if( strcmp("flags",param) == 0 )
		{
			value[strlen(value)-1]='\0';
			if(strstr (value,"AUTHORIZED") != NULL )
			{
				dev[auth_temp].cli_AuthenticationState = 1;
				dev[auth_temp].cli_Active = 1;
				auth_temp++;
				read_flag=1;
			}
		}
		if(read_flag==1)
		{
			if( strcmp("dot11RSNAStatsSTAAddress",param) == 0 )
			{
				value[strlen(value)-1]='\0';
				sscanf(value, "%x:%x:%x:%x:%x:%x",
						(unsigned int *)&dev[mac_temp].cli_MACAddress[0],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[1],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[2],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[3],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[4],
						(unsigned int *)&dev[mac_temp].cli_MACAddress[5] );
				mac_temp++;
				read_flag=0;
			}
		}
	}
	*output_array_size = auth_temp;
	auth_temp=0;
	mac_temp=0;
	free(line);
	fclose(f);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

#define MACADDRESS_SIZE 6

INT wifihal_AssociatedDevicesstats3(INT apIndex,CHAR *interface_name,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	FILE *fp = NULL;
	char str[MAX_BUF_SIZE] = {0};
	int wificlientindex = 0 ;
	int count = 0;
	int signalstrength = 0;
	int arr[MACADDRESS_SIZE] = {0};
	unsigned char mac[MACADDRESS_SIZE] = {0};
	UINT wifi_count = 0;
	char virtual_interface_name[MAX_BUF_SIZE] = {0};
	char pipeCmd[MAX_CMD_SIZE] = {0};

	*output_array_size = 0;
	*associated_dev_array = NULL;

	sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", interface_name, interface_name);
	fp = popen(pipeCmd, "r");
	if (fp == NULL) 
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__ );
		return RETURN_ERR;
	}
	
	/* Read the output a line at a time - output it. */
	fgets(str, sizeof(str)-1, fp);
	wifi_count = (unsigned int) atoi ( str );
	*output_array_size = wifi_count;
	printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
	pclose(fp);

	if(wifi_count == 0)
	{
		return RETURN_OK;
	}
	else
	{
		wifi_associated_dev3_t* temp = NULL;
		temp = (wifi_associated_dev3_t*)calloc(1, sizeof(wifi_associated_dev3_t)*wifi_count) ;
		if(temp == NULL)
		{
			printf("Error Statement. Insufficient memory \n");
			return RETURN_ERR;
		}

		snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
		system(pipeCmd);
		memset(pipeCmd,0,sizeof(pipeCmd));
		if(apIndex == 0)
                	snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_2G.txt", interface_name);
		else if(apIndex == 1)
	                snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_5G.txt", interface_name);
                system(pipeCmd);

		fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
		if(fp == NULL)
		{
			printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
			return RETURN_ERR;
		}
		fclose(fp);

		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2", interface_name);
		fp = popen(pipeCmd, "r");
		if(fp)
		{
			for(count =0 ; count < wifi_count; count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
					printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
				}
				temp[count].cli_AuthenticationState = 1; //TODO
                temp[count].cli_Active = 1; //TODO
			}
			pclose(fp);
		}

		sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt", interface_name);
		fp = popen(pipeCmd, "r");
		if(fp)
		{ 
			pclose(fp);
		}
		fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				fgets(str, MAX_BUF_SIZE, fp);
				signalstrength = atoi(str);
				temp[count].cli_SignalStrength = signalstrength;
				temp[count].cli_RSSI = signalstrength;
				temp[count].cli_SNR = signalstrength + 95;
			}
			pclose(fp);
		}


		if((apIndex == 0) || (apIndex == 4))
		{
			for(count =0 ; count < wifi_count ;count++)
			{	
				strcpy(temp[count].cli_OperatingStandard,"g");
				strcpy(temp[count].cli_OperatingChannelBandwidth,"20MHz");
			}

			//BytesSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if(fp)
			{ 
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bytes_Send.txt | tr -s ' ' | cut -f 2","r");
			if(fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_BytesSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//BytesReceived
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bytes_Received.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_BytesReceived = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//PacketsSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Send.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}

			fp = popen("cat /tmp/Ass_Packets_Send.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_PacketsSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//PacketsReceived
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Received.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Packets_Received.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_PacketsReceived = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//ErrorsSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//ErrorsSent
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
				}
				pclose(fp);
			}

			//LastDataDownlinkRate
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
					temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
				}
				pclose(fp);
			}

			//LastDataUplinkRate
			sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt", interface_name);
			fp = popen(pipeCmd, "r");
			if (fp)
			{
				pclose(fp);
			}
			fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
			if (fp)
			{
				for (count = 0; count < wifi_count; count++)
				{
					fgets(str, MAX_BUF_SIZE, fp);
					temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
					temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
				}
				pclose(fp);
			}

		}
		else if ((apIndex == 1) || (apIndex == 5))
		{
			for (count = 0; count < wifi_count; count++)
			{
				strcpy(temp[count].cli_OperatingStandard, "a");
				strcpy(temp[count].cli_OperatingChannelBandwidth, "20MHz");
				temp[count].cli_BytesSent = 0;
				temp[count].cli_BytesReceived = 0;
				temp[count].cli_LastDataUplinkRate = 0;
				temp[count].cli_LastDataDownlinkRate = 0;
				temp[count].cli_PacketsSent = 0;
				temp[count].cli_PacketsReceived = 0;
				temp[count].cli_ErrorsSent = 0;
			}
		}

		for (count = 0; count < wifi_count; count++)
		{
			temp[count].cli_Retransmissions = 0;
			temp[count].cli_DataFramesSentAck = 0;
			temp[count].cli_DataFramesSentNoAck = 0;
			temp[count].cli_MinRSSI = 0;
			temp[count].cli_MaxRSSI = 0;
			strncpy(temp[count].cli_InterferenceSources, "", 64);
			memset(temp[count].cli_IPAddress, 0, 64);
			temp[count].cli_RetransCount = 0;
			temp[count].cli_FailedRetransCount = 0;
			temp[count].cli_RetryCount = 0;
			temp[count].cli_MultipleRetryCount = 0;
		}
		*associated_dev_array = temp;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

int wifihal_interfacestatus(CHAR *wifi_status,CHAR *interface_name)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
	char path[512] = {0},status[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE];
	int count = 0;

	sprintf(cmd, "ifconfig %s | grep RUNNING | tr -s ' ' | cut -d ' ' -f4", interface_name);
	fp = popen(cmd,"r");
	if(fp == NULL)
	{
		printf("Failed to run command in Function %s\n",__FUNCTION__);
		return 0;
	}
	if(fgets(path, sizeof(path)-1, fp) != NULL)
	{
		for(count=0;path[count]!='\n';count++)
			status[count]=path[count];
		status[count]='\0';
	}
	strcpy(wifi_status,status);
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//To-do
INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	//Using different approach to get required WiFi Parameters from system available commands
#if 0 
	FILE *f;
	int read_flag=0, auth_temp=0, mac_temp=0,i=0;
	char cmd[256], buf[2048];
	char *param , *value, *line=NULL;
	size_t len = 0;
	ssize_t nread;
	wifi_associated_dev3_t *dev=NULL;
	*associated_dev_array = NULL;
	sprintf(cmd, "hostapd_cli -p /var/run/hostapd%d all_sta | grep AUTHORIZED | wc -l" , apIndex);
	_syscmd(cmd,buf,sizeof(buf));
	*output_array_size = atoi(buf);

	if (*output_array_size <= 0)
			return RETURN_OK;

	dev=(wifi_associated_dev3_t *) AnscAllocateMemory(*output_array_size * sizeof(wifi_associated_dev3_t));
	*associated_dev_array = dev;
	sprintf(cmd, "hostapd_cli -p /var/run/hostapd%d all_sta > /tmp/connected_devices.txt" , apIndex);
	_syscmd(cmd,buf,sizeof(buf));
	f = fopen("/tmp/connected_devices.txt", "r");
	if (f==NULL)
	{
			*output_array_size=0;
			return RETURN_ERR;
	}
	while ((nread = getline(&line, &len, f)) != -1)
	{
			param = strtok(line,"=");
			value = strtok(NULL,"=");

			if( strcmp("flags",param) == 0 )
			{
					value[strlen(value)-1]='\0';
					if(strstr (value,"AUTHORIZED") != NULL )
					{
							dev[auth_temp].cli_AuthenticationState = 1;
							dev[auth_temp].cli_Active = 1;
							auth_temp++;
							read_flag=1;
					}
			}
			if(read_flag==1)
			{
					if( strcmp("dot11RSNAStatsSTAAddress",param) == 0 )
					{
							value[strlen(value)-1]='\0';
							sscanf(value, "%x:%x:%x:%x:%x:%x",
											(unsigned int *)&dev[mac_temp].cli_MACAddress[0],
											(unsigned int *)&dev[mac_temp].cli_MACAddress[1],
											(unsigned int *)&dev[mac_temp].cli_MACAddress[2],
											(unsigned int *)&dev[mac_temp].cli_MACAddress[3],
											(unsigned int *)&dev[mac_temp].cli_MACAddress[4],
											(unsigned int *)&dev[mac_temp].cli_MACAddress[5] );

					}
					else if( strcmp("rx_packets",param) == 0 )
					{
							sscanf(value, "%d", &(dev[mac_temp].cli_PacketsReceived));
					}

					else if( strcmp("tx_packets",param) == 0 )
					{
							sscanf(value, "%d", &(dev[mac_temp].cli_PacketsSent));				
					}

					else if( strcmp("rx_bytes",param) == 0 )
					{
							sscanf(value, "%d", &(dev[mac_temp].cli_BytesReceived));
					}

					else if( strcmp("tx_bytes",param) == 0 )
					{
							sscanf(value, "%d", &(dev[mac_temp].cli_BytesSent));		
							mac_temp++;
							read_flag=0;
					}						
			}
	}

	*output_array_size = auth_temp;
	auth_temp=0;
	mac_temp=0;
	free(line);
	fclose(f);
#endif
	char interface_name[MAX_BUF_SIZE] = {0};
	char wifi_status[MAX_BUF_SIZE] = {0};
	char hostapdconf[MAX_BUF_SIZE] = {0};

	wifi_associated_dev3_t *dev_array = NULL;
	ULONG wifi_count = 0;

	*associated_dev_array = NULL;
	*output_array_size = 0;

	printf("wifi_getApAssociatedDeviceDiagnosticResult3 apIndex = %d \n", apIndex);
	//if(apIndex == 0 || apIndex == 1 || apIndex == 4 || apIndex == 5) // These are availble in RPI.
	{
		sprintf(hostapdconf, "/nvram/hostapd%d.conf", apIndex);

		GetInterfaceName(interface_name, hostapdconf);

		if(strlen(interface_name) > 1)
		{
			wifihal_interfacestatus(wifi_status,interface_name);
			if(strcmp(wifi_status,"RUNNING") == 0)
			{
				wifihal_AssociatedDevicesstats3(apIndex,interface_name,&dev_array,&wifi_count);

				*associated_dev_array = dev_array;
				*output_array_size = wifi_count;		
			}
			else
			{
				*associated_dev_array = NULL;
			}
		}
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

/* getIPAddress function */
/**
* @description Returning IpAddress of the Matched String
*
* @param 
* @str Having MacAddress
* @ipaddr Having ipaddr 
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT getIPAddress(char *str,char *ipaddr)
{
    FILE *fp = NULL;
    char buf[1024] = {0},ipAddr[50] = {0},phyAddr[100] = {0},hostName[100] = {0};
    int LeaseTime = 0,ret = 0;
    if ( (fp=fopen("/nvram/dnsmasq.leases", "r")) == NULL )
    {
        return RETURN_ERR;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        /*
        Sample:sss
        1560336751 00:cd:fe:f3:25:e6 10.0.0.153 NallamousiPhone 01:00:cd:fe:f3:25:e6
        1560336751 12:34:56:78:9a:bc 10.0.0.154 NallamousiPhone 01:00:cd:fe:f3:25:e6
        */
        ret = sscanf(buf, LM_DHCP_CLIENT_FORMAT,
                 &(LeaseTime),
                 phyAddr,
                 ipAddr,
                 hostName
              );
        if(ret != 4)
		continue;
        if(strcmp(str,phyAddr) == 0)
                strcpy(ipaddr,ipAddr);
    }
    return RETURN_OK;
}

/* wifi_getApInactiveAssociatedDeviceDiagnosticResult function */
/**
* @description Returning Inactive wireless connected clients informations
*
* @param 
* @filename Holding private_wifi 2g/5g content files
* @associated_dev_array  Having inactiv wireless clients informations
* @output_array_size Returning Inactive wireless counts
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT wifi_getApInactiveAssociatedDeviceDiagnosticResult(char *filename,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	int count = 0,maccount = 0,i = 0,wificlientindex = 0;
	FILE *fp = NULL;
	int arr[MACADDRESS_SIZE] = {0};
	unsigned char mac[MACADDRESS_SIZE] = {0};
	char path[1024] = {0},str[1024] = {0},ipaddr[50] = {0},buf[512] = {0};
	sprintf(buf,"cat %s | grep Station | sort | uniq | wc -l",filename);
	fp = popen(buf,"r");
	if(fp == NULL)
		return RETURN_ERR;
	else
	{
		fgets(path,sizeof(path),fp);
		maccount = atoi(path);
	}
	pclose(fp);
	*output_array_size = maccount;
	wifi_associated_dev3_t* temp = NULL;
	temp = (wifi_associated_dev_t *) calloc (*output_array_size, sizeof(wifi_associated_dev_t));
	*associated_dev_array = temp;
	if(temp == NULL)
	{
		printf("Error Statement. Insufficient memory \n");
		return RETURN_ERR;
	}
	memset(buf,0,sizeof(buf));
	sprintf(buf,"cat %s | grep Station | cut -d ' ' -f2 | sort | uniq",filename);
	fp = popen(buf,"r");
	for(count = 0; count < maccount ; count++)
	{
		fgets(path,sizeof(path),fp);
		for(i = 0; path[i]!='\n';i++)
			str[i]=path[i];
		str[i]='\0';
		getIPAddress(str,ipaddr);
		memset(buf,0,sizeof(buf));
		if(strlen(ipaddr) > 0)
		{
			sprintf(buf,"ping -q -c 1 -W 1  \"%s\"  > /dev/null 2>&1",ipaddr);
			if (WEXITSTATUS(system(buf)) != 0)  //InActive wireless clients info
			{
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
					fprintf(stderr,"%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__,count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
				}
				temp[count].cli_AuthenticationState = 0; //TODO
				temp[count].cli_Active = 0; //TODO      
				temp[count].cli_SignalStrength = 0;
			}
			else //Active wireless clients info
			{
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
					fprintf(stderr,"%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__,count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
				}
				temp[count].cli_Active = 1;
			}
		}
		memset(ipaddr,0,sizeof(ipaddr));
	}
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering object
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Capability bool r/o
//To get Band Steering Capability
INT wifi_getBandSteeringCapability(BOOL *support) {
	*support=FALSE;
	return RETURN_OK;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable bool r/w
//To get Band Steering enable status
INT wifi_getBandSteeringEnable(BOOL *enable) {
	*enable=FALSE;
	return RETURN_OK;
}

//To turn on/off Band steering
INT wifi_setBandSteeringEnable(BOOL enable) {
	
	return RETURN_OK;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.UtilizationThreshold int r/w
//to set and read the band steering BandUtilizationThreshold parameters 
INT wifi_getBandSteeringBandUtilizationThreshold (INT radioIndex, INT *pBuThreshold){
	
	return RETURN_ERR;
}

INT wifi_setBandSteeringBandUtilizationThreshold (INT radioIndex, INT buThreshold){
	
	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.RSSIThreshold int r/w
//to set and read the band steering RSSIThreshold parameters 
INT wifi_getBandSteeringRSSIThreshold (INT radioIndex, INT *pRssiThreshold){
	
	return RETURN_ERR;
}

INT wifi_setBandSteeringRSSIThreshold (INT radioIndex, INT rssiThreshold){
	
	return RETURN_ERR;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.PhyRateThreshold int r/w
//to set and read the band steering physical modulation rate threshold parameters 
INT wifi_getBandSteeringPhyRateThreshold (INT radioIndex, INT *pPrThreshold) { //If chip is not support, return -1
	
	return RETURN_ERR;
}

INT wifi_setBandSteeringPhyRateThreshold (INT radioIndex, INT prThreshold) { //If chip is not support, return -1
	
	return RETURN_ERR;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.History string r/o
//pClientMAC[64]
//pSourceSSIDIndex[64]
//pDestSSIDIndex[64]
//pSteeringReason[256]
INT wifi_getBandSteeringLog(INT record_index, ULONG *pSteeringTime, CHAR *pClientMAC, INT *pSourceSSIDIndex, INT *pDestSSIDIndex, INT *pSteeringReason) { //if no steering or redord_index is out of boundary, return -1. pSteeringTime returns the UTC time in seconds. pClientMAC is pre allocated as 64bytes. pSteeringReason returns the predefined steering trigger reason 
	*pSteeringTime=1454685924;
	strcpy(pClientMAC, "14:CF:E2:13:CD:AE");
	strcpy(pSourceSSIDIndex, "ath0");
	strcpy(pSourceSSIDIndex, "ath1");
	snprintf(pSteeringReason, 256, "RSSIThreshold=%d; RSSI=%d", 30, 35);
	return RETURN_OK;
}

INT wifi_ifConfigDown(INT apIndex)
{
  INT status = RETURN_OK;
  char cmd[64];

  snprintf(cmd, sizeof(cmd), "ifconfig ath%d down", apIndex);
  printf("%s: %s\n", __func__, cmd);
  system(cmd);

  return status;
}

INT wifi_ifConfigUp(INT apIndex)
{
    char cmd[128];
	char buf[1024];  

    snprintf(cmd, sizeof(cmd), "ifconfig %s%d up 2>/dev/null", AP_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    return 0;
}

//>> Deprecated. Replace with wifi_applyRadioSettings
INT wifi_pushBridgeInfo(INT apIndex)
{
    char ip[32]; 
    char subnet[32]; 
    char bridge[32];
    int vlanId;
    char cmd[128];
    char buf[1024];

    wifi_getApBridgeInfo(apIndex,bridge,ip,subnet);
    wifi_getApVlanID(apIndex,&vlanId);

    snprintf(cmd, sizeof(cmd), "cfgVlan %s%d %s %d %s ", AP_PREFIX, apIndex, bridge, vlanId, ip);
    _syscmd(cmd,buf, sizeof(buf));

    return 0;
}

INT wifi_pushChannel(INT radioIndex, UINT channel)
{
    char cmd[128];
    char buf[1024];
	int  apIndex;
	
	apIndex=(radioIndex==0)?0:1;	
	snprintf(cmd, sizeof(cmd), "iwconfig %s%d freq %d",AP_PREFIX, apIndex,channel);
	_syscmd(cmd,buf, sizeof(buf));

    return 0;
}

INT wifi_pushChannelMode(INT radioIndex)
{
	//Apply Channel mode, pure mode, etc that been set by wifi_setRadioChannelMode() instantly
	return RETURN_ERR;
}

INT wifi_pushDefaultValues(INT radioIndex)
{
    //Apply Comcast specified default radio settings instantly
	//AMPDU=1
	//AMPDUFrames=32
	//AMPDULim=50000
	//txqueuelen=1000
    
    return RETURN_ERR;
}

INT wifi_pushTxChainMask(INT radioIndex)
{
	//Apply default TxChainMask instantly
	return RETURN_ERR;
}

INT wifi_pushRxChainMask(INT radioIndex)
{
	//Apply default RxChainMask instantly
	return RETURN_ERR;
}
//<<

INT wifi_pushSSID(INT apIndex, CHAR *ssid)
{
    INT status;

    status = wifi_setSSIDName(apIndex,ssid);
    wifi_setApEnable(apIndex,FALSE);
    wifi_setApEnable(apIndex,TRUE);

    return status;
}

INT wifi_pushSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
    //Apply default Ssid Advertisement instantly

    return RETURN_ERR;
}

INT wifi_getRadioUpTime(INT radioIndex, ULONG *output)
{
	INT status = RETURN_ERR;
	*output = 0;
	return RETURN_ERR;
}

INT wifi_getApEnableOnLine(INT wlanIndex, BOOL *enabled)
{
   return RETURN_OK;
}

INT wifi_getApSecurityWpaRekeyInterval(INT apIndex, INT *output_int)
{
   return RETURN_OK;
}

//To-do
INT wifi_getApSecurityMFPConfig(INT apIndex, CHAR *output_string)
{
	return RETURN_OK;
}
INT wifi_setApSecurityMFPConfig(INT apIndex, CHAR *MfpConfig)
{
	return RETURN_OK;
}
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char output[50]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file,"channel",output,64);

    if(strcmp(output,"0")==0)
        *output_bool = TRUE;
    else
        *output_bool = FALSE;

    WIFI_ENTRY_EXIT_DEBUG("Exit %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getRouterEnable(INT wlanIndex, BOOL *enabled)
{
   return RETURN_OK;
}

INT wifi_setApSecurityWpaRekeyInterval(INT apIndex, INT *rekeyInterval)
{
   return RETURN_OK;
}

INT wifi_setRouterEnable(INT wlanIndex, INT *RouterEnabled)
{
   return RETURN_OK;
}

INT wifi_getApIndexForWiFiBand(wifi_band band)
{
    char cmd[128] = {0};
    char buf[1028] = {0};
    int  apIndex = -1;

    _syscmd("iwconfig wlan0|grep 802.11a", buf, sizeof(buf));
    if( strlen(buf) > 0 )
    {
        apIndex = ( band_2_4 == band ) ? 1: 0;
    }
    else
    {
        apIndex = ( band_2_4 == band ) ? 0 : 1;
    }

    wifi_dbg_printf("AP Index for band %d is %d", band, apIndex );
    return apIndex;
}

INT wifi_getRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char config_file[MAX_BUF_SIZE] = {0};

    if (NULL == output)
        return RETURN_ERR;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,wlanIndex);
    wifi_hostapdRead(config_file,"hw_mode",output,64);

    if(strcmp(output,"b")==0)
        sprintf(output, "%s", "1,2,5.5,11");
    else if (strcmp(output,"a")==0)
        sprintf(output, "%s", "6,9,11,12,18,24,36,48,54");
    else if ((strcmp(output,"n")==0) | (strcmp(output,"g")==0))
        sprintf(output, "%s", "1,2,5.5,6,9,11,12,18,24,36,48,54");

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char *temp;
    char temp_output[128];
    char temp_TransmitRates[128];
    char config_file[MAX_BUF_SIZE] = {0};

    if (NULL == output)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,wlanIndex);
    wifi_hostapdRead(config_file,"supported_rates",output,64);

    strcpy(temp_TransmitRates,output);
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates," ");
    while(temp!=NULL)
    {
        temp[strlen(temp)-1]=0;
        if((temp[0]=='5') && (temp[1]=='\0'))
        {
            temp="5.5";
        }
        strcat(temp_output,temp);
        temp = strtok(NULL," ");
        if(temp!=NULL)
        {
            strcat(temp_output,",");
        }
    }
    strcpy(output,temp_output);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
        return RETURN_OK;
}


INT wifi_setRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
    int i=0;
    char *temp;
    char temp1[128];
    char temp_output[128];
    char temp_TransmitRates[128];
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == output)
        return RETURN_ERR;

    strcpy(temp_TransmitRates,output);

    for(i=0;i<strlen(temp_TransmitRates);i++)
    {
        if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) | (temp_TransmitRates[i]==' ') | (temp_TransmitRates[i]=='.'))
        {
            continue;
        }
        else
        {
            return RETURN_ERR;
        }
    }
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates," ");
    while(temp!=NULL)
    {
        strcpy(temp1,temp);
        if(wlanIndex==1)
        {
            if((strcmp(temp,"1")==0) | (strcmp(temp,"2")==0) | (strcmp(temp,"5.5")==0))
            {
                return RETURN_ERR;
            }
        }

        if(strcmp(temp,"5.5")==0)
        {
            strcpy(temp1,"55");
        }
        else
        {
            strcat(temp1,"0");
        }
        strcat(temp_output,temp1);
        temp = strtok(NULL," ");
        if(temp!=NULL)
        {
            strcat(temp_output," ");
        }
    }
    strcpy(output,temp_output);


    params.name = "supported_rates";
    params.value = output;

    wifi_dbg_printf("\n%s:",__func__);
    wifi_dbg_printf("params.value=%s\n",params.value);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,wlanIndex);
    wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_pushRadioChannel2(INT radioIndex, UINT channel, UINT channel_width_MHz, UINT csa_beacon_count)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//CSA operation is not done, so we ignore beacon count here ** csa_beacon_count **
	wifi_setRadioChannel(radioIndex,channel); //Set the Channel 
	wifi_setRadioOperatingChannelBandwidth(radioIndex,channel_width_MHz); //Set the bandwidth for the Channel
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
INT wifi_getNeighboringWiFiStatus(INT apIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
		WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char cmd[1024] =  {0};
        char buf[1024] = {0};
        char tmp_buf[1024] = {0};

	char HConf_file[MAX_BUF_SIZE] = {'\0'};
        int count = 0;
        char interface_name[50] = {0};

 	*neighbor_ap_array = NULL;
    	*output_array_size = 0;
 	wifi_neighbor_ap2_t *scan_array = NULL;
        int scan_count=0;

	
	sprintf(HConf_file,"%s%d%s","/nvram/hostapd",apIndex,".conf");
        GetInterfaceName(interface_name,HConf_file);

	sprintf(cmd,"%s%s%s","iwlist ",interface_name," scan | grep Address | cut -d " " -f15 |  tr -s ' ' |   tr \\n ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
	 _syscmd(cmd,buf,sizeof(buf));


	for(count = 0;buf[count]!='\n';count++)
                tmp_buf[count] = buf[count]; //ajusting the size
        tmp_buf[count] = '\0';

 	char* token = strtok(tmp_buf, ",");

	while (token != NULL) { 
        	scan_array->ap_BSSID[scan_count] = token;
		scan_count++;
	        token = strtok(NULL, ","); 
    	} 

	*neighbor_ap_array = scan_array;
	*output_array_size = scan_count;
return RETURN_OK;

}
INT wifi_getApAssociatedDeviceStats(
        INT apIndex,
        mac_address_t *clientMacAddress,
        wifi_associated_dev_stats_t *associated_dev_stats,
        u64 *handle)
{
    wifi_associated_dev_stats_t *dev_stats = associated_dev_stats;
	char HConf_file[MAX_BUF_SIZE] = {'\0'};
        int count = 0;
	int i=0;
        char interface_name[50] = {0};
	char cmd[1024] =  {0};
	char buf[1024] = {0};
	char tmp_buf[1024] = {0};

	const char *StatsName[] = {"rx packets",
				   "tx packets",
				   "rx bytes",
				   "tx bytes",
			           "tx errors"	};

   sprintf(HConf_file,"%s%d%s","/nvram/hostapd",apIndex,".conf");
   GetInterfaceName(interface_name,HConf_file);

   for(i=0;i<=4;i++)
   {

	 sprintf(cmd,"%s%s%s%s%s","iw dev ",interface_name," station dump |  grep -i -A 18  ",clientMacAddress,"  | grep ",StatsName[i]," | cut -d ':' -f2");

        _syscmd(cmd,buf,sizeof(buf));
	 for(count = 0;buf[count]!='\n';count++)
                tmp_buf[count] = buf[count]; //ajusting the size
        tmp_buf[count] = '\0';

	if(strcmp(StatsName[i],"rx packets") == 0)
	{
		strcpy(dev_stats->cli_rx_frames,tmp_buf);
	}
	else if(strcmp(StatsName[i],"tx packets") == 0)
	{
		 strcpy(dev_stats->cli_tx_frames,tmp_buf);
	}
	else if(strcmp(StatsName[i],"rx bytes") == 0)
        {
                 strcpy(dev_stats->cli_rx_bytes,tmp_buf);
        }
	else if(strcmp(StatsName[i],"tx bytes") == 0)
        {
                 strcpy(dev_stats->cli_tx_bytes,tmp_buf);
        }
	else if(strcmp(StatsName[i],"tx failed") == 0)
        {
                 strcpy(dev_stats->cli_rx_bytes,tmp_buf);
        }
	else
		printf("No Matching stats info");
    }
    return RETURN_OK;

}

INT wifi_getSSIDNameStatus(INT apIndex, CHAR *output_string)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[1024] =  {0};
    char buf[1024] = {0};
    char tmp_buf[50] = {0};
    int count = 0;

    if (NULL == output_string)
    {
        return RETURN_ERR;
    }

    sprintf(cmd,"iw dev %s%d info | grep ssid | cut -d ' ' -f2", AP_PREFIX,apIndex);
    _syscmd(cmd,buf,sizeof(buf));

    for(count = 0;buf[count]!='\n';count++)
        tmp_buf[count] = buf[count]; //ajusting the size
    tmp_buf[count] = '\0';

    strcpy(output_string,tmp_buf);
    return RETURN_OK;
}
INT wifi_getApMacAddressControlMode(INT apIndex, INT *output_filterMode)
{
         char cmd[1024] =  {0};
         char tmp_buf[512] = {0};
         char buf[256]={'\0'};
         int count = 0;

if(apIndex==0 || apIndex==1)
       {
           //set the filtermode
           sprintf(cmd,"syscfg get %dblockall",apIndex);
           _syscmd(cmd,buf,sizeof(buf));
        for(count = 0;buf[count]!='\n';count++)
                tmp_buf[count] = buf[count]; //ajusting the size
        tmp_buf[count] = '\0';
        strcpy(output_filterMode,tmp_buf);
        return RETURN_OK;
       }
return RETURN_ERR;
}
INT wifi_getApAssociatedDeviceDiagnosticResult2(INT apIndex,wifi_associated_dev2_t **associated_dev_array,UINT *output_array_size)
{
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

        FILE *fp = NULL;
        char str[MAX_BUF_SIZE] = {0};
        int wificlientindex = 0 ;
        int count = 0;
        int signalstrength = 0;
        int arr[MACADDRESS_SIZE] = {0};
        unsigned char mac[MACADDRESS_SIZE] = {0};
        UINT wifi_count = 0;
        char virtual_interface_name[MAX_BUF_SIZE] = {0};
        char pipeCmd[MAX_CMD_SIZE] = {0};

        *output_array_size = 0;
        *associated_dev_array = NULL;
	char interface_name[50] = {0};
	 char HConf_file[MAX_BUF_SIZE] = {'\0'};

        sprintf(HConf_file,"%s%d%s","/nvram/hostapd",apIndex,".conf");
        GetInterfaceName(interface_name,HConf_file);

        sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", interface_name, interface_name);
        fp = popen(pipeCmd, "r");
        if (fp == NULL)
        {
                printf("Failed to run command inside function %s\n",__FUNCTION__ );
                return RETURN_ERR;
        }

        /* Read the output a line at a time - output it. */
        fgets(str, sizeof(str)-1, fp);
        wifi_count = (unsigned int) atoi ( str );
        *output_array_size = wifi_count;
        printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
        pclose(fp);

        if(wifi_count == 0)
        {
                return RETURN_OK;
        }
        else
        {
                wifi_associated_dev2_t* temp = NULL;
                temp = (wifi_associated_dev2_t*)calloc(1, sizeof(wifi_associated_dev2_t)*wifi_count) ;
                if(temp == NULL)
                {
                        printf("Error Statement. Insufficient memory \n");
                        return RETURN_ERR;
                }

                snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
                system(pipeCmd);

                fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
                if(fp == NULL)
                {
                        printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
                        return RETURN_ERR;
                }
                fclose(fp);

                sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2", interface_name);
                fp = popen(pipeCmd, "r");
                if(fp)
                {
                        for(count =0 ; count < wifi_count; count++)
                        {
                                fgets(str, MAX_BUF_SIZE, fp);
                                if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
                                {
                                        for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
                                        {
                                                mac[wificlientindex] = (unsigned char) arr[wificlientindex];

                                        }
                                        memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
                                        printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
                                }
                                temp[count].cli_AuthenticationState = 1; //TODO
                temp[count].cli_Active = 1; //TODO
                        }
                        pclose(fp);
                }

//Updating  RSSI per client
              sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt", interface_name);
                fp = popen(pipeCmd, "r");
                if(fp)
                {
                        pclose(fp);
                }
                fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
                if(fp)
                {
                        for(count =0 ; count < wifi_count ;count++)
                        {
                                fgets(str, MAX_BUF_SIZE, fp);
                                signalstrength = atoi(str);
                                temp[count].cli_RSSI = signalstrength;
                        }
                        pclose(fp);
                }


			//LastDataDownlinkRate
                       sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt", interface_name);
                        fp = popen(pipeCmd, "r");
                        if (fp)
                        {
                                pclose(fp);
                        }
                        fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
                        if (fp)
                        {
                                for (count = 0; count < wifi_count; count++)
                                {
                                        fgets(str, MAX_BUF_SIZE, fp);
                                        temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
                                        temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
                                }
                                pclose(fp);
                        }

                        //LastDataUplinkRate
                        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt", interface_name);
                        fp = popen(pipeCmd, "r");
                        if (fp)
                        {
                                pclose(fp);
                        }
                        fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
                        if (fp)
                        {
                                for (count = 0; count < wifi_count; count++)
                                {
                                        fgets(str, MAX_BUF_SIZE, fp);
                                        temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
                                        temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
                                }
                                pclose(fp);
                        }
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;

}

INT wifi_getSSIDTrafficStats2(INT ssidIndex,wifi_ssidTrafficStats2_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp = NULL;
        char HConf_file[MAX_BUF_SIZE] = {'\0'};
        char interface_name[50] = {0};
        char pipeCmd[MAX_CMD_SIZE] = {0};
        char str[MAX_BUF_SIZE] = {0};
	wifi_ssidTrafficStats2_t *out = output_struct;
	 sprintf(HConf_file,"%s%d%s","/nvram/hostapd",ssidIndex,".conf");
         GetInterfaceName(interface_name,HConf_file);
	 sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | sed 's/ /,/g' | sed 's/,$/ /g' | cut -d  ' ' -f11");
	 fp = popen(pipeCmd, "r");
         out->ssid_BytesSent = atol(str);

	sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | sed 's/ /,/g' | sed 's/,$/ /g' | cut -d  ' ' -f3");
         fp = popen(pipeCmd, "r");
         out->ssid_BytesReceived = atol(str);


	sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | sed 's/ /,/g' | sed 's/,$/ /g' | cut -d  ' ' -f12");
         fp = popen(pipeCmd, "r");
         out->ssid_PacketsSent = atol(str);
			
	sprintf(pipeCmd,"%s%s%s","cat /proc/net/dev | grep ",interface_name," |  tr -s ' '  | sed 's/ /,/g' | sed 's/,$/ /g' | cut -d  ' ' -f4");
         fp = popen(pipeCmd, "r");
         out->ssid_PacketsReceived = atol(str);
/*
	 out->ssid_UnicastPacketsSent        = uni->ims_tx_data_packets;
    	 out->ssid_UnicastPacketsReceived    = uni->ims_rx_data_packets;
	 out->ssid_MulticastPacketsSent      = multi->ims_tx_data_packets - multi->ims_tx_bcast_data_packets;
    	 out->ssid_MulticastPacketsReceived  = multi->ims_rx_data_packets - multi->ims_rx_bcast_data_packets;
         out->ssid_BroadcastPacketsSent      = multi->ims_tx_bcast_data_packets;
    	 out->ssid_BroadcastPacketsRecevied  = multi->ims_rx_bcast_data_packets; 
*/
 return RETURN_OK;

}

//Enables or disables device isolation. A value of true means that the devices connected to the Access Point are isolated from all other devices within the home network (as is typically the case for a Wireless Hotspot).     
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char output_val[3]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"ap_isolate",output_val,64);

    if( strcmp(output_val,"1") == 0 )
        *output=TRUE;
    else
        *output=FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char str[MAX_BUF_SIZE]={'\0'};
    char string[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *ch;
    char config_file[MAX_BUF_SIZE] = {0};
    struct params params;

    if(enable == TRUE)
        strcpy(string,"1");
    else
        strcpy(string,"0");

    params.name = "ap_isolate";
    params.value = string;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getApManagementFramePowerControl(INT wlanIndex, INT *ManagementFramePowerControl)
{
   return RETURN_OK;
}

INT wifi_setApManagementFramePowerControl(INT wlanIndex, INT dBm)
{
   return RETURN_OK;
}
INT wifi_getRadioDcsChannelMetrics(INT radioIndex,wifi_channelMetrics_t *input_output_channelMetrics_array,INT size)
{
   return RETURN_OK;
}
INT wifi_setRadioDcsDwelltime(INT radioIndex, INT ms)
{
	return RETURN_OK;
}
INT wifi_getRadioDcsDwelltime(INT radioIndex, INT *ms)
{
	return RETURN_OK;
}
INT wifi_setRadioDcsScanning(INT radioIndex, BOOL enable)
{
	return RETURN_OK;
}
INT wifi_setBSSTransitionActivation(UINT apIndex, BOOL activate)
{
        return RETURN_OK;
}
wifi_apAuthEvent_callback apAuthEvent_cb = NULL;

void wifi_apAuthEvent_callback_register(wifi_apAuthEvent_callback callback_proc)
{
    return;
}

INT wifi_setApCsaDeauth(INT apIndex, INT mode)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_setApScanFilter(INT apIndex, INT mode, CHAR *essid)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_pushRadioChannel(INT radioIndex, UINT channel)
{
    // TODO Implement me!
    //Apply wifi_pushRadioChannel() instantly
    return RETURN_ERR;
}



INT wifi_setRadioStatsEnable(INT radioIndex, BOOL enable)
{
    // TODO Implement me!
    return RETURN_ERR;
}

#ifdef HAL_NETLINK_IMPL
static int tidStats_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1],*tidattr;
    int rem , tid_index = 0;

    wifi_associated_dev_tid_stats_t *out = (wifi_associated_dev_tid_stats_t*)arg;
    wifi_associated_dev_tid_entry_t *stats_entry;

    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
                 [NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED },
    };
    static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
                 [NL80211_TID_STATS_TX_MSDU] = { .type = NLA_U64 },
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);


    if (!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "station stats missing!\n");
        return NL_SKIP;
    }

    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                             tb[NL80211_ATTR_STA_INFO],
                             stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    nla_for_each_nested(tidattr, sinfo[NL80211_STA_INFO_TID_STATS], rem)
    {
        stats_entry = &out->tid_array[tid_index];

        stats_entry->tid = tid_index;
        stats_entry->ac = _tid_ac_index_get[tid_index];

        if(sinfo[NL80211_STA_INFO_TID_STATS])
        {
            if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,tidattr, tid_policy)) {
                printf("failed to parse nested stats attributes!");
                return;
            }
        }
        if(stats_info[NL80211_TID_STATS_TX_MSDU])
            stats_entry->num_msdus = (unsigned long long)nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);

        if(tid_index < (PS_MAX_TID - 1))
            tid_index++;
    }
    //ToDo: sum_time_ms, ewma_time_ms
    return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceTidStatsResult(INT radioIndex,  mac_address_t *clientMacAddress, wifi_associated_dev_tid_stats_t *tid_stats,  ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char  if_name[10];
    char mac_addr[MAC_ALEN];

    snprintf(if_name,sizeof(if_name),"wlan%d",radioIndex);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
              NL_AUTO_PORT,
              NL_AUTO_SEQ,
              nl.id,
              0,
              0,
              NL80211_CMD_GET_STATION,
              0);

    if(mac_addr_aton(mac_addr, clientMacAddress)) {
        printf("invalid mac address\n");
        return 0;
    }

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, mac_addr);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,tidStats_callback,tid_stats);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
//iw implementation
#define TID_STATS_FILE "/tmp/tid_stats_file.txt"
#define TOTAL_MAX_LINES 50

    char buf[256] = {'\0'}; /* or other suitable maximum line size */
    char if_name[10];
    FILE *fp=NULL;
    char pipeCmd[1024]= {'\0'};
    int lines,tid_index=0;
    char mac_addr[20] = {'\0'};

    wifi_associated_dev_tid_entry_t *stats_entry;

    snprintf(if_name,sizeof(if_name),"wlan%d",radioIndex);
    strcpy(mac_addr,clientMacAddress);

    snprintf(pipeCmd,sizeof(pipeCmd),"iw dev %s station dump -v > "TID_STATS_FILE,if_name);
    fp= popen(pipeCmd,"r");
    if(fp == NULL)
    {
        perror("popen for station dump failed\n");
        return RETURN_ERR;
    }

    snprintf(pipeCmd,sizeof(pipeCmd),"grep -n 'Station' "TID_STATS_FILE " | cut -d ':' -f1  | head -2 | tail -1");
    fp=popen(pipeCmd,"r");
    if(fp == NULL)
    {
        perror("popen for grep station failed\n");
        return RETURN_ERR;
    }
    else if(fgets(buf,sizeof(buf),fp) != NULL)
        lines=atoi(buf);
    else
    {
        fprintf(stderr,"No devices are connected \n");
        return RETURN_ERR;
    }

    if(lines == 1)
        lines = TOTAL_MAX_LINES; //only one client is connected , considering next MAX lines of iw output

    for(tid_index=0; tid_index<PS_MAX_TID; tid_index++)
    {
        stats_entry = &tid_stats->tid_array[tid_index];
        stats_entry->tid = tid_index;

        snprintf(pipeCmd, sizeof(pipeCmd),"cat "TID_STATS_FILE" | awk '/%s/ {for(i=0; i<=%d; i++) {getline; print}}'  |  grep -F -A%d 'MSDU'  | awk '{print $3}' | tail -1",mac_addr,lines,tid_index+2);

        fp=popen(pipeCmd,"r");

        if(fp ==NULL)
        {
            perror("Failed to read from tid file \n");
            return RETURN_ERR;
        }
        else if(fgets(buf,sizeof(buf),fp) != NULL)
            stats_entry->num_msdus = atol(buf);

        stats_entry->ac = _tid_ac_index_get[tid_index];
//      TODO:
//      ULLONG ewma_time_ms;    <! Moving average value based on last couple of transmitted msdus
//      ULLONG sum_time_ms; <! Delta of cumulative msdus times over interval
    }
    return RETURN_OK;
#endif
}


INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
    // TODO Implement me!
    return RETURN_ERR;
}


INT wifi_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientMeasure(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_eventUnregister(void)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_delApAclDevices(INT apINdex)
{
    // TODO Implement me!
    return RETURN_ERR;
}

//Code here, in rxStatsInfo_callback, txStatsInfo_callback and in chanSurveyInfo_callback originates from:
/*
Copyright (c) 2007, 2008	Johannes Berg
Copyright (c) 2007		Andy Lutomirski
Copyright (c) 2007		Mike Kershaw
Copyright (c) 2008-2009		Luis R. Rodriguez
Licensed under the ISC license
*/

#ifdef HAL_NETLINK_IMPL
static int rxStatsInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
    char mac_addr[20],dev[20];

    nla_parse(tb,
        NL80211_ATTR_MAX,
        genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0),
        NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }

    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }
    mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy )) {
        fprintf(stderr, "failed to parse nested rate attributes!");
        return;
    }

   if(sinfo[NL80211_STA_INFO_TID_STATS])
   {
       if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
           printf("failed to parse nested stats attributes!");
           return;
       }
   }

   if( nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]) )
   {
       printf("Type is VHT\n");
       if(rinfo[NL80211_RATE_INFO_VHT_NSS])
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = (char*)(nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]));

       if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 1;
       if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
             ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
             ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]) )
                         ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
  }
  else
  {
      printf(" OFDM or CCK \n");
      ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
      ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = 0;
  }

  if(sinfo[NL80211_STA_INFO_RX_BITRATE]) {
      if(rinfo[NL80211_RATE_INFO_MCS])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->mcs = (char*)(nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]));
      }
      if(sinfo[NL80211_STA_INFO_RX_BYTES64])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]);
      else if (sinfo[NL80211_STA_INFO_RX_BYTES])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);

      if(stats_info[NL80211_TID_STATS_RX_MSDU])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_RX_MSDU]);

      if (sinfo[NL80211_STA_INFO_SIGNAL])
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->rssi_combined = (char*)(nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]));
      //Assigning 0 for RETRIES ,PPDUS and MPDUS as we dont have rx retries attribute in libnl_3.3.0
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->retries = 0;
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->ppdus = 0;
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = 0;
      //rssi_array need to be filled
      return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_rx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char phy_addr[MAC_ALEN];
    char if_name[10];

    snprintf(if_name,sizeof(if_name),"wlan%d",radioIndex);
    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
    fprintf(stderr, "Error initializing netlink \n");
    return 0;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return 0;
    }

    genlmsg_put(msg,
        NL_AUTO_PORT,
        NL_AUTO_SEQ,
        nl.id,
        0,
        0,
        NL80211_CMD_GET_STATION,
        0);

    if (mac_addr_aton(phy_addr, clientMacAddress)) {
        printf("invalid mac address\n");
        return 0;
    }

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, phy_addr);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, rxStatsInfo_callback, stats_array);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
    //TODO Implement me
    return RETURN_OK;
#endif
}

#ifdef HAL_NETLINK_IMPL
static int txStatsInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
    char mac_addr[20],dev[20];

    nla_parse(tb,
              NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }

    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
        fprintf(stderr, "failed to parse nested rate attributes!");
        return;
    }

    if(sinfo[NL80211_STA_INFO_TID_STATS])
    {
        if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
            printf("failed to parse nested stats attributes!");
            return;
        }
    }
    if(nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]))
    {
        printf("Type is VHT\n");
        if(rinfo[NL80211_RATE_INFO_VHT_NSS])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = (char*)(nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]));

        if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 1;
        if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]))
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
    }
    else
    {
        printf(" OFDM or CCK \n");
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = 0;
    }

    if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
       if(rinfo[NL80211_RATE_INFO_MCS])
           ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mcs = (char*)(nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]));
    }

    if(sinfo[NL80211_STA_INFO_TX_BYTES64])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]);
    else if (sinfo[NL80211_STA_INFO_TX_BYTES])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);

    //Assigning  0 for mpdus and ppdus , as we do not have attributes in netlink
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;

    if(stats_info[NL80211_TID_STATS_TX_MSDU])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);

    if(sinfo[NL80211_STA_INFO_TX_RETRIES])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);

    if(sinfo[NL80211_STA_INFO_TX_FAILED])
                 ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->attempts = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]) + nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);

    return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char mac_addr[MAC_ALEN];
    char if_name[10];

    snprintf(if_name,sizeof(if_name),"wlan%d",radioIndex);

    nl.id = initSock80211(&nl);

    if(nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return 0;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if(!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return 0;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                0,
                NL80211_CMD_GET_STATION,
                0);

    if(mac_addr_aton(mac_addr, clientMacAddress)) {
        printf("invalid mac address\n");
        return 0;
    }
    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, mac_addr);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, txStatsInfo_callback, stats_array);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
    //TODO Implement me
    return RETURN_OK;
#endif
}

INT wifi_getBSSTransitionActivation(UINT apIndex, BOOL *activate)
{
    // TODO Implement me!
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file, "bss_transition", buf, 64);
    *activate = (strncmp("1",buf,1) == 0);

    return RETURN_OK;
}

INT wifi_setNeighborReportActivation(UINT apIndex, BOOL activate)
{
     char buf[MAX_BUF_SIZE] = {0};
     char cmd[MAX_CMD_SIZE] = {0};
     char config_file[MAX_BUF_SIZE] = {0};
     struct params list;

     list.name = "rrm_neighbor_report";
     list.value = activate?"1":"0";

     sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
     wifi_hostapdWrite(config_file, &list, 1);
     return RETURN_OK;

}

INT wifi_getNeighborReportActivation(UINT apIndex, BOOL *activate)
{
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file, "rrm_neighbor_report", buf, 64);
    *activate = (strncmp("1",buf,1) == 0);

    return RETURN_OK;

}
#ifdef HAL_NETLINK_IMPL
static int chanSurveyInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
    char dev[20];
    int freq =0 ;
    static int i=0;

    wifi_channelStats_t_loc *out = (wifi_channelStats_t_loc*)arg;

    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0), NULL);

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if (!tb[NL80211_ATTR_SURVEY_INFO]) {
        fprintf(stderr, "survey data missing!\n");
        return NL_SKIP;
    }

    if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,tb[NL80211_ATTR_SURVEY_INFO],survey_policy))
    {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }


    if(out[0].array_size == 1 )
    {
        if(sinfo[NL80211_SURVEY_INFO_IN_USE])
        {
	    if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
                freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
	    out[0].ch_number = ieee80211_frequency_to_channel(freq);

            if (sinfo[NL80211_SURVEY_INFO_NOISE])
	        out[0].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
                out[0].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
	        out[0].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
	        out[0].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
	        out[0].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
            if (sinfo[NL80211_SURVEY_INFO_TIME])
	        out[0].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
	    return NL_STOP;
        }
   }
   else
   {
       if ( i <=  out[0].array_size )
       {
           if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
               freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
           out[i].ch_number = ieee80211_frequency_to_channel(freq);

	   if (sinfo[NL80211_SURVEY_INFO_NOISE])
               out[i].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
	   if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
               out[i].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
               out[i].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
               out[i].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
               out[i].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
           if (sinfo[NL80211_SURVEY_INFO_TIME])
               out[i].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
      }
   }

   i++;
   return NL_SKIP;
}
#endif

INT wifi_getRadioChannelStats(INT radioIndex,wifi_channelStats_t *input_output_channelStats_array,INT array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    wifi_channelStats_t_loc local[array_size];
    char  if_name[10];

    local[0].array_size = array_size;

    snprintf(if_name,sizeof(if_name),"wlan%d",radioIndex);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                NLM_F_DUMP,
                NL80211_CMD_GET_SURVEY,
                0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_send_auto(nl.socket, msg);
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,chanSurveyInfo_callback,local);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    //Copying the Values
    for(int i=0;i<=array_size;i++)
    {
        input_output_channelStats_array[i].ch_number = local[i].ch_number;
        input_output_channelStats_array[i].ch_noise = local[i].ch_noise;
	input_output_channelStats_array[i].ch_utilization_busy_rx = local[i].ch_utilization_busy_rx;
	input_output_channelStats_array[i].ch_utilization_busy_tx = local[i].ch_utilization_busy_tx;
	input_output_channelStats_array[i].ch_utilization_busy = local[i].ch_utilization_busy;
	input_output_channelStats_array[i].ch_utilization_busy_ext = local[i].ch_utilization_busy_ext;
	input_output_channelStats_array[i].ch_utilization_total = local[i].ch_utilization_total;
	//TODO: ch_radar_noise, ch_max_80211_rssi, ch_non_80211_noise, ch_utilization_busy_self
    }
    return RETURN_OK;
#else
    FILE *fp = NULL;
    char HConf_file[MAX_BUF_SIZE] = {'\0'};
    char interface_name[50] = {0};
    char pipeCmd[MAX_CMD_SIZE] = {0};
    char str[MAX_BUF_SIZE] = {0};
    wifi_channelStats_t *out=NULL;
    int i=0;
    out = &input_output_channelStats_array[0];
    const char *StatsName[] = {"active time",
                                "busy time",
                                "receive time",
                                "transmit time",
                                "noise"  };

     sprintf(HConf_file,"%s%d%s","/nvram/hostapd",radioIndex,".conf");
     GetInterfaceName(interface_name,HConf_file);
     snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s survey dump > /tmp/Channel_Stats.txt", interface_name);
     system(pipeCmd);
     for(i=0;i<5;i++)
     {
         sprintf(pipeCmd,"%s%s%s","cat  /tmp/Channel_Stats.txt |tail | grep ",StatsName[i]," | cut -d ':' -f2  | tr -d '\t' | cut -d ' ' -f1");
         fp = popen(pipeCmd, "r");
         if(fp)
         {
             fgets(str, MAX_BUF_SIZE, fp);
             //Updating the channel status in Milli Seconds(ms), few informations such as ch_radar_noise,ch_max_80211_rssi,ch_utilization,ch_utilization_busy_self,ch_utilization_busy_ext need to be updated
             if(strcmp(StatsName[i],"active time") == 0)
                 out->ch_utilization_total = atol(str);
             else if(strcmp(StatsName[i],"busy time") == 0)
                 out->ch_utilization_busy = atol(str);
             else if(strcmp(StatsName[i],"receive time") == 0)
                 out->ch_utilization_busy_rx = atol(str);
             else if(strcmp(StatsName[i],"transmit time") == 0)
                 out->ch_utilization_busy_tx = atol(str);
             else if(strcmp(StatsName[i],"noise") == 0)
                 out->ch_non_80211_noise = atoi(str);
             else
                 printf("No Channel matches found");
         }
     }
     return RETURN_OK;
#endif
}

void wifi_apDisassociatedDevice_callback_register(wifi_apDisassociatedDevice_callback callback_proc)
{
    // TODO Implement me!
}


INT wifi_setBTMRequest(UINT apIndex, CHAR *peerMac, wifi_BTMRequest_t *request)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_setRMBeaconRequest(UINT apIndex, CHAR *peer, wifi_BeaconRequest_t *in_request, UCHAR *out_DialogToken)
{
    // TODO Implement me!
    return RETURN_ERR;
}

/*INT wifi_getRadioChannels(INT radioIndex, wifi_channelMap_t *outputMap, INT outputMapSize)
{
    // TODO Implement me!
    return RETURN_ERR;
}*/

/*INT wifi_chan_eventRegister(wifi_chan_eventCB_t eventCb)
{
    // TODO Implement me!
    return RETURN_ERR;
}*/

#ifdef _WIFI_HAL_TEST_
int main(int argc,char **argv)
{
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	int index;
	INT ret=0;
    if(argc <= 1) {
        printf("help\n");
        //fprintf(stderr,"%s", commands_help);

        exit(-1);
    } 

    if(strstr(argv[1], "init")!=NULL) {
        return wifi_init();
    }
    else if(strstr(argv[1], "reset")!=NULL) {
        return wifi_reset();
    }    
	
	index = atoi(argv[2]);
    if(strstr(argv[1],"wifi_getApAssociatedDeviceTidStatsResult")!=NULL)
    {
        printf("arguments are %s %s %s \n", argv[1],argv[2],argv[3]);
        if(argc < 3 )
        {
            printf("Insufficient arguments \n");
            exit(-1);
        }

        char sta[20] = {'\0'};
        u64 handle= 0;
        strcpy(sta,argv[3]);
        mac_address_t *st;
        st=sta;

        wifi_associated_dev_tid_stats_t tid_stats;
        wifi_getApAssociatedDeviceTidStatsResult(index,st,&tid_stats,handle);
        for(int tid_index=0; tid_index<PS_MAX_TID; tid_index++) //print tid stats
            printf(" tid=%d \t ac=%d \t num_msdus=%lld \n" ,tid_stats.tid_array[tid_index].tid,tid_stats.tid_array[tid_index].ac,tid_stats.tid_array[tid_index].num_msdus);
    }

    if(strstr(argv[1], "getApEnable")!=NULL) {
        BOOL enable;
		ret=wifi_getApEnable(index, &enable);
        printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
    }
    else if(strstr(argv[1], "setApEnable")!=NULL) {
        BOOL enable = atoi(argv[3]);
        ret=wifi_setApEnable(index, enable);
        printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
    }
    else if(strstr(argv[1], "getApStatus")!=NULL) {
        char status[64]; 
        ret=wifi_getApStatus(index, status);
        printf("%s %d: %s, returns %d\n", argv[1], index, status, ret);
    }
    else if(strstr(argv[1], "getSSIDTrafficStats2")!=NULL) {
		wifi_ssidTrafficStats2_t stats={0};
		ret=wifi_getSSIDTrafficStats2(index, &stats); //Tr181
		printf("%s %d: returns %d\n", argv[1], index, ret);
		printf("     ssid_BytesSent             =%lu\n", stats.ssid_BytesSent);
		printf("     ssid_BytesReceived         =%lu\n", stats.ssid_BytesReceived);
		printf("     ssid_PacketsSent           =%lu\n", stats.ssid_PacketsSent);
		printf("     ssid_PacketsReceived       =%lu\n", stats.ssid_PacketsReceived);
		printf("     ssid_RetransCount          =%lu\n", stats.ssid_RetransCount);
		printf("     ssid_FailedRetransCount    =%lu\n", stats.ssid_FailedRetransCount);
		printf("     ssid_RetryCount            =%lu\n", stats.ssid_RetryCount);
		printf("     ssid_MultipleRetryCount    =%lu\n", stats.ssid_MultipleRetryCount);
		printf("     ssid_ACKFailureCount       =%lu\n", stats.ssid_ACKFailureCount);
		printf("     ssid_AggregatedPacketCount =%lu\n", stats.ssid_AggregatedPacketCount);
		printf("     ssid_ErrorsSent            =%lu\n", stats.ssid_ErrorsSent);
		printf("     ssid_ErrorsReceived        =%lu\n", stats.ssid_ErrorsReceived);
		printf("     ssid_UnicastPacketsSent    =%lu\n", stats.ssid_UnicastPacketsSent);
		printf("     ssid_UnicastPacketsReceived    =%lu\n", stats.ssid_UnicastPacketsReceived);
		printf("     ssid_DiscardedPacketsSent      =%lu\n", stats.ssid_DiscardedPacketsSent);
		printf("     ssid_DiscardedPacketsReceived  =%lu\n", stats.ssid_DiscardedPacketsReceived);
		printf("     ssid_MulticastPacketsSent      =%lu\n", stats.ssid_MulticastPacketsSent);
		printf("     ssid_MulticastPacketsReceived  =%lu\n", stats.ssid_MulticastPacketsReceived);
		printf("     ssid_BroadcastPacketsSent      =%lu\n", stats.ssid_BroadcastPacketsSent);
		printf("     ssid_BroadcastPacketsRecevied  =%lu\n", stats.ssid_BroadcastPacketsRecevied);
		printf("     ssid_UnknownPacketsReceived    =%lu\n", stats.ssid_UnknownPacketsReceived);
	}
	else if(strstr(argv[1], "getNeighboringWiFiDiagnosticResult2")!=NULL) {
		wifi_neighbor_ap2_t *neighbor_ap_array=NULL, *pt=NULL;
		UINT array_size=0;
		UINT i=0;
		ret=wifi_getNeighboringWiFiDiagnosticResult2(index, &neighbor_ap_array, &array_size);
		printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
		for(i=0, pt=neighbor_ap_array; i<array_size; i++, pt++) {	
			printf("  neighbor %d:\n", i);
			printf("     ap_SSID                =%s\n", pt->ap_SSID);
			printf("     ap_BSSID               =%s\n", pt->ap_BSSID);
			printf("     ap_Mode                =%s\n", pt->ap_Mode);
			printf("     ap_Channel             =%d\n", pt->ap_Channel);
			printf("     ap_SignalStrength      =%d\n", pt->ap_SignalStrength);
			printf("     ap_SecurityModeEnabled =%s\n", pt->ap_SecurityModeEnabled);
			printf("     ap_EncryptionMode      =%s\n", pt->ap_EncryptionMode);
			printf("     ap_SupportedStandards  =%s\n", pt->ap_SupportedStandards);
			printf("     ap_OperatingStandards  =%s\n", pt->ap_OperatingStandards);
			printf("     ap_OperatingChannelBandwidth   =%s\n", pt->ap_OperatingChannelBandwidth);
			printf("     ap_SecurityModeEnabled         =%s\n", pt->ap_SecurityModeEnabled);
			printf("     ap_BeaconPeriod                =%d\n", pt->ap_BeaconPeriod);
			printf("     ap_Noise                       =%d\n", pt->ap_Noise);
			printf("     ap_BasicDataTransferRates      =%s\n", pt->ap_BasicDataTransferRates);
			printf("     ap_SupportedDataTransferRates  =%s\n", pt->ap_SupportedDataTransferRates);
			printf("     ap_DTIMPeriod                  =%d\n", pt->ap_DTIMPeriod);
			printf("     ap_ChannelUtilization          =%d\n", pt->ap_ChannelUtilization);			
		}
		if(neighbor_ap_array)
			free(neighbor_ap_array); //make sure to free the list
	}
	else if(strstr(argv[1], "getApAssociatedDeviceDiagnosticResult")!=NULL) {
		wifi_associated_dev_t *associated_dev_array=NULL, *pt=NULL;
		UINT array_size=0;
		UINT i=0;
		ret=wifi_getApAssociatedDeviceDiagnosticResult(index, &associated_dev_array, &array_size);
		printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
		for(i=0, pt=associated_dev_array; i<array_size; i++, pt++) {	
			printf("  associated_dev %d:\n", i);
			printf("     cli_OperatingStandard      =%s\n", pt->cli_OperatingStandard);
			printf("     cli_OperatingChannelBandwidth  =%s\n", pt->cli_OperatingChannelBandwidth);
			printf("     cli_SNR                    =%d\n", pt->cli_SNR);
			printf("     cli_InterferenceSources    =%s\n", pt->cli_InterferenceSources);
			printf("     cli_DataFramesSentAck      =%lu\n", pt->cli_DataFramesSentAck);
			printf("     cli_DataFramesSentNoAck    =%lu\n", pt->cli_DataFramesSentNoAck);
			printf("     cli_BytesSent              =%lu\n", pt->cli_BytesSent);
			printf("     cli_BytesReceived          =%lu\n", pt->cli_BytesReceived);
			printf("     cli_RSSI                   =%d\n", pt->cli_RSSI);
			printf("     cli_MinRSSI                =%d\n", pt->cli_MinRSSI);
			printf("     cli_MaxRSSI                =%d\n", pt->cli_MaxRSSI);
			printf("     cli_Disassociations        =%d\n", pt->cli_Disassociations);
			printf("     cli_AuthenticationFailures =%d\n", pt->cli_AuthenticationFailures);
		}
		if(associated_dev_array)
			free(associated_dev_array); //make sure to free the list
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return 0;
}


#endif
//<<

