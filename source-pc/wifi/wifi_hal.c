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

    module: wifi_hal.c

        For CCSP Component:  Wifi_Provisioning_and_management

    ---------------------------------------------------------------

    description:

        This sample implementation file gives the function call prototypes and 
        structure definitions used for the RDK-Broadband 
        Wifi hardware abstraction layer

     
    ---------------------------------------------------------------

    environment:

        This HAL layer is intended to support Wifi drivers 
        through an open API.  

    ---------------------------------------------------------------

    author:

        zhicheng_qiu@cable.comcast.com 

**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>
//#include <net/if.h>   //ifreq
#include <unistd.h>   //close
#include <linux/wireless.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <malloc.h>

#include "ccsp/ansc_platform.h"//LNT_EMU
#include "wifi_hal_emu.h"

#ifndef AP_PREFIX
#define AP_PREFIX	"ath"
#endif

#ifndef RADIO_PREFIX
#define RADIO_PREFIX	"wifi"
//#define RADIO_PREFIX	"wlan"
#endif

#define RADIO_24GHZ 0
#define RADIO_5GHZ  1

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

#define wifi_printf printf
#define MAX_APS 2
#define NULL_CHAR '\0'

//PSM Access-RDKB-EMU
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
//static char *BssSsid ="eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.SSID.%d.SSID";

static int MacFilter = 0 ;
static BOOL WPSSessionStarted = FALSE;
typedef unsigned char mac_address_t[6];


/**************************************************************************/
/*! \fn static INT list_add_param(param_list_t *list,struct params params)
 **************************************************************************
 *  \brief This function will add params in list and increment count
 *  \param[in] *list - pointer to list
 *  \param[in] param - parameter that we need to add in list
 *  \return (RETURN_OK/RETURN_ERR)
 **************************************************************************/
static INT list_add_param(param_list_t *list,struct params params)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(list->parameter_list==NULL)
    {

        if(list->parameter_list=(struct params *)calloc(1,(sizeof(struct params))))
        {
            list->count=1;
            memcpy(&(list->parameter_list[list->count-1]),&params,sizeof(params));
            wifi_dbg_printf("\n[%s]:inside calloc\n",__func__);
        }
        else
        {
            wifi_dbg_printf("\n[%s]:memmory allocation failed!!\n",__func__);
            return RETURN_ERR;
        }
    }
    else
    {
        if(list->parameter_list=(struct params *)realloc(list->parameter_list,((list->count +1) * sizeof(struct params))))
        {
            list->count = list->count + 1;
            memcpy(&(list->parameter_list[list->count-1]),&params,sizeof(params));
            wifi_dbg_printf("\n[%s]:inside realloc\n",__func__);
        }
        else
        {
            wifi_dbg_printf("\n[%s]:memmory allocation failed!!\n",__func__);
            return RETURN_ERR;
        }
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
   return RETURN_OK;
}

/**************************************************************************/
/*! \fn static void list_free_param(param_list_t *list)
 **************************************************************************
 *  \brief This function will free memory allocated by param list
 *  \param[in] *list - pointer to list
 *  \return none
 **************************************************************************/
static void list_free_param(param_list_t *list)
{
        if(list->parameter_list)
                free(list->parameter_list);
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

/* The type of encryption the neighboring WiFi SSID advertises.          */
/* Each list item is an enumeration of: TKIP, AES                        */
void wlan_encryption_mode_to_string(char* encryption_mode, char* string)
{
   WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
   /* Ensure string starts with null */
   string[0] = '\0';

   if (strstr(encryption_mode, "(none)") != NULL)
   {
      strcpy(string, "None");
   }
   else if (strstr(encryption_mode, "group_tkip") != NULL)
   {
      strcpy(string, "TKIP");
   }
   else if (strstr(encryption_mode, "group_ccmp") != NULL)
   {
      strcpy(string, "CCMP");
   }
   WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//open a file and read that line
INT File_Reading(CHAR *file,char *Value)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp = NULL;
        char buf[1024] = {0},copy_buf[512] ={0};
        int count = 0;
        fp = popen(file,"r");
        if(fp == NULL)
                return RETURN_ERR;
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

// convert wireless mode into supported standards
void wlan_wireless_mode_to_supported_standards_string(char* wireless_mode,char* string,char* freq)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    /* Ensure string starts with null */
   string[0] = '\0';

   if (strcmp(wireless_mode, "ac") == 0)
   {
      strcpy(string, "a,n,ac");
   }
   else if ((strcmp(wireless_mode, "n") == 0) && (strcmp(freq,"2.4GHz") == 0))
   {
      strcpy(string, "b,g,n");
   }
   else if (strcmp(wireless_mode, "bgn") == 0)
   {
      strcpy(string, "b,g,n");
   }
   else if ((strcmp(wireless_mode, "n") == 0) && (strcmp(freq,"5GHz") == 0))
   {
      strcpy(string, "a,n");
   }
   else if (strcmp(wireless_mode, "a") == 0)
   {
      strcpy(string, "a");
   }
   else if (strcmp(wireless_mode, "g") == 0)
   {
      strcpy(string, "b,g");
   }
   else if (strcmp(wireless_mode, "b") == 0)
   {
      strcpy(string, "b");
   }
   else if (strcmp(wireless_mode, "an") == 0)
   {
      strcpy(string, "a,n");
   }
   WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//convert wireless bitrates into operated standards
void wlan_bitrate_to_operated_standards_string(char* bitrate,char* string,char* freq)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	/* Ensure string starts with null */
        string[0] = '\0';
	
	ULONG rate = 0;
	rate = atol(bitrate);
	if(( rate == 54 ) && strcmp(freq,"2.4GHz") == 0)
	{
		strcpy(string,"g");
	}
	else if( rate == 11 )
	{
		strcpy(string,"b");
	}
	else if(( rate == 54 ) && strcmp(freq,"5GHz") == 0)
	{
		strcpy(string,"a");
	}
	else if(( rate >= 600 ) && (rate <= 900))
	{
		strcpy(string,"n");
	}
	else if(( rate >= 1200 ) && (rate <= 5300))
	{
		strcpy(string,"ac");
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}
//convert operated standards into operating channel bandwith
void wlan_operated_standards_to_channel_bandwidth_string(char* wireless_mode,char* string)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        /* Ensure string starts with null */
        string[0] = '\0';

        if((strcmp(wireless_mode,"a") == 0) || strcmp(wireless_mode,"g") == 0)
        {
                strcpy(string,"20MHz");
        }
        else if(strcmp(wireless_mode,"n") == 0)
        {
                strcpy(string,"40MHz");
        }
        else if(strcmp(wireless_mode,"ac") == 0)
        {
                strcpy(string,"20/40/80MHz");
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}


/****************************************************************************
		Xfinity-wifi and Private-wifi (2.4Ghz) Function Definitions
*****************************************************************************/

/***************************************************************
	Checking Hostapd status(whether it's running or not)
****************************************************************/

/*
* 	Procedure	: Checking Hostapd status(whether it's running or not)
*	Purpose		: Restart the Hostapd with updated configuration parameter
*	Parameter	:
*	 status		: Having Hostapd status
* 	Return_values	: None
*/

//Get to know the current status of public wifi
INT Hostapd_PublicWifi_status(char status[50])
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp;
        char path[256];
        int count;
        fp = popen("ifconfig wlan0_0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4 > /tmp/public_wifi_status.txt","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return ;
        }
        pclose(fp);
        fp = popen("cat /tmp/public_wifi_status.txt","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return RETURN_ERR;
        }
        if(fgets(path, sizeof(path)-1, fp) != NULL)
        {
        for(count=0;path[count]!='\n';count++)
                status[count]=path[count];
        status[count]='\0';
        }
        else
        {
        status[0] = '\0';
        }
        printf("current XfinityWifi status %s \n",status);
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get to know the current status of private wifi
INT Hostapd_PrivateWifi_status(char status[50])
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp;
        char path[256];
        int count;
        fp = popen("ifconfig wlan0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4 > /tmp/private_wifi_status.txt","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return ;
        }
        pclose(fp);
        fp = popen("cat /tmp/private_wifi_status.txt","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return RETURN_ERR;
        }
        if(fgets(path, sizeof(path)-1, fp) != NULL)
        {
        for(count=0;path[count]!='\n';count++)
                status[count]=path[count];
        status[count]='\0';
        }
        else
        {
        status[0] = '\0';
        }
        printf("current PrivateWifi status %s \n",status);
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

/*******************************************************************
	    Restarting Hostapd with new configuration
********************************************************************/

//passing the hostapd configuration file and get the interface name
INT GetInterfaceName(char interface_name[50],char conf_file[100])
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
        char path[MAX_BUF_SIZE] = {0},output_string[MAX_BUF_SIZE] = {0},fname[MAX_BUF_SIZE] = {0};
        int count = 0;
        char *interface = NULL;
        sprintf(fname,"%s%s%s","cat ",conf_file," | grep interface=");
        fp = popen(fname,"r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return RETURN_ERR;
        }
        if(fgets(path, sizeof(path)-1, fp) != NULL)
        {
                interface = strchr(path,'=');
                strcpy(output_string,interface+1);
        }
        for(count = 0;output_string[count]!='\n';count++)
                interface_name[count] = output_string[count];
        interface_name[count]='\0';
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//passing the hostapd configuration file and get the virtual interface of xfinity(2g)
INT GetInterfaceName_virtualInterfaceName_2G(char interface_name[50])
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp;
        char path[256] = {0},output_string[256] = {0};
        int count = 0;
        char *interface;
       	fp = popen("cat /nvram/hostapd0.conf | grep -w bss","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return RETURN_ERR;
        }
        if(fgets(path, sizeof(path)-1, fp) != NULL)
        {
                interface = strchr(path,'=');
                strcpy(output_string,interface+1);
        }
	for(count = 0;output_string[count]!='\n';count++)
                interface_name[count] = output_string[count];
        interface_name[count]='\0';
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Restarting the hostapd process
void RestartHostapd()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512];
	char virtual_interface_name[512],buf[512];
	GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"up");
	system(buf);
        //system("ifconfig wlan0 up");
        system("ps -eaf | grep hostapd0 | grep -v grep | awk '{print $2}' | xargs kill -9");
        system("hostapd -B /nvram/hostapd0.conf");
	sprintf(buf,"%s%s %s","ifconfig mon.",interface_name,"up");
	system(buf);
        //system("ifconfig mon.wlan0 up");
	sprintf(buf,"%s %s %s","ifconfig",virtual_interface_name,"up");
	system(buf);
        //system("ifconfig wlan0_0 up");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//kill the existing hostapd process
void KillHostapd()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512];
        char virtual_interface_name[512],buf[512];
        GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
        GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
	sprintf(buf,"%s%s %s","ifconfig mon.",interface_name,"down");
        system(buf);
       // system("ifconfig mon.wlan0 down");
        system("ps -eaf | grep hostapd0 | grep -v grep | awk '{print $2}' | xargs kill -9");
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        system(buf);

       // system("ifconfig wlan0 down");
	sprintf(buf,"%s %s %s","ifconfig",virtual_interface_name,"down");
        system(buf);
        //system("ifconfig wlan0_0 down");
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"up");
        system(buf);
        //system("ifconfig wlan0 up");
        system("hostapd -B /nvram/hostapd0.conf");
	sprintf(buf,"%s%s %s","ifconfig mon.",interface_name,"up");
        system(buf);
        //system("ifconfig mon.wlan0 up");
	sprintf(buf,"%s %s %s","ifconfig",virtual_interface_name,"up");
        system(buf);
        //system("ifconfig wlan0_0 up");
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"up");
        system(buf);

        //system("ifconfig wlan0 up");
        system("ps -eaf | grep hostapd0 | grep -v grep | awk '{print $2}' | xargs kill -9");
        system("hostapd -B /nvram/hostapd0.conf");
	sprintf(buf,"%s%s %s","ifconfig mon.",interface_name,"up");
        system(buf);
        //system("ifconfig mon.wlan0 up");
	sprintf(buf,"%s %s %s","ifconfig",virtual_interface_name,"up");
        system(buf);
	sleep(5);
        //system("ifconfig wlan0_0 up");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Restart the xfinity wifi of 2g
void xfinitywifi_2g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	bool ssidEnable = 0;
	wifi_getSSIDEnable(ssidIndex,&ssidEnable);	
	if(ssidEnable == TRUE)
	        system("hostapd -B /nvram/hostapd4.conf");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Restart the private wifi of 2g
void privatewifi_2g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	bool ssidEnable = 0;
        wifi_getSSIDEnable(ssidIndex,&ssidEnable); 
        if(ssidEnable == TRUE) 
	        system("hostapd -B /nvram/hostapd0.conf");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Restart the xfinity and private wifi of 2g
void KillHostapd_2g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512],buf[512];
        GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
        system("ps -eaf | grep hostapd0.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
        system("sleep 2");
        system("ps -eaf | grep hostapd4.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
        system("rmmod rtl8812au");
        system("sleep 3");
        system("modprobe rtl8812au");
        system("sleep 5");
	sprintf(buf,"%s%s","rm /var/run/hostapd/",interface_name);
	system(buf);
        sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        system(buf);
        system("sleep 3");
        sprintf(buf,"%s %s %s","ifconfig",interface_name,"up");
        system(buf);
        system("hostapd -B /nvram/hostapd0.conf");
        sleep(2);
        xfinitywifi_2g(4);
        sleep(2);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

}
//Restart the xfinity and private wifi of 2g
void KillHostapd_xfinity_2g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512],buf[512];
        GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
        system("ps -eaf | grep hostapd4.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
        system("sleep 2");
        system("ps -eaf | grep hostapd0.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
        system("rmmod rtl8812au");
        system("sleep 3");
        system("modprobe rtl8812au");
        system("sleep 5");
	sprintf(buf,"%s%s","rm /var/run/hostapd/",interface_name);
	system(buf);
        sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        system(buf);
        system("sleep 3");
        sprintf(buf,"%s %s %s","ifconfig",interface_name,"up");
        system(buf);
        system("hostapd -B /nvram/hostapd4.conf");
        sleep(2);
        privatewifi_2g(0);
        sleep(2);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Restart the xfinity wifi of 5g
void xfinitywifi_5g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	bool ssidEnable = 0;
        wifi_getSSIDEnable(ssidIndex,&ssidEnable);
        if(ssidEnable == TRUE) 
		system("hostapd -B /nvram/hostapd5.conf");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Restart the private wifi of 5g
void privatewifi_5g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	bool ssidEnable = 0;
        wifi_getSSIDEnable(ssidIndex,&ssidEnable);
        if(ssidEnable == TRUE) 
		system("hostapd -B /nvram/hostapd1.conf");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Restart the xfinity and private wifi of 5g
void KillHostapd_5g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512],buf[512];
        GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
	system("ps -eaf | grep hostapd1.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
	system("sleep 2");
	system("ps -eaf | grep hostapd5.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
	system("rmmod rtl8812au");
	system("sleep 3");
	system("modprobe rtl8812au");
	system("sleep 5");
	sprintf(buf,"%s%s","rm /var/run/hostapd/",interface_name);
	system(buf);
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        system(buf);
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"up");
        system(buf);
        system("hostapd -B /nvram/hostapd1.conf");
	sleep(2);
	xfinitywifi_5g(5);
	sleep(2);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Restart the xfinity and private wifi of 5g
void KillHostapd_xfinity_5g(int ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512],buf[512];
        GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
	system("ps -eaf | grep hostapd5.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
	system("sleep 2");
	system("ps -eaf | grep hostapd1.conf | grep -v grep | awk '{print $2}' | xargs kill -9");
	system("rmmod rtl8812au");
	system("sleep 3");
	system("modprobe rtl8812au");
	system("sleep 5");
	sprintf(buf,"%s%s","rm /var/run/hostapd/",interface_name);
	system(buf);
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        system(buf);
        system("sleep 3");
	sprintf(buf,"%s %s %s","ifconfig",interface_name,"up");
        system(buf);
        system("hostapd -B /nvram/hostapd5.conf");
	sleep(2);
	privatewifi_5g(1);
	sleep(2);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Kill the existing xfinity wifi set up
INT killXfinityWiFi()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512];
        char virtual_interface_name[512];
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
        GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
	sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
        if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
        {
                return RETURN_ERR;
        }
	if(buf[0] == '#')
		GetInterfaceName(virtual_interface_name,"/nvram/hostapd4.conf");
	else
	        GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
        system("killall CcspHotspot");
        system("killall hotspot_arpd");
        system("brctl delif brlan1 gretap0.100");
	sprintf(buf,"%s %s","brctl delif brlan1",virtual_interface_name);
	system(buf);
        //system("brctl delif brlan1 wlan0_0");
        system("ifconfig brlan1 down");
        system("brctl delbr brlan1");
	system("vconfig rem gretap0.100");
        system("brctl delif brlan2 gretap0.101");
	sprintf(buf,"%s %s","brctl delif brlan2",interface_name);
	system(buf);
        //system("brctl delif brlan2 wlan2");
        system("ifconfig brlan2 down");
        system("brctl delbr brlan2");
	system("vconfig rem gretap0.101");
        system("ip link del gretap0");
        system("iptables -D FORWARD -j general_forward");
        system("iptables -D OUTPUT -j general_output");
        system("iptables -F general_forward");
        system("iptables -F general_output");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;

}

//Restarting the hostapd process with Factory_Reset set up
void defaultwifi_restarting_process()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char wireless_count[20] = {0};
	int wireless_interface_count = 0;
	File_Reading("cat /tmp/wireless_interface_count",wireless_count);
	wireless_interface_count = atoi(wireless_count);
	/* **************** TP-Link ************** */
	if(wireless_interface_count == 2)
		KillHostapd_5g(1);
	else if(wireless_interface_count == 4)
	{
		system("killall hostapd");
		sleep(1);
		system("rmmod rtl8812au");
		sleep(1);
		system("modprobe rtl8812au");
		sleep(1);
		privatewifi_5g(1);
		privatewifi_2g(0);
		xfinitywifi_2g(4);
		xfinitywifi_5g(5);
	}
	/* **************** Tenda ************** */
	else if(wireless_interface_count == 3)
	{
		system("sh /lib/rdk/start_hostapd.sh");
		KillHostapd_5g(1);
	}
	else if(wireless_interface_count == 1)
	{
		system("sh /lib/rdk/start_hostapd.sh");
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

// Restarting the hostapd process with dongle identification(Tenda/Tp-link)
int hostapd_restarting_process(int apIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char wireless_count[20] = {0};
	char interface[MAX_BUF_SIZE] = {0};
	int wireless_interface_count = 0;
	char dependant_interface[10] = {0};
	sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
	if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
	{
		return RETURN_ERR;
	}
	File_Reading("cat /tmp/wireless_interface_count",wireless_count);
	wireless_interface_count = atoi(wireless_count);
	if(buf[0] == '#')
	{
		/* **************** TP-Link ************** */
		if(wireless_interface_count == 2)
		{
			/*** private wifi and xfinity-wifi for 5g ***/		
			if(apIndex == 1)
			{		
				KillHostapd_5g(apIndex);
			}
			else if(apIndex == 5)
			{
				KillHostapd_xfinity_5g(apIndex);
			}
		}
		else if(wireless_interface_count == 4)
		{
			system("killall hostapd");
			sleep(1);
			system("rmmod rtl8812au");
			sleep(1);
			system("modprobe rtl8812au");
			sleep(1);
			privatewifi_5g(1);
			privatewifi_2g(0);
			xfinitywifi_2g(4);
			xfinitywifi_5g(5);
		}

	}
	else
	{
		/* ***************** Tenda **************** */
		if((apIndex == 0) || (apIndex == 4))
		{
			system("sh /lib/rdk/start_hostapd.sh");
		}
		else if(apIndex == 1)
		{
			KillHostapd_5g(apIndex);
		}
		else if(apIndex == 5)
		{
			KillHostapd_xfinity_5g(apIndex);
		}

	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//get the mac address of wan interface
void get_mac(unsigned char *mac)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    int fd;
    struct ifreq ifr;
    char *iface = "eth0";
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Check the hostapd status
BOOL checkWifi()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        //check hostapd is running
        FILE *fp = NULL;
        char path[FILE_SIZE];
        int count = 0;
        fp = popen ("ps -eaf | grep hostapd | grep -v grep | wc -l","r");
        if(fp == NULL)
                return ;
        fgets(path,FILE_SIZE,fp);
        count = atoi ( path );
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        if( count)
        {
                return true;
        }
        else
        {
                return false;
        }
}

//check the wireless interface status
BOOL checkLanInterface()
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp = NULL;
        fp = popen("ifconfig | grep wlan | wc -l", "r");
        char path[FILE_SIZE];
        int count;
        if(fp == NULL)
                return 0;
        fgets(path,FILE_SIZE,fp);
        count = atoi ( path );
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        if( count)
        {
                return true;
        }
        else
        {
                return false;
        }
}

//Get the ssid name from hostapd configuration file
INT GettingHostapdSsid(INT ssidIndex,char *hostapd_conf,char *val)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
	int count = 0;
	char *ssid_val = NULL;
	char path[256] = {0},fname[256] = {0},output[128] = {0};
	sprintf(fname,"%s%s%s","cat ",hostapd_conf," | grep -w ssid");
	fp = popen(fname,"r");
	if (fp == NULL) {
		printf("Failed to run command inside function %s\n",__FUNCTION__);
		return RETURN_ERR;
	}
	if(ssidIndex == 4)
	{
		while(fgets(path, sizeof(path)-1, fp)!=NULL)
		{
			ssid_val = strchr(path,'=');
			strcpy(output,ssid_val+1);
		}

	}
	else
	{
		/* Read the output a line at a time - output it. */
		fgets(path, sizeof(path)-1, fp);
		ssid_val = strchr(path,'=');
		strcpy(output,ssid_val+1);
	}
	for(count=0;output[count]!='\n';count++)
		val[count]=output[count];
	val[count]='\0';
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Disable wifi interface 
void DisableWifi(int InstanceNumber)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512];
        char virtual_interface_name[512];
	char buf[MAX_BUF_SIZE] = {0},cmd[MAX_CMD_SIZE] = {0};

        if(InstanceNumber == 0)
        {
        	GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        }
        else if(InstanceNumber == 1)
        {
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
                sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        }
        else if(InstanceNumber == 4)
	{
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return;
		}
		if(buf[0] == '#')
			GetInterfaceName(virtual_interface_name,"/nvram/hostapd4.conf");
		else
			GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
		sprintf(buf,"%s %s %s","ifconfig",virtual_interface_name,"down");
	}
        else if(InstanceNumber == 5)
        {
		GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
                sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
        }
        system(buf);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

INT CcspHal_change_config_value(char *field_name, char *field_value, char *buf, unsigned int *nbytes)
{
        int found=0, old_value_length, adjustment_bytes, count=0;
        char *p, *buf_base = buf, *value_start_pos;
        while(*buf)
        {
                for(;*buf&&(*buf=='\t'||*buf=='\n'||*buf==SPACE);buf++);
                p = field_name;
                for(;*buf&&*p&&!(*buf^*p); p++, buf++);
                if(!*p)
                {
                        found = 1;
                        for(;*buf&&(*buf=='\t'||*buf=='\n'||*buf==SPACE);buf++);
                        printf("buf:%s\n", buf);
                        for(old_value_length=0;*buf&&*buf^NEW_LINE;buf++) old_value_length++;
                        break;
                }
                else
                {
                        for(;*buf&&*buf^NEW_LINE;buf++);
                        buf++;//going past \n
                }
        }

        if (!found)
        {
                printf("Invalid field name\n");
                return -1;
        }
        //KEEPING NOTE OF POSITION WHERE VALUE HAS TO BE CHANGED
        value_start_pos = buf-old_value_length;
        //FOR BUFFER ADJUSTMENTS
        adjustment_bytes = strlen(field_value)-old_value_length;// bytes to be adjusted either way
        *nbytes += adjustment_bytes;

        if(adjustment_bytes<0)
        {//shifting buffer content to left
                for(;*buf;buf++)*(buf+adjustment_bytes) = *buf;
        }
        if(adjustment_bytes>0)
        {//shifting buffer content to right
                p = buf;
                for(;*buf;++buf);
                buf--;//moving back to last character
                for(;buf>=p;buf--)*(buf+adjustment_bytes) = *buf;
        }

        while(*field_value)
        {
                *value_start_pos++ = *field_value++;

        } //replacing old value with new value.
return 0;
}


int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    FILE *f;
    char *ptr = retBuf;
	int bufSize=retBufSize, bufbytes=0, readbytes=0;

    if((f = popen(cmd, "r")) == NULL) {
        printf("popen %s error\n", cmd);
        return -1;
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
    return 0;
}

// Read the hostapd configuration file with corresponding parameters
int wifi_hostapdRead(int ap,struct params *params,char *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char file_name[20];
    char cmd[MAX_CMD_SIZE]={'\0'};
    char buf[MAX_BUF_SIZE]={'\0'};
    char *ch;
    char *position;
        printf("\n Params Name is %s\n",params->name);
    if(strcmp(params->name, "beaconType") == 0)
    {
        sprintf(cmd,"grep 'AP_SECMODE%d' %s",ap,SEC_FNAME);
        printf("\ncmd=%s\n",cmd);
    }
    else
    {
        sprintf(file_name,"%s%d.conf",HOSTAPD_FNAME,ap);
        sprintf(cmd,"grep '%s=' %s",params->name,file_name);
    }
    if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
    {
        wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }
    if (buf[0] == NULL_CHAR)
        return RETURN_ERR;
    position = buf;
    while(*position != NULL_CHAR)
    {
        if (*position == NEW_LINE)
        {
            *position = NULL_CHAR;
            break;
        }
        position++;
    }
    position = strchr(buf, '=');
    if (position == NULL)
    {
        wifi_dbg_printf("Line %d: invalid line '%s'",__LINE__, buf);
        return RETURN_ERR;
    }
    *position = NULL_CHAR;
    position++;
    strncpy(output,position,strlen(position)+1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

//Write the hosatpd configuration with corresponding parameters
int wifi_hostapdWrite(int ap,param_list_t *list)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char cmd[MAX_CMD_SIZE];
        char wpa_val[2];
        char cur_val[127]={'\0'};
        char buf[MAX_BUF_SIZE];
        int loop_ctr=0;
        char IfName[MAX_BUF_SIZE] = {0};
        char ssid_cur_value[50] = {0};
        for(loop_ctr=0;loop_ctr<list->count;loop_ctr++)
        {
                memset(cur_val,'\0',sizeof(cur_val));
                if(strncmp(list->parameter_list[loop_ctr].name,"beaconType",strlen("beaconType")) ==0 )
                {
                        wifi_dbg_printf("\nparams name is BeaconType params value is %s \n",list->parameter_list[loop_ctr].value);
                        if((strcmp(list->parameter_list[loop_ctr].value,"WPAand11i")==0))
                                strcpy(wpa_val,"3");
                        else if((strcmp(list->parameter_list[loop_ctr].value,"11i")==0))
                                strcpy(wpa_val,"2");
                        else if((strcmp(list->parameter_list[loop_ctr].value,"WPA")==0))
                                strcpy(wpa_val,"1");

                        wifi_hostapdRead(ap,&(list->parameter_list[loop_ctr]),cur_val);

                        if(ap==0)
                                strncpy(list->parameter_list[loop_ctr].name,"AP_SECMODE0",strlen("AP_SECMODE0")+1);
                        else if(ap==1)
                                strncpy(list->parameter_list[loop_ctr].name,"AP_SECMODE1",strlen("AP_SECMODE1")+1);
                        else
                        {
                                wifi_dbg_printf("\n%s %d Invalid AP\n",__func__,__LINE__);
                                return RETURN_ERR;
                        }

                        sprintf(cmd,"sed -i 's/%s=%s/%s=%s/g' %s",list->parameter_list[loop_ctr].name,cur_val,list->parameter_list[loop_ctr].name,list->parameter_list[loop_ctr].value,SEC_FNAME);
                        wifi_dbg_printf("\n%s cur_val for secfile=%s cmd=%s",__func__,cur_val,cmd);
                        _syscmd(cmd,buf,sizeof(buf));

                        memset(list->parameter_list[loop_ctr].name,'\0',sizeof(list->parameter_list[loop_ctr].name));
                        memset(list->parameter_list[loop_ctr].value,'\0',sizeof(list->parameter_list[loop_ctr].value));
                        memset(cur_val,'\0',sizeof(cur_val));
                        strncpy(list->parameter_list[loop_ctr].name,"wpa",strlen("wpa"));
                        strncpy(list->parameter_list[loop_ctr].value,wpa_val,strlen(wpa_val));

                        /* If new security mode value for param "wpa" is '3' then set it to '2'.
                           Security mode '3' is supposed to support both WPA-Personal and WPA2-personal
                           but it is supporting only WPA-Personal and not to WPA2-Personal for security
                           mode setting '3'.
                         */
    /*                  if( ('3' == wpa_val[0]) && ( wifi_getApIndexForWiFiBand(band_2_4) == ap) )
                        {
                                wifi_dbg_printf("\n Current value of param wpa is 3, setting it to 2.\n");
                                strcpy(list->parameter_list[loop_ctr].value, "2");
                        }*/
			 wifi_hostapdRead(ap,&(list->parameter_list[loop_ctr]),cur_val);
                        sprintf(cmd,"sed -i 's/%s=%s/%s=%s/g' %s%d.conf",list->parameter_list[loop_ctr].name,cur_val,list->parameter_list[loop_ctr].name,list->parameter_list[loop_ctr].value,HOSTAPD_FNAME,ap);
                        printf("\ncur_val for wpa=%s wpa_val=%s\ncmd=%s\n",cur_val,wpa_val,cmd);
                        _syscmd(cmd,buf,sizeof(buf));
                }
                else if(strncmp(list->parameter_list[loop_ctr].name,"ht_capab",strlen("ht_capab")) ==0 )
                {
                        memset(cmd,'\0',sizeof(cmd));
                        sprintf(cmd,"sed -i 's/%s.*$/%s=%s/' %s%d.conf",list->parameter_list[loop_ctr].name,list->parameter_list[loop_ctr].name,list->parameter_list[loop_ctr].value,HOSTAPD_FNAME,ap);
                        _syscmd(cmd,buf,sizeof(buf));

                }
                else
                {
                        wifi_hostapdRead(ap,&(list->parameter_list[loop_ctr]),cur_val);
                        printf("\ncur_value=%s\n",cur_val);
                        memset(cmd,'\0',sizeof(cmd));
                        sprintf(cmd,"sed -i 's/%s=%s/%s=%s/g' %s%d.conf",list->parameter_list[loop_ctr].name,cur_val,list->parameter_list[loop_ctr].name,list->parameter_list[loop_ctr].value,HOSTAPD_FNAME,ap);
                        _syscmd(cmd,buf,sizeof(buf));
                        wifi_dbg_printf("\ncmdsss=%s\n",cmd);
                }
        }
	hostapd_restarting_process(ap);//Restarting the hostapd process
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}	


void wifi_apAuthEvent_callback_register(wifi_apAuthEvent_callback callback_proc)
{
    return;
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//TODO: clears internal variables to implement a factory reset of the Wi-Fi subsystem
	char cmd[128] = {0};
	/*delete running hostapd conf files*/
        wifi_dbg_printf("\n[%s]: deleting hostapd conf file %s and %s",__func__,HOSTAPD_CONF_0,HOSTAPD_CONF_1);
        sprintf(cmd, "rm -rf %s %s",HOSTAPD_CONF_0,HOSTAPD_CONF_1);
        system(cmd);
        /*create new configuraion file from default configuration*/
        if(RETURN_ERR == prepare_hostapd_conf())
        {
                return RETURN_ERR;
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
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
	//TODO:Restore all radio parameters without touch access point parameters
	return RETURN_OK;
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
	//TODO:Restore selected radio parameters without touch access point parameters
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

// Initializes the wifi subsystem (all radios)
INT wifi_init()                            //RDKB
{
	//TODO: Initializes the wifi subsystem
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	int hostapd_count = 0;
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	/* preparing hostapd configuration*/
        if(RETURN_ERR == prepare_hostapd_conf())
        {
                return RETURN_ERR;
        }
	sprintf(cmd,"%s","ps -eaf | grep hostapd | grep -v grep | wc -l");
	_syscmd(cmd,buf,sizeof(buf));	
	hostapd_count = atoi(buf);
	if(hostapd_count > 0)
	{
		printf("hostapd service is already running \n");
	}
	else
	{
		system("systemctl start hostapd.service");
	        sleep(10);//sleep to wait for hostapd to start
	}
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
	//TODO: creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)a
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
	else
		*output=2;
	return RETURN_OK;
}

//Get the total number of SSID entries in this wifi subsystem 
INT wifi_getSSIDNumberOfEntries(ULONG *output) //Tr181
{
	if (NULL == output)
		return RETURN_ERR;
	else
	//	*output=16; //RDKB-EMU
		*output=6;
	return RETURN_OK;
}

//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)      //RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);	
	char cmd[MAX_CMD_SIZE]={'\0'};
        char buf[MAX_BUF_SIZE]={'\0'};
        char HConf_file[MAX_BUF_SIZE]={'\0'};
        char IfName[MAX_BUF_SIZE]={'\0'};
        char path[MAX_BUF_SIZE]={'\0'};
        char tmp_status[MAX_BUF_SIZE]={'\0'};
        int count = 0;
        FILE *fp = NULL;
	if(radioIndex < 0)
		return RETURN_ERR;
        if((radioIndex == 0) || (radioIndex == 1))
        {
                sprintf(HConf_file,"%s%d%s","/nvram/hostapd",radioIndex,".conf");
                GetInterfaceName(IfName,HConf_file);
                if (NULL == output_bool)
                {
                        return RETURN_ERR;
                } else {
                        sprintf(cmd,"%s%s%s","ifconfig ",IfName," | grep RUNNING | tr -s ' ' | cut -d ' ' -f4");
                        _syscmd(cmd,buf,sizeof(buf));
                        if(strlen(buf)>0)
                                *output_bool=1;
                        else
                        {
                                if(radioIndex == 0)
                                        fp = fopen("/tmp/Get2gRadioEnable.txt","r");
                                else if(radioIndex == 1)
                                        fp = fopen("/tmp/Get5gRadioEnable.txt","r");
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

                        }
                        return RETURN_OK;
                }
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
#if 0
//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)	//RDKB
{
	if (NULL == output_bool) 
		return RETURN_ERR;
	/*} else {
		*output_bool = FALSE;
		return RETURN_OK;
	}*/ //RDKB-EMU
	FILE *fp=NULL;
        char path[256] = {0},status[256] = {0},tmp_status[256] = {0},interface_name[100] = {0};
        int count;
        if(radioIndex == 0)
        {
		GetInterfaceName(interface_name,"/etc/hostapd_2.4G.conf");
		if(strcmp(interface_name,"wlan0") == 0)
                	fp = popen("ifconfig wlan0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan1") == 0)
                	fp = popen("ifconfig wlan1 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan2") == 0)
                	fp = popen("ifconfig wlan2 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
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
                pclose(fp);
        }
	else if(radioIndex == 1)
        {
		GetInterfaceName(interface_name,"/etc/hostapd_5G.conf");
		if(strcmp(interface_name,"wlan0") == 0)
                	fp = popen("ifconfig wlan0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan1") == 0)
                	fp = popen("ifconfig wlan1 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan2") == 0)
                	fp = popen("ifconfig wlan2 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
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
                pclose(fp);
        }

        else if(radioIndex == 4)
        {
		GetInterfaceName_virtualInterfaceName_2G(interface_name);
		if(strcmp(interface_name,"wlan0_0") == 0)
                	fp = popen("ifconfig wlan0_0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan1_0") == 0)
                	fp = popen("ifconfig wlan1_0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan2_0") == 0)
                	fp = popen("ifconfig wlan2_0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
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
                pclose(fp);
        }
	else if(radioIndex == 5)
        {
		GetInterfaceName(interface_name,"/etc/hostapd_xfinity_5G.conf");
		if(strcmp(interface_name,"wlan0") == 0)
                	fp = popen("ifconfig wlan0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan1") == 0)
                	fp = popen("ifconfig wlan1 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		else if(strcmp(interface_name,"wlan2") == 0)
                	fp = popen("ifconfig wlan2 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
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
                pclose(fp);
        }

        if(strcmp(status,"RUNNING") == 0)
                *output_bool = TRUE;
        else
	{
		if((radioIndex == 4) || (radioIndex == 5))
		{
                        *output_bool = FALSE;
			return 0;
		}
                else if(radioIndex == 0)
                        fp = fopen("/tmp/Get2gRadioEnable.txt","r");
                else if(radioIndex == 1)
                        fp = fopen("/tmp/Get5gRadioEnable.txt","r");
                if(fp == NULL)
		{
                        *output_bool = FALSE;
			return 0;
		}
                if(fgets(path, sizeof(path)-1, fp) != NULL)
                {
                        for(count=0;path[count]!='\n';count++)
                                tmp_status[count]=path[count];
                        tmp_status[count]='\0';
                }
                fclose(fp);
                if(strcmp(tmp_status,"0") == 0)
                        *output_bool = FALSE;
                else
                        *output_bool = TRUE;
	}
	return RETURN_OK;
}
#endif
#if 0
//Set the Radio enable config parameter
INT wifi_setRadioEnable(INT radioIndex, BOOL enable)		//RDKB
{
	//Set wifi config. Wait for wifi reset to apply
	//RDKB-EMU
	char interface_name[512] = {0};
        char virtual_interface_name[512] = {0},buf[512] = {0},command[512] = {0};
	BOOL GetssidEnable;
	
	wifi_getSSIDEnable(radioIndex,&GetssidEnable);
        if(radioIndex == 0)
        {
                sprintf(buf,"%s%d%s","echo ",GetssidEnable," > /tmp/Get2gssidEnable.txt");
                system("rm /tmp/Get2gRadioEnable.txt");
                sprintf(command,"%s%d%s","echo ",enable," > /tmp/Get2gRadioEnable.txt");
        }
        else if(radioIndex == 1)
        {
                sprintf(buf,"%s%d%s","echo ",GetssidEnable," > /tmp/Get5gssidEnable.txt");
                system("rm /tmp/Get5gRadioEnable.txt");
                sprintf(command,"%s%d%s","echo ",enable," > /tmp/Get5gRadioEnable.txt");
        }
        system(buf);
        system(command);


	if((radioIndex == 0) && (enable == false))
	{
		GetInterfaceName(interface_name,"/etc/hostapd_2.4G.conf");
		sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
		system(buf);
		//system("ifconfig wlan0 down");
	}
	//KillHostapd();
	else if((radioIndex == 1) && (enable == false))
	{
		GetInterfaceName(interface_name,"/etc/hostapd_5G.conf");
		sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
                system(buf);
		//system("ifconfig wlan1 down");
	}
	else if((radioIndex == 4) && (enable == false))
	{
		GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
		sprintf(buf,"%s %s %s","ifconfig",virtual_interface_name,"down");
                system(buf);
		//system("ifconfig wlan0_0 down");
	}
	else if((radioIndex == 4) && (enable == true))
	{
		wifi_stopHostApd();
		wifi_startHostApd();
	}
	else if((radioIndex == 5) && (enable == false))
        {
		GetInterfaceName(interface_name,"/etc/hostapd_xfinity_5G.conf");
                sprintf(buf,"%s %s %s","ifconfig",interface_name,"down");
                system(buf);
                //system("ifconfig wlan0_0 down");
        }
        else if((radioIndex == 5) && (enable == true))
	{
		KillHostapd_xfinity_5g();
        }
	
	if((radioIndex == 0) || (radioIndex == 1))  //Both parameter's SSID and Radio are true , Hostapd will be restart else it's won't restart
        {
                if((enable == true) && (GetssidEnable == true))
                        wifi_applyRadioSettings(radioIndex);
        }

	//KillHostapd();
	return RETURN_OK;
}
#endif
//Set the Radio enable config parameter
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
                if((radioIndex == 0) || (radioIndex == 1))  //if((SSID.Enable == TRUE ) && (Radio.Enable == TRUE)) then bring's up SSID
                {
                        if((enable == TRUE) && (GetssidEnable == TRUE))
                        {
				hostapd_restarting_process(radioIndex);
                        }
                }
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}
//Get the Radio enable status
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);	
	if (NULL == output_bool) 
	{
		return RETURN_ERR;
	} 
	else 
	{
		wifi_getRadioEnable(radioIndex, output_bool);
		WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
		return RETURN_OK;
	}
}

//Get the Radio Interface name from platform, eg "wifi0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, "%s%d", RADIO_PREFIX, radioIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the wifi maxbitrate
INT get_wifiMaxbitrate(int radioIndex,char *output_string)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[MAX_BUF_SIZE] = {0};
	wifi_getRadioOperatingChannelBandwidth(radioIndex,&buf);
	if((strcmp(buf,"20MHz") == 0) && (radioIndex == 0))
		strcpy(output_string,"144 Mb/s");
	else if((strcmp(buf,"40MHz") == 0) && (radioIndex == 0))
		strcpy(output_string,"300 Mb/s");
	else if((strcmp(buf,"20MHz") == 0) && (radioIndex == 1))
		strcpy(output_string,"54 Mb/s");
	else if((strcmp(buf,"40MHz") == 0) && (radioIndex == 1))
		strcpy(output_string,"300 Mb/s");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[512] =  {0};
	char buf[1024] = {0};
	int count = 0;
	ULONG MaxBitRate = 0;

	if (NULL == output_string) 
		return RETURN_ERR;

	/*apIndex=(radioIndex==0)?0:1;

	  snprintf(cmd, sizeof(cmd), "iwconfig %s%d | grep \"Bit Rate\" | cut -d':' -f2 | cut -d' ' -f1,2", AP_PREFIX, apIndex);
	  _syscmd(cmd,buf, sizeof(buf));

	  snprintf(output_string, 64, "%s", buf);*/
	char interface_name[50] = {0},tmp_buf[50] = {0};
	FILE *fp = NULL;
	if(radioIndex == 0)
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	else if(radioIndex == 1)
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");

	sprintf(cmd,"%s%s%s%s%s","iwconfig ",interface_name," | grep ",interface_name," | wc -l");
	File_Reading(cmd,buf);
	if(strcmp(buf,"1") == 0)
	{
		sprintf(cmd,"%s%s%s","iwconfig ",interface_name," | grep 'Bit Rate' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1,2");
		_syscmd(cmd,buf,sizeof(buf));
	}
	else
		strcpy(output_string,"0");
	if(strcmp(buf,"0") == 0)
	{
		get_wifiMaxbitrate(radioIndex,output_string);
	}
	else if(strlen(buf) > 0)
	{
		for(count = 0;buf[count]!='\n';count++)
                        tmp_buf[count] = buf[count]; //ajusting the size
                tmp_buf[count] = '\0';
                strcpy(output_string,tmp_buf);
	}
	else
	{
		get_wifiMaxbitrate(radioIndex,output_string);
	}

	if (strstr(output_string, "Mb/s")) {
                //216.7 Mb/s
                MaxBitRate = strtof(output_string,0);
        } else if (strstr(output_string, "Gb/s")) {
                //1.3 Gb/s
                MaxBitRate = strtof(output_string,0) * 1000;
        } else {
                //Auto or Kb/s
                MaxBitRate = 0;
        }
        sprintf(output_string,"%lu",MaxBitRate);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}


//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex==0)?"2.4GHz":"5GHz");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex==0)?"2.4GHz":"5GHz");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex==0)?"b,g,n":"a,n,ac");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
#if 0
	if (NULL == output_string) 
		return RETURN_ERR;
	if(radioIndex==0) {
		snprintf(output_string, 64, "n");		//"ht" needs to be translated to "n" or others
		*gOnly=FALSE;
		*nOnly=TRUE;
		*acOnly=FALSE;
	} else {
		snprintf(output_string, 64, "ac");		//"vht" needs to be translated to "ac"
		*gOnly=FALSE;
		*nOnly=FALSE;
		*acOnly=FALSE;	
	}
#endif
	char string[50] = {0};
	struct params params={"hw_mode",""};
	if ((NULL == output_string) && (NULL == gOnly) && (NULL == nOnly) && (NULL == acOnly))
		return RETURN_ERR;

	memset(output_string,'\0',4);
	wifi_hostapdRead(radioIndex,&params,output_string);

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
		wifi_dbg_printf("\nReturning from getRadioStandard\n");
		*gOnly=FALSE;
		*nOnly=FALSE;
		*acOnly=TRUE;
	}
	else
		wifi_dbg_printf("\nInvalid Mode\n");

	//for a,n mode
	if(radioIndex == 1)
	{
		struct params params={"ieee80211n",""};
		wifi_hostapdRead(radioIndex,&params,string);
		wifi_dbg_printf("\noutput_string=%s\n",string);
		if(strcmp(string,"1")==0)
		{
			strcpy(output_string,"n");
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
	return RETURN_ERR;
}

//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[128] = {'\0'};
	int count = 0;	
	if (NULL == output_string) 
		return RETURN_ERR;
	//snprintf(output_string, 64, (radioIndex==0)?"1-11":"36,40");
	char PossibleChannels[256] = {0},interface_name[256] = {0};
	if(radioIndex == 0)
	{
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		sprintf(PossibleChannels,"%s %s %s","iwlist",interface_name ,"freq  | grep Channel | grep -v 'Current Frequency' | grep 2'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | sed 's/^0//g' | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
	}
	else if(radioIndex == 1)
	{
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
		sprintf(PossibleChannels,"%s %s %s","iwlist",interface_name ,"freq  | grep Channel | grep -v 'Current Frequency' | grep 5'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 |tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
	}
	_syscmd(PossibleChannels, buf, sizeof(buf));
	strcpy(output_string,buf);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[128] = {'\0'};
	int count = 0;
	if (NULL == output_string) 
		return RETURN_ERR;
	//snprintf(output_string, 256, (radioIndex==0)?"1,6,11":"36,40");
	char Channels[256] = {0},interface_name[256] = {0};
        if(radioIndex == 0)
        {
                GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
                sprintf(Channels,"%s %s %s","iwlist",interface_name ,"channel  | grep Channel | grep -v 'Current Frequency' | grep 2'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 | sed 's/^0//g' | tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
        }
        else if(radioIndex == 1)
        {
                GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
                sprintf(Channels,"%s %s %s","iwlist",interface_name ,"channel  | grep Channel | grep -v 'Current Frequency' | grep 5'\\.' | cut -d ':' -f1 | tr -s ' ' | cut -d ' ' -f3 |tr '\\n' ' ' | sed 's/ /,/g' | sed 's/,$/ /g'");
        }
	_syscmd(Channels, buf, sizeof(buf));
	strcpy(output_string,buf);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the running channel number 
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_ulong) 
		return RETURN_ERR;
#if 0//LNT_EMU
	char cmd[128]={0};
	char buf[256]={0};
	INT apIndex;


	apIndex=(radioIndex==0)?0:1;


	snprintf(cmd, sizeof(cmd), "iwlist %s%d channel | grep Current | | cut -d'(' -f2 | cut -d')' -f1 | cut -d' ' -f2", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	*output_ulong=0;
	if(strlen(buf)>=1)
		*output_ulong = atol(buf);

	if(*output_ulong<=0)  {
		//TODO: SSID is inactive, get channel from wifi config
		// *output_ulong = 0;           
	}       
	return RETURN_OK;
#endif
#if 1//RDKB_EMU
	struct params params={"channel",""};
	char output[3]={'\0'};
	wifi_hostapdRead(radioIndex,&params,output);
	if(output!=NULL)
	{
		*output_ulong=atol(output);
	}
	wifi_dbg_printf("\n*output_long=%ld output from hal=%s\n",*output_ulong,output);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
#endif
}
//update the radio channel number
void wifi_updateRadiochannel(INT radioIndex,ULONG channel)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char path[1024] = {0};
        char channelvalue[50] = {0},current_channel_value[50] = {0},channel_value[50] = {0};
        char str[100] = {0},str1[100] = {0},str2[100] = {0};
        FILE *fp = NULL;
        char *Channel;
        int count = 0;
        if ( radioIndex == 0 ) 
                fp = popen("cat /nvram/hostapd0.conf | grep -w channel ", "r");
        else if ( radioIndex == 1 )
                fp = popen("cat /nvram/hostapd1.conf | grep -w channel ", "r");
        else if ( radioIndex == 4 )
                fp = popen("cat /nvram/hostapd4.conf | grep -w channel ", "r");
        else if ( radioIndex == 5 )
                fp = popen("cat /nvram/hostapd5.conf | grep -w channel ", "r");

        if (fp == NULL) {
                printf("Failed to run command in function %s\n",__FUNCTION__);
                return;
        }

        fgets(path, sizeof(path)-1, fp);
        Channel = strchr(path,'=');
        strcpy(channel_value,Channel+1);
        for(count=0;channel_value[count]!='\n';count++)
                current_channel_value[count]=channel_value[count];
        current_channel_value[count]='\0';
        sprintf(str1,"%s%s","channel=",current_channel_value);
        sprintf(channelvalue,"%lu",channel);
        sprintf(str2,"%s%s","channel=",channelvalue);
        if ( radioIndex == 0 )
                sprintf(str,"%s%s/%s%s%s","sed -i -e 's/",str1,str2,"/g' ","/nvram/hostapd0.conf");
        else if ( radioIndex == 1 )
                sprintf(str,"%s%s/%s%s%s","sed -i -e 's/",str1,str2,"/g' ","/nvram/hostapd1.conf");
        else if ( radioIndex == 4 )
                sprintf(str,"%s%s/%s%s%s","sed -i -e 's/",str1,str2,"/g' ","/nvram/hostapd4.conf");
        else if ( radioIndex == 5 )
                sprintf(str,"%s%s/%s%s%s","sed -i -e 's/",str1,str2,"/g' ","/nvram/hostapd5.conf");
        system(str);
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}
//set the autochannelenable config parameter
INT wifi_setAutoChannelEnableVal(INT radioIndex,ULONG channel)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//RDKB_EMU
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	if(radioIndex == 0)
	{
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return RETURN_ERR;
		}
		if(buf[0] == '#')
		{
			wifi_updateRadiochannel(radioIndex,channel);
			wifi_updateRadiochannel(4,channel);
		}
		else
		{
			wifi_updateRadiochannel(radioIndex,channel);
		}
	}
	else if(radioIndex == 1)
	{
		wifi_updateRadiochannel(radioIndex,channel);
		wifi_updateRadiochannel(5,channel);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Store the previous channel number
void wifi_storeprevchanval(INT radioIndex) //for AutoChannelEnable
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
	char path[1024] = {0}, channel_value[1024] = {0},current_channel_value[1024] = {0},str[1024] = {0};
	char *Channel;
	int count = 0;
	if(radioIndex == 0 ) 
		fp = popen("cat /nvram/hostapd0.conf | grep -w channel ", "r");
	else if(radioIndex == 1)
		fp = popen("cat /nvram/hostapd1.conf | grep -w channel ", "r");
	if (fp == NULL) {
		printf("Failed to run command in function %s\n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path)-1, fp);
	Channel = strchr(path,'=');
	strcpy(channel_value,Channel+1);
	for(count=0;channel_value[count]!='\n';count++)
		current_channel_value[count]=channel_value[count];
	current_channel_value[count]='\0';
	if((radioIndex == 0 ) || (radioIndex == 4))
		sprintf(str,"%s%s%s","echo ",current_channel_value," > /var/prevchanval2G_AutoChannelEnable");
	else if(radioIndex == 1)
		sprintf(str,"%s%s%s","echo ",current_channel_value," > /var/prevchanval5G_AutoChannelEnable");
	system(str);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}
//Set the running channel number 
INT wifi_setRadioChannel(INT radioIndex, ULONG channel)	//RDKB	//AP only
{
	//Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
	//return RETURN_ERR;//LNT_EMU
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	struct params params={'\0'};
	char str_channel[3]={'\0'};
	char Value[50] = {0};
	param_list_t list;
	strncpy(params.name,"channel",strlen("channel"));
	sprintf(str_channel,"%d",channel);
	strncpy(params.value,str_channel,strlen(str_channel));
	memset(&list,0,sizeof(list));
	if(RETURN_ERR == list_add_param(&list,params))
	{
		return RETURN_ERR;
	}
	wifi_storeprevchanval(radioIndex);
	if(radioIndex == 0)
	{
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return RETURN_ERR;
		}
		if(buf[0] == '#')
		{	
			printf(" Value of Channel is %s and %s\n",params.value,str_channel);
			wifi_hostapdWrite(radioIndex,&list);
			wifi_hostapdWrite(4,&list);
			list_free_param(&list);
		}	
		else
		{

			wifi_hostapdWrite(radioIndex,&list);
			list_free_param(&list);
		}
	}
	else if(radioIndex == 1) 
	{
		wifi_hostapdWrite(radioIndex,&list);
		wifi_hostapdWrite(5,&list);
		list_free_param(&list);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) //RDKB
{
	//Set to wifi config only. Wait for wifi reset to apply.
	//return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[256] = {0};
	char str_channel[256] = {0};
	int count = 0;
	ULONG Value = 0;
	FILE *fp = NULL;
	if(enable == TRUE)
	{
		if(radioIndex == 0)
		{
			fp = fopen("/var/prevchanval2G_AutoChannelEnable","r");
		}
		else if(radioIndex == 1)
		{
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
				pclose(fp);
			}
		}
		wifi_setRadioChannel(radioIndex,Value);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
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

INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable)			//RDKB
{	
	//Set to wifi config only. Wait for wifi reset to apply.
	return RETURN_ERR;
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

// Get the Radio Channel BandWidth
INT wifi_halgetRadioChannelBW(CHAR *file,CHAR *Value)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[256] = {0};
	FILE *fp = NULL;
	sprintf(buf,"%s%s%s","cat ",file," | grep -w require_ht");
	fp = popen(buf,"r");
	if(fp)
	{
		if(fgets(buf,sizeof(buf),fp) != NULL)
		{
			if(buf[0] == '#')
				strcpy(Value,"20MHz");
			else
				strcpy(Value,"40MHz");
		}
	}
	pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
//Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	//snprintf(output_string, 64, (radioIndex==0)?"20MHz":"40MHz");
	CHAR Value[50] = {0};
	if(radioIndex == 0)
		wifi_halgetRadioChannelBW("/nvram/hostapd0.conf",Value);
	else if(radioIndex == 1)
		wifi_halgetRadioChannelBW("/nvram/hostapd1.conf",Value);
	strcpy(output_string,Value);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//set the radio channel bandwidth for 40MHz
INT wifi_halsetRadioChannelBW_40(char *file)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[256] = {0},Value[256] = {0};
	int count = 0,ht_count = 0;
	sprintf(buf,"%s%s%s","cat ",file," | grep require_ht | wc -l");
	File_Reading(buf,Value);
	count = atoi(Value);
	sprintf(buf,"%s%s%s","cat ",file," | grep ht_capab | wc -l");
	File_Reading(buf,Value);
	ht_count = atoi(Value);
	if((count == 1) && (ht_count == 1))
	{
		sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/require_ht=1/ s/^#*//",'"',file);
		system(buf);
		sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/ht_capab=/ s/^#*//",'"',file);
		system(buf);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// set the radio channel bandwidth for 20MHz
INT wifi_halsetRadioChannelBW_20(char *file)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char buf[256] = {0},Value[256] = {0};
        int count = 0,ht_count = 0;
        sprintf(buf,"%s%s%s","cat ",file," | grep require_ht | wc -l");
        File_Reading(buf,Value);
        count = atoi(Value);
        sprintf(buf,"%s%s%s","cat ",file," | grep ht_capab | wc -l");
        File_Reading(buf,Value);
        ht_count = atoi(Value);
        if((count == 1) && (ht_count == 1))
	{
		sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/require_ht=1/ s/^/","#/",'"',file);                       
                system(buf);
		sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/ht_capab/ s/^/","#/",'"',file);                                      
	        system(buf);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) //Tr181	//AP only
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
	if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
	{
		return RETURN_ERR;
	}
	if(buf[0] == '#') //TP-link
	{
		if(strcmp(bandwidth,"40MHz") == 0)
		{
			if(radioIndex == 0)
			{ 
				wifi_halsetRadioChannelBW_40("/nvram/hostapd0.conf");
				wifi_halsetRadioChannelBW_40("/nvram/hostapd4.conf");
			}
			else if(radioIndex == 1)
			{
				wifi_halsetRadioChannelBW_40("/nvram/hostapd1.conf");
				wifi_halsetRadioChannelBW_40("/nvram/hostapd5.conf");
			}
		}
		else if(strcmp(bandwidth,"20MHz") == 0)
		{
			if(radioIndex == 0)
			{ 
				wifi_halsetRadioChannelBW_20("/nvram/hostapd0.conf");
				wifi_halsetRadioChannelBW_20("/nvram/hostapd4.conf");
			}
			else if(radioIndex == 1)
			{
				wifi_halsetRadioChannelBW_20("/nvram/hostapd1.conf");
				wifi_halsetRadioChannelBW_20("/nvram/hostapd5.conf");
			}
		}
	}
	else  //Tenda
	{
		if(strcmp(bandwidth,"40MHz") == 0)
		{
			if(radioIndex == 1)
			{
				wifi_halsetRadioChannelBW_40("/nvram/hostapd1.conf");
				wifi_halsetRadioChannelBW_40("/nvram/hostapd5.conf");
			}
		}
		else if(strcmp(bandwidth,"20MHz") == 0)
		{
			if(radioIndex == 0)
				wifi_halsetRadioChannelBW_20("/nvram/hostapd0.conf");
			else if(radioIndex == 1)
			{
				wifi_halsetRadioChannelBW_20("/nvram/hostapd1.conf");
				wifi_halsetRadioChannelBW_20("/nvram/hostapd5.conf");
			}
		}
	}
	hostapd_restarting_process(radioIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_halgetRadioExtChannel(CHAR *file,CHAR *Value)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	CHAR buf[150] = {0};
	FILE *fp = NULL;
	sprintf(buf,"%s%s%s","cat ",file," | grep -w ht_capab= | cut -d '=' -f2 | cut -d ']' -f1 | cut -d '[' -f2");
	fp = popen(buf,"r");
	if(fp)
	{
		if(fgets(buf,sizeof(buf)-1,fp) != NULL)
		{
			if(buf[4] == '+')
				strcpy(Value,"AboveControlChannel");
			else 
				strcpy(Value,"BelowControlChannel");
		}
	}
	pclose(fp);	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	//snprintf(output_string, 64, (radioIndex==0)?"":"BelowControlChannel");
	CHAR Value[100] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
	if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
	{
		return RETURN_ERR;
	}
	if(buf[0] == '#')//TP-link
	{
		if(radioIndex == 0)
		{
			wifi_getRadioOperatingChannelBandwidth(radioIndex,Value);
			if(strcmp(Value,"20MHz") == 0)
				strcpy(Value,"Auto");
			else
				wifi_halgetRadioExtChannel("/nvram/hostapd0.conf",Value);
		}
		else if(radioIndex == 1)
		{
			wifi_getRadioOperatingChannelBandwidth(radioIndex,Value);
			if(strcmp(Value,"20MHz") == 0)
				strcpy(Value,"Auto");
			else
				wifi_halgetRadioExtChannel("/nvram/hostapd1.conf",Value);
		}
	}
	else//Tenda
	{
		if(radioIndex == 0)
		{
			strcpy(Value,"Auto");//Tenda supports speed ipto 150mbps only
		}
		else if(radioIndex == 1)
		{
			wifi_getRadioOperatingChannelBandwidth(radioIndex,Value);
			if(strcmp(Value,"20MHz") == 0)
				strcpy(Value,"Auto");
			else
				wifi_halgetRadioExtChannel("/nvram/hostapd1.conf",Value);
		}
	}

	strcpy(output_string,Value);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) //Tr181	//AP only
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={'\0'};
	char ext_channel[127]={'\0'};
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	param_list_t list;
	strcpy(params.name,"ht_capab");
	if(NULL!= strstr(string,"Above")) 
		strcpy(ext_channel,"\[HT40+\]\[SHORT-GI-20\]\[SHORT-GI-40\]");
	else if(NULL!= strstr(string,"Below"))
		strcpy(ext_channel,"\[HT40-\]\[SHORT-GI-20\]\[SHORT-GI-40\]");
	sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
	if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
	{
		return RETURN_ERR;
	}
	if(buf[0] == '#')//TP-Link
	{
		if((radioIndex == 0) || (radioIndex == 1))
		{
			strncpy(params.value,ext_channel,strlen(ext_channel));
			memset(&list,0,sizeof(list));
			if(RETURN_ERR == list_add_param(&list,params))
			{
				return RETURN_ERR;
			}
			wifi_hostapdWrite(radioIndex,&list);
			list_free_param(&list);
		}
	}
	else//Tenda
	{
		if(radioIndex == 0)
			return RETURN_ERR;
		else if(radioIndex == 1)
		{
			strncpy(params.value,ext_channel,strlen(ext_channel));
			memset(&list,0,sizeof(list));
			if(RETURN_ERR == list_add_param(&list,params))
			{
				return RETURN_ERR;
			}
			wifi_hostapdWrite(radioIndex,&list);
			list_free_param(&list);
		}
	}
	hostapd_restarting_process(radioIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}


//Get the guard interval value. eg "400nsec" or "800nsec" 
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string)	//Tr181
{
	//save config and apply instantly
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex==0)?"400nsec":"400nsec");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
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



//Get current Transmit Power, eg "75", "100"
//The transmite power level is in units of full power for this radio.
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
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
	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Set Transmit Power
//The transmite power level is in units of full power for this radio.
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower)	//RDKB
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[128]={0};
	char buf[256]={0};
	INT apIndex;	
		
	apIndex=(radioIndex==0)?0:1;
	
	snprintf(cmd, sizeof(cmd),  "iwconfig %s%d txpower %lu", AP_PREFIX, apIndex, TransmitPower);
	_syscmd(cmd, buf, sizeof(buf));	
	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
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
	if (NULL == output) 
		return RETURN_ERR;
	snprintf(output, 64, (radioIndex==0)?"1,2":"1.5,150");
	return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates)
{
	return RETURN_ERR;
}

INT wifi_halGetIfStats(char * ifname, wifi_radioTrafficStats2_t *pStats)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	CHAR buf[512] = {0};
	CHAR Value[512] = {0};
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_PacketsReceived=atol(Value);
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_PacketsSent=atol(Value);
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_BytesReceived=atol(Value);
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_BytesSent=atol(Value);
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_ErrorsReceived=atol(Value);
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_ErrorsSent=atol(Value);
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_DiscardPacketsReceived=atol(Value);
	sprintf(buf,"%s%s%s","ifconfig -a ",ifname," | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
	File_Reading(buf,Value);
	pStats->radio_DiscardPacketsSent=atol(Value);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
INT GetIfacestatus(CHAR *interface_name,CHAR *status)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        CHAR buf[512] = {0};
        FILE *fp = NULL;
        INT count = 0;
        //sprintf(buf,"%s%s%s%s%s","ifconfig -a ",interface_name," | grep ",interface_name," | wc -l > /tmp/Iface_count.txt");
        sprintf(buf,"%s%s%s%s%s","ifconfig -a ",interface_name," | grep ",interface_name," | wc -l");
        system(buf);
        //fp = popen("cat /tmp/Iface_count.txt","r");
        fp = popen(buf,"r");
        if(fp == NULL)
                return RETURN_ERR;
        if(fgets(buf,sizeof(buf)-1,fp) != NULL)
        {
                for(count = 0;buf[count]!='\n';count++)
                        status[count] = buf[count];
                status[count] = '\0';
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}

INT wifi_halGetIfStatsNull(wifi_radioTrafficStats2_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	output_struct->radio_BytesSent=0;
	output_struct->radio_BytesReceived=0;
	output_struct->radio_PacketsSent=0;
	output_struct->radio_PacketsReceived=0;
	output_struct->radio_ErrorsSent=0;
	output_struct->radio_ErrorsReceived=0;
	output_struct->radio_DiscardPacketsSent=0;
	output_struct->radio_DiscardPacketsReceived=0;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;	
}
//Get detail radio traffic static info
INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *output_struct) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_struct) 
		return RETURN_ERR;
		
	//ifconfig radio_x	
#if 0
	output_struct->radio_BytesSent=250;	//The total number of bytes transmitted out of the interface, including framing characters.
	output_struct->radio_BytesReceived=168;	//The total number of bytes received on the interface, including framing characters.
	output_struct->radio_PacketsSent=25;	//The total number of packets transmitted out of the interface.
	output_struct->radio_PacketsReceived=20; //The total number of packets received on the interface.

	output_struct->radio_ErrorsSent=0;	//The total number of outbound packets that could not be transmitted because of errors.
	output_struct->radio_ErrorsReceived=0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
	output_struct->radio_DiscardPacketsSent=0; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->radio_DiscardPacketsReceived=0; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
#endif
	CHAR private_interface_name[50] = {0},public_interface_name[50] = {0};
	CHAR private_interface_status[50] = {0},public_interface_status[50] = {0};
        char buf[MAX_BUF_SIZE] = {0};
        char cmd[MAX_CMD_SIZE] = {0};	
	
        wifi_radioTrafficStats2_t               private_radioTrafficStats,public_radioTrafficStats;
	if(radioIndex == 0) //2.4GHz
	{
		GetInterfaceName(private_interface_name,"/nvram/hostapd0.conf");
		GetIfacestatus(private_interface_name,private_interface_status);
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return RETURN_ERR;
		}
		if(buf[0] == '#')//TP-link
		{
			GetInterfaceName(public_interface_name,"/nvram/hostapd4.conf");
		}
		else //Tenda
		{
			GetInterfaceName_virtualInterfaceName_2G(public_interface_name);
		}
                GetIfacestatus(public_interface_name,public_interface_status);
                if(strcmp(private_interface_status,"1") == 0)
                        wifi_halGetIfStats(private_interface_name,&private_radioTrafficStats);
                else
                        wifi_halGetIfStatsNull(&private_radioTrafficStats);
                if(strcmp(public_interface_status,"1") == 0)
                        wifi_halGetIfStats(public_interface_name,&public_radioTrafficStats);
                else
                        wifi_halGetIfStatsNull(&public_radioTrafficStats);
        }
        else if(radioIndex == 1) //5GHz
        {
                GetInterfaceName(private_interface_name,"/nvram/hostapd1.conf");
                GetIfacestatus(private_interface_name,private_interface_status);
                GetInterfaceName(public_interface_name,"/nvram/hostapd5.conf");
                GetIfacestatus(public_interface_name,public_interface_status);
                if(strcmp(private_interface_status,"1") == 0)
                        wifi_halGetIfStats(private_interface_name,&private_radioTrafficStats);
                else
                        wifi_halGetIfStatsNull(&private_radioTrafficStats);

                if(strcmp(public_interface_status,"1") == 0)
                        wifi_halGetIfStats(public_interface_name,&public_radioTrafficStats);
                else
                        wifi_halGetIfStatsNull(&public_radioTrafficStats);
        }
		output_struct->radio_BytesSent=private_radioTrafficStats.radio_BytesSent + public_radioTrafficStats.radio_BytesSent;                  output_struct->radio_BytesReceived=private_radioTrafficStats.radio_BytesReceived + public_radioTrafficStats.radio_BytesReceived;
                output_struct->radio_PacketsSent=private_radioTrafficStats.radio_PacketsSent + public_radioTrafficStats.radio_PacketsSent;
                output_struct->radio_PacketsReceived=private_radioTrafficStats.radio_PacketsReceived + public_radioTrafficStats.radio_PacketsReceived;
                output_struct->radio_ErrorsSent=private_radioTrafficStats.radio_ErrorsSent + public_radioTrafficStats.radio_ErrorsSent;
                output_struct->radio_ErrorsReceived=private_radioTrafficStats.radio_ErrorsReceived + public_radioTrafficStats.radio_ErrorsReceived;
                output_struct->radio_DiscardPacketsSent=private_radioTrafficStats.radio_DiscardPacketsSent + public_radioTrafficStats.radio_DiscardPacketsSent;
                output_struct->radio_DiscardPacketsReceived=private_radioTrafficStats.radio_DiscardPacketsReceived + public_radioTrafficStats.radio_DiscardPacketsReceived;

	output_struct->radio_PLCPErrorCount=0;	//The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.	
	output_struct->radio_FCSErrorCount=0;	//The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
	output_struct->radio_InvalidMACCount=0;	//The number of packets that were received with a detected invalid MAC header error.
	output_struct->radio_PacketsOtherReceived=0;	//The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
	output_struct->radio_NoiseFloor=-99; 	//The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
	output_struct->radio_ChannelUtilization=35; //Percentage of time the channel was occupied by the radio\92s own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
	output_struct->radio_ActivityFactor=2; //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_CarrierSenseThreshold_Exceeded=20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_RetransmissionMetirc=0; //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage
	
	output_struct->radio_MaximumNoiseFloorOnChannel=-1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
	output_struct->radio_MinimumNoiseFloorOnChannel=-1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_MedianNoiseFloorOnChannel=-1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_StatisticsStartTime=0; 	    //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.
	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	if(radioIndex == 0) 
	{
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return RETURN_ERR;
		}
		if(buf[0] == '#')//TP-link
		{
			hostapd_restarting_process(radioIndex);
		}
		else //Tenda
		{
			system("sh /lib/rdk/start_hostapd.sh");
		}
	}
	else
		hostapd_restarting_process(radioIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the radio index assocated with this SSID entry
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex) 
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == radioIndex) 
		return RETURN_ERR;
	*radioIndex=ssidIndex%2;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get SSID enable configuration parameters (not the SSID enable status)
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_bool) 
		return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return wifi_getApEnable(ssidIndex, output_bool);
}

//Set SSID enable configuration parameters
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	return wifi_setApEnable(ssidIndex, enable);
}

//Get the SSID enable status
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) //Tr181
{
	/*	char cmd[128]={0};
		char buf[128]={0};
		snprintf(cmd, sizeof(cmd), "ifconfig %s%d | grep %s%d", AP_PREFIX, ssidIndex, AP_PREFIX, ssidIndex);	
		_syscmd(cmd, buf, sizeof(buf));

		snprintf(output_string, 64, (strlen(buf)> 5)?"Enabled":"Disabled");*/

	//RDKB-EMULATOR
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
	/*	if(apIndex==0) 
		snprintf(output, 64, "HOME-XXXX-2.4");
		else if(apIndex==1)
		snprintf(output, 64, "HOME-XXXX-5");
		else if(apIndex==2)
		snprintf(output, 64, "XHS-XXXXXX");
		else if(apIndex==4)
		snprintf(output, 64, "Xfinitywifi-2.4");
		else if(apIndex==5)
		snprintf(output, 64, "Xfinitywifi-5");	
		else
		snprintf(output, 64, "OOS");*/
	//RDKB_EMULATOR
		WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
		struct params params={"ssid",""};
		char buf[MAX_BUF_SIZE] = {0};
		char cmd[MAX_CMD_SIZE] = {0},ssid_val[50] = {0};
		
		if (NULL == output)
			return RETURN_ERR;
		if(apIndex == 4)
		{
			sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
			if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
			{
				return RETURN_ERR;
			}
			if(buf[0] == '#') //Tp-link
			{
				wifi_hostapdRead(apIndex,&params,output);
			}
			else //Tenda
			{
				GettingHostapdSsid(apIndex,"/nvram/hostapd0.conf",ssid_val);
				strcpy(output,ssid_val);
			}
		}
		else if((apIndex == 0) || (apIndex == 1) || (apIndex == 5))
		{
			wifi_hostapdRead(apIndex,&params,output);
		}
		else
			snprintf(output, 64, "OOS");
		wifi_dbg_printf("\n[%s]: SSID Name is : %s",__func__,output);
		WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
		if(output==NULL)
			return RETURN_ERR;
		else
			return RETURN_OK;
}
        
// Set a max 32 byte string and sets an internal variable to the SSID name          
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string)
{
	//Set to wifi config. wait for wifi reset or wifi_pushSSID to apply
	//return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char str[MAX_BUF_SIZE]={'\0'};
	char cmd[MAX_CMD_SIZE]={'\0'};
	char buf[MAX_BUF_SIZE]={'\0'};
	char *ch;
	int count = 0;
        FILE *fp = NULL;
        char path[256] = {0};
        char *ssid_val,output[50],*ssid_value;
        char str1[50],str2[50],val[50],val1[100],value[100];
        char *strValue = NULL;
        unsigned char *mac;
        char status[50];

	struct params params;
	param_list_t list;

	if(NULL == ssid_string)
		return RETURN_ERR;

	strcpy(params.name,"ssid");
	strcpy(params.value,ssid_string);
	printf("\n%s\n",__func__);
	memset(&list,0,sizeof(list));
	if(RETURN_ERR == list_add_param(&list,params))
	{
		return RETURN_ERR;
	}
	if(apIndex == 4)
	{
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return RETURN_ERR;
		}
		if(buf[0] == '#')//TP-link
		{
			wifi_hostapdWrite(apIndex,&list);
			list_free_param(&list);
		}
		else //Tenda
		{
			fp = popen("cat /nvram/hostapd0.conf | grep -w ssid ", "r");
			if (fp == NULL) 
			{
				printf("Failed to run command inside function %s\n",__FUNCTION__);
				return RETURN_ERR;
			}
			/* Read the output a line at a time - output it. */
			while(fgets(path, sizeof(path)-1, fp)!=NULL)
			{
				ssid_val = strchr(path,'=');
				strcpy(output,ssid_val+1);
				for(count=0;output[count]!='\n';count++)
					val[count]=output[count];
				val[count]='\0';
			}
			pclose(fp);
			if(path[0] == '#')
			{
				for(count=0;path[count]!='=';count++)
					val1[count] = path[count];
				val1[count] = '\0';

				sprintf(str1,"%s%c%s",val1,'=',val);
				sprintf(str2,"%s%c%s",val1,'=',ssid_string);
				sprintf(str,"%s%s/%s%s","sed -i '59s/",str1,str2,"/' /nvram/hostapd0.conf");
			}
			else
			{
				sprintf(str1,"%s%s","ssid=",val);
				sprintf(str2,"%s%s","ssid=",ssid_string);
				sprintf(str,"%s%s/%s%s","sed -i '59s/",str1,str2,"/' /nvram/hostapd0.conf");
			}
			system(str);
			hostapd_restarting_process(apIndex);
		}
		killXfinityWiFi();
		get_mac(&mac);
		//display uplink mac address
		printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		//Getting xfinity_wifi_5G SSID value
		fp = popen("cat /nvram/hostapd5.conf | grep -w ssid ", "r");
		if (fp == NULL) {
			printf("Failed to run command inside function %s\n",__FUNCTION__);
			return;
		}
		while(fgets(path, sizeof(path)-1, fp)!=NULL)
		{
			ssid_value = strchr(path,'=');
			strcpy(output,ssid_value+1);
		}
		pclose(fp);
		for(count=0;output[count]!='\n';count++)
			value[count]=output[count];
		value[count]='\0';

		//sysevent daemon updation with new ssid
		sprintf(str,"%s %c%.2x:%.2x:%.2x:%.2x:%.2x:%.2x;%s;%c%c","sysevent set snooper-queue1-circuitID",'"',mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],ssid_string,'o','"');
		system(str);
		sprintf(str,"%s %c%.2x:%.2x:%.2x:%.2x:%.2x:%.2x;%s;%c%c","sysevent set snooper-queue2-circuitID",'"',mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],value,'o','"');
		system(str);
		sleep(10);
		system("/lib/rdk/hotspot_restart.sh");
	}

	else if(apIndex == 5)
	{
		wifi_hostapdWrite(apIndex,&list);
		list_free_param(&list);
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return RETURN_ERR;
		}
		if(buf[0] == '#')//TP-link
		{
			struct params params={"ssid",""};
			wifi_hostapdRead(4,&params,value);
		}
		else
		{
			//Getting Xfinity_wifi_2.4Ghz ssid value
			fp = popen("cat /nvram/hostapd0.conf | grep -w ssid ", "r");
			if (fp == NULL) {
				printf("Failed to run command inside function %s\n",__FUNCTION__);
				return;
			}
			/* Read the output a line at a time - output it. */
			while(fgets(path, sizeof(path)-1, fp)!=NULL)
			{
				ssid_value = strchr(path,'=');
				strcpy(output,ssid_value+1);
			}
			pclose(fp);

			for(count=0;output[count]!='\n';count++)
				value[count]=output[count];
			value[count]='\0';
		}
		killXfinityWiFi();
		printf("Before Getting the MAc Address \n");
		get_mac(&mac);
		//display uplink mac address
		printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		//sysevent daemon updation with new ssid
		sprintf(str,"%s %c%.2x:%.2x:%.2x:%.2x:%.2x:%.2x;%s;%c%c","sysevent set snooper-queue1-circuitID",'"',mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],value,'o','"');
		system(str);
		sprintf(str,"%s %c%.2x:%.2x:%.2x:%.2x:%.2x:%.2x;%s;%c%c","sysevent set snooper-queue2-circuitID",'"',mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],ssid_string,'o','"');
		system(str);
		sleep(10);
		system("/lib/rdk/hotspot_restart_5G.sh");
	}

	else
	{
		wifi_hostapdWrite(apIndex,&list);
		list_free_param(&list);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifihal_getBaseBSSID(CHAR *interface_name,CHAR *mac,INT index)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp = NULL;
        char path[1024] = {0};
        if(index == 4)
        {
                if(strcmp(interface_name,"wlan0_0") == 0)
                        fp = popen("ifconfig -a | grep wlan0_0 | tr -s ' ' | cut -d ' ' -f5  ", "r");
                else if(strcmp(interface_name,"wlan1_0") == 0)
                        fp = popen("ifconfig -a | grep wlan1_0 | tr -s ' ' | cut -d ' ' -f5  ", "r");
                else if(strcmp(interface_name,"wlan2_0") == 0)
                        fp = popen("ifconfig -a | grep wlan2_0 | tr -s ' ' | cut -d ' ' -f5  ", "r");
        }
        else
        {
                if(strcmp(interface_name,"wlan0") == 0)
                        fp = popen("ifconfig -a | grep wlan0 | grep -v mon.wlan0 | grep -v wlan0_0 | tr -s ' ' | cut -d ' ' -f5  ", "r");
                else if(strcmp(interface_name,"wlan1") == 0)
                        fp = popen("ifconfig -a | grep wlan1 | grep -v mon.wlan1 | grep -v wlan1_0 | tr -s ' ' | cut -d ' ' -f5  ", "r");
                else if(strcmp(interface_name,"wlan2") == 0)
                        fp = popen("ifconfig -a | grep wlan2 | grep -v mon.wlan2 | grep -v wlan2_0 | tr -s ' ' | cut -d ' ' -f5  ", "r");
                else if(strcmp(interface_name,"wlan3") == 0)
                        fp = popen("ifconfig -a | grep wlan3 | grep -v mon.wlan3 | grep -v wlan3_0 | tr -s ' ' | cut -d ' ' -f5  ", "r");
        }
        if (fp == NULL) {
                printf("Failed to run command inside function %s\n",__FUNCTION__ );
                strcpy(mac,"00:00:00:00:00:00");
                return RETURN_OK;
        }
        fgets(path, sizeof(path)-1, fp);
        strcpy(mac,path);
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}


//Get the BSSID 
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string)	//RDKB
{
#if 0//LNT_EMU
	char cmd[128]={0};


	sprintf(cmd, "ifconfig -a %s%d | grep HWaddr | tr -s " " | cut -d' ' -f5", AP_PREFIX, ssidIndex);
	_syscmd(cmd, output_string, 64);

	return RETURN_OK;
#endif
#if 1//RDKB_EMU
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	char bssid[20] = {0};
        char interface_name[512] = {0};
        char virtual_interface_name[512] = {0};

        if(ssidIndex == 0) //private_wifi for 2.4G
        {
                GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
                wifihal_getBaseBSSID(interface_name,bssid,ssidIndex);
                strcpy(output_string,bssid);
        }
        else if(ssidIndex == 1) //private_wifi for 5G
        {
                GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
                wifihal_getBaseBSSID(interface_name,bssid,ssidIndex);
                strcpy(output_string,bssid);
        }

        else if(ssidIndex == 4) //public_wifi for 2.4G
	{
		char cmd[MAX_CMD_SIZE] = {0};
		char buf[MAX_BUF_SIZE] = {0};
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
		{
			return RETURN_ERR;
		}
		if(buf[0] == '#') //tp-link
		{
			GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
			wifihal_getBaseBSSID(interface_name,bssid,0);
		}
		else//tenda
		{
			GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
                	wifihal_getBaseBSSID(virtual_interface_name,bssid,ssidIndex);
		}
		strcpy(output_string,bssid);
	}
	else if(ssidIndex == 5) //public_wifi for 5G
        {
                GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
                wifihal_getBaseBSSID(interface_name,bssid,ssidIndex);
                strcpy(output_string,bssid);
        }

#endif
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the MAC address associated with this Wifi SSID
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) //Tr181
{
	/*	char cmd[128]={0};


		sprintf(cmd, "ifconfig -a %s%d | grep HWaddr | tr -s " " | cut -d' ' -f5", AP_PREFIX, ssidIndex);
		_syscmd(cmd, output_string, 64);*/ 
	//RDKB-EMULATOR
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_string) 
		return RETURN_ERR;
	char bssid[20] = {0};
        char interface_name[512] = {0};
        char virtual_interface_name[512] = {0};
        if(ssidIndex == 0) //private_wifi eith 2.4G
        {
                GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
                wifihal_getBaseBSSID(interface_name,bssid,ssidIndex);
                strcpy(output_string,bssid);
        }
        else if(ssidIndex == 1) //private_wifi with 5G
        {
                GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
                wifihal_getBaseBSSID(interface_name,bssid,ssidIndex);
                strcpy(output_string,bssid);
        }

        else if(ssidIndex == 4)//public_wifi with 2.4G
        {
		char cmd[MAX_CMD_SIZE] = {0};
                char buf[MAX_BUF_SIZE] = {0};
                sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
                if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
                {
                        return RETURN_ERR;
                }
                if(buf[0] == '#') //tp-link
                {
                        GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
                        wifihal_getBaseBSSID(interface_name,bssid,0);
                }
                else//tenda
                {
                        GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
                        wifihal_getBaseBSSID(virtual_interface_name,bssid,ssidIndex);
                }
                strcpy(output_string,bssid);
        }
        else if(ssidIndex == 5)//public_wifi with 5G
        {
                GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
                wifihal_getBaseBSSID(interface_name,bssid,ssidIndex);
                strcpy(output_string,bssid);
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Get the basic SSID traffic static info
INT wifi_getSSIDTrafficStats2(INT ssidIndex, wifi_ssidTrafficStats2_t *output_struct) //Tr181
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[128]={0};
	char buf[1024]={0};
	
	sprintf(cmd, "ifconfig %s%d ", AP_PREFIX, ssidIndex);
    _syscmd(cmd, buf, sizeof(buf));
	
	output_struct->ssid_BytesSent		=2048;	//The total number of bytes transmitted out of the interface, including framing characters.
	output_struct->ssid_BytesReceived	=4096;	//The total number of bytes received on the interface, including framing characters.
	output_struct->ssid_PacketsSent		=128;	//The total number of packets transmitted out of the interface.
	output_struct->ssid_PacketsReceived	=128; //The total number of packets received on the interface.

	output_struct->ssid_RetransCount	=0;	//The total number of transmitted packets which were retransmissions. Two retransmissions of the same packet results in this counter incrementing by two.
	output_struct->ssid_FailedRetransCount=0; //The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit. This parameter is based on dot11FailedCount from [802.11-2012].	
	output_struct->ssid_RetryCount		=0;  //The number of packets that were successfully transmitted after one or more retransmissions. This parameter is based on dot11RetryCount from [802.11-2012].	
	output_struct->ssid_MultipleRetryCount=0; //The number of packets that were successfully transmitted after more than one retransmission. This parameter is based on dot11MultipleRetryCount from [802.11-2012].	
	output_struct->ssid_ACKFailureCount	=0;  //The number of expected ACKs that were never received. This parameter is based on dot11ACKFailureCount from [802.11-2012].	
	output_struct->ssid_AggregatedPacketCount=0; //The number of aggregated packets that were transmitted. This applies only to 802.11n and 802.11ac.	

	output_struct->ssid_ErrorsSent		=0;	//The total number of outbound packets that could not be transmitted because of errors.
	output_struct->ssid_ErrorsReceived	=0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
	output_struct->ssid_UnicastPacketsSent=2;	//The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
	output_struct->ssid_UnicastPacketsReceived=2;  //The total number of received packets, delivered by this layer to a higher layer, which were not addressed to a multicast or broadcast address at this layer.
	output_struct->ssid_DiscardedPacketsSent=1; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->ssid_DiscardedPacketsReceived=1; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->ssid_MulticastPacketsSent=10; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a multicast address at this layer, including those that were discarded or not sent.
	output_struct->ssid_MulticastPacketsReceived=0; //The total number of received packets, delivered by this layer to a higher layer, which were addressed to a multicast address at this layer.  
	output_struct->ssid_BroadcastPacketsSent=0;  //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
	output_struct->ssid_BroadcastPacketsRecevied=1; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
	output_struct->ssid_UnknownPacketsReceived=0;  //The total number of packets received via the interface which were discarded because of an unknown or unsupported protocol.
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);	
	return RETURN_OK;
}

//Apply SSID and AP (in the case of Acess Point devices) to the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applySSIDSettings(INT ssidIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//Tr181
INT wifi_getNeighboringWiFiStatus(INT apIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
#if 0
    int rc;
    char buf[IOCTL_MAX_BUF_SIZE];
    //char *ifName = _wifi_getApName(apIndex);
    char ifName[50] = {0};
    strcpy(ifName,"wlan0");
    struct iwreq request;

    *neighbor_ap_array = NULL;
    *output_array_size = 0;

    memset(buf, 0, sizeof(buf));
    memset(&request, 0, sizeof(request));
    request.u.data.pointer = buf;
    request.u.data.length = sizeof(buf);
    rc = _wifi_ioctl_iwreq_data(ifName, SIOCGIWSCAN, buf, sizeof(buf));
    if (rc < 0) return RETURN_ERR;

    int size = rc;
    struct iw_event *iw_event;
    char *ptr = buf;
    unsigned len = size;
    BOOL parse_error = TRUE;
    int scan_count = 0;
    int status;
    wifi_neighbor_ap2_t *scan_array = NULL;
    wifi_neighbor_ap2_t *scan_record = NULL;

    while (len > IW_EV_LCP_LEN) {
        // next event
        iw_event = (struct iw_event *)ptr;
        // end of buffer
        if (len < iw_event->len) break;
        // new record
        if (SIOCGIWAP == iw_event->cmd)
        {
            // append new record to results
            parse_error = FALSE;
            scan_record = realloc(scan_array, sizeof(*scan_record) * (scan_count + 1));
            if (!scan_record) {
                free(scan_array);
                return RETURN_ERR;
            }
            scan_array = scan_record;
            scan_record = &scan_array[scan_count];
            memset(scan_record, 0, sizeof(*scan_record));
            scan_count++;
        }

        // Skip entry events in case of parser error
        if (TRUE == parse_error) continue;

        status = _wifi_scan_results_parse_event(iw_event, scan_record);
	if (RETURN_OK != status)
        {
            // Clear previous data in case of error
            memset(scan_record, 0, sizeof(*scan_record));
            // Skip parsing of next events till new record is found
            parse_error = TRUE;
            // Reset count
            scan_count--;
        }

        ptr += iw_event->len;
        len -= iw_event->len;
    }
    *neighbor_ap_array = scan_array;
    *output_array_size = scan_count;
#endif
    //CHAR  ap_SSID[64];
    //CHAR  ap_BSSID[64];
    //CHAR  ap_Mode[64];
    //UINT  ap_Channel;
    //INT   ap_SignalStrength;
    //CHAR  ap_SecurityModeEnabled[64];
    //CHAR  ap_EncryptionMode[64];
    //CHAR  ap_OperatingFrequencyBand[16];
    //CHAR  ap_SupportedStandards[64];
    //CHAR  ap_OperatingStandards[16];
    //CHAR  ap_OperatingChannelBandwidth[16];
    //UINT  ap_BeaconPeriod;
    //INT   ap_Noise;
    //CHAR  ap_BasicDataTransferRates[256];
    //CHAR  ap_SupportedDataTransferRates[256];
    //UINT  ap_DTIMPeriod;
    //UINT  ap_ChannelUtilization;
    return RETURN_OK;
}

//Sacn to get the nearby wifi devices
int GetScanningValues(char *file,char *value)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        FILE *fp = NULL;
        char path[256] = {0};
        fp = popen(file,"r");
        int count = 0;
        if(fp == NULL)
        {
                printf("=== %s == \n",__FUNCTION__);
                return 0;
        }
        while(fgets(path,sizeof(path),fp) != NULL)
        {
                for(count = 0;path[count]!='\n';count++)
                        value[count] = path[count];
                value[count]='\0';
        }
        pclose(fp);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
void converting_lowercase_to_uppercase(char *Value)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	int i = 0;
	for(i=0;i<=strlen(Value);i++) //Converting lowercase to uppercase
	{
		if(Value[i]>=97 && Value[i]<=122)
		{
			Value[i]=Value[i]-32;
		}
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}
// scan to get the nearby wifi device lists
void wifihal_GettingNeighbouringAPScanningDetails(char *interface_name,wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
	wifi_neighbor_ap2_t *pt=NULL;
	CHAR cmd[128]={0},Value[256] = {0},security_mode[256] = {0};
	CHAR buf[8192]={0},str[256] = {0};
	UINT count = 0,i = 0,index = 0;
	fp = fopen("/tmp/wifiscan.txt","r");
	if(fp == NULL)
	{
		printf("wifiscan.txt is not there,please check the wireless command \n");
		*output_array_size=0;
		return ;
	}

	//For Total Number of AP's
	sprintf(buf,"%s%s%s","cat /tmp/wifiscan.txt | grep ",interface_name," | wc -l");
	GetScanningValues(buf,Value);
	*output_array_size=atoi(Value);

	//zqiu: HAL alloc the array and return to caller. Caller response to free it.
	*neighbor_ap_array=(wifi_neighbor_ap2_t *)calloc(sizeof(wifi_neighbor_ap2_t), *output_array_size);
	for (index = 0, pt=*neighbor_ap_array; index < *output_array_size; index++, pt++) 
	{
		sprintf(buf,"%s%s%s%d","cat /tmp/wifiscan.txt | grep ",interface_name," | cut -d ' ' -f2 | cut -d '(' -f1 | head -",index+1);
		GetScanningValues(buf,pt->ap_BSSID);
		sprintf(buf,"%s%d","cat /tmp/wifiscan.txt | grep SSID | cut -d ':' -f2 | sed 's/^ //g' | head -",index+1);
		GetScanningValues(buf,pt->ap_SSID);
		sprintf(buf,"%s%d","cat /tmp/wifiscan.txt | grep freq | cut -d ':' -f2 | cut -d ' ' -f2 | head -",index+1);
		GetScanningValues(buf,Value);
		if(Value[0] == '2')
			strcpy(pt->ap_OperatingFrequencyBand,"2.4GHz");
		else
			strcpy(pt->ap_OperatingFrequencyBand,"5GHz");

		fp = popen("cat /tmp/wifiscanning.txt | sed -n '1!p' | cut -d ' ' -f1 | tr '[:upper:]' '[:lower:]'","r");
		if(fp == NULL)
		{
			printf("Failed Function %s \n",__FUNCTION__);
			return ;
		}
		while(fgets(buf,sizeof(buf)-1,fp) != NULL)
		{
			for(count=0;buf[count]!='\n';count++)
				Value[count] = buf[count];
			Value[count] = '\0';
			if(strcmp(pt->ap_BSSID,Value) == 0)
			{
				converting_lowercase_to_uppercase(Value);
				sprintf(buf,"%s%s%s","cat /tmp/wifiscanning.txt | grep ",Value," | cut -d ' ' -f4,5");
				GetScanningValues(buf,pt->ap_SecurityModeEnabled);
				if(strcmp(pt->ap_SecurityModeEnabled,"WPA WPA2") == 0)
					strcpy(pt->ap_SecurityModeEnabled,"WPA-WPA2");
				sprintf(buf,"%s%s%s","cat /tmp/wifiscanning.txt | grep ",Value," | cut -d ' ' -f13-16");
				if(strcmp(pt->ap_SecurityModeEnabled,"WPA ") == 0)
					sprintf(buf,"%s%s%s","cat /tmp/wifiscanning.txt | grep ",Value," | cut -d ' ' -f17-19");
				GetScanningValues(buf,str);
				wlan_encryption_mode_to_string(str,pt->ap_EncryptionMode);
				sprintf(buf,"%s%s%s","cat /tmp/wifiscanning.txt | grep ",Value," | cut -d ' ' -f8");
				if((strcmp(pt->ap_SecurityModeEnabled,"WPA ") == 0) || (strcmp(pt->ap_SecurityModeEnabled,"WPA2 ") == 0))
					sprintf(buf,"%s%s%s","cat /tmp/wifiscanning.txt | grep ",Value," | awk '{print $3}'");
				GetScanningValues(buf,str);
				wlan_bitrate_to_operated_standards_string(str,pt->ap_OperatingStandards,pt->ap_OperatingFrequencyBand);
				wlan_operated_standards_to_channel_bandwidth_string(pt->ap_OperatingStandards,pt->ap_OperatingChannelBandwidth);
				break;
			}
		}
		pclose(fp);
		sprintf(buf,"%s%d","cat /tmp/wifiscan.txt | grep 'primary channel' | cut -d ':' -f2 | cut -d ' ' -f2 | head -",index+1);
		GetScanningValues(buf,Value);
		pt->ap_Channel=atoi(Value);

		fp = popen("cat /tmp/wifi-scan.txt | grep Address | cut -d '-' -f2 | cut -d ' ' -f3 | tr '[:upper:]' '[:lower:]'","r");
		if(fp == NULL)
		{
			printf("Failed Function %s \n",__FUNCTION__);
			return ;
		}
		while(fgets(buf,sizeof(buf)-1,fp) != NULL)
		{
			for(count=0;buf[count]!='\n';count++)
				Value[count] = buf[count];
			Value[count] = '\0';
			if(strcmp(pt->ap_BSSID,Value) == 0)
			{
				sprintf(buf,"%s%s%s","cat /tmp/iwlist-scan.txt | grep ",Value," | awk '{print $2}'");
				GetScanningValues(buf,pt->ap_Mode);
			}
			if(strcmp(pt->ap_BSSID,Value) == 0)
			{
				sprintf(buf,"%s%s%s","cat /tmp/iwlist-scan.txt | grep ",Value," | awk '{print $3}'");
				GetScanningValues(buf,str);
				wlan_wireless_mode_to_supported_standards_string(str,pt->ap_SupportedStandards,pt->ap_OperatingFrequencyBand);
			}
		}

		pclose(fp);
		sprintf(buf,"%s%d","cat /tmp/wifiscan.txt | grep signal | cut -d ':' -f2 | sed 's/^ //g' | head -",index+1);
		GetScanningValues(buf,Value);
		pt->ap_SignalStrength=atoi(Value);
		sprintf(buf,"%s%d","cat /tmp/wifiscan.txt | grep 'Supported rates' | cut -d ':' -f2 | sed 's/^ //g' | sed 's/ /,/g' | sed 's/,$//g' | head -",index+1);
		GetScanningValues(buf,pt->ap_SupportedDataTransferRates);
		sprintf(buf,"%s%d","cat /tmp/wifiscan.txt | grep 'beacon interval' | cut -d ':' -f2 | sed 's/^ //g' | cut -d ' ' -f1 | head -",index+1);
		GetScanningValues(buf,Value);
		pt->ap_BeaconPeriod=atoi(Value);
		strcpy(pt->ap_BasicDataTransferRates,"1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54");
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}
//Start the wifi scan and get the result into output buffer for RDKB to parser. The result will be used to manage endpoint list
//HAL funciton should allocate an data structure array, and return to caller with "neighbor_ap_array"
INT wifi_getNeighboringWiFiDiagnosticResult2(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size) //Tr181	
{
#if 1
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	INT status = RETURN_ERR;
	UINT index;
	wifi_neighbor_ap2_t *pt=NULL;
	char cmd[512]={0},Value[256] = {0},security_mode[256] = {0};
	char buf[8192]={0},str[256] = {0},interface_name[50] = {0},wifi_status[50] = {0};
	int count = 0,i=0;
	//sprintf(cmd, "iwlist %s%d scan",AP_PREFIX,(radioIndex==0)?0:1);	//suppose ap0 mapping to radio0
	/*	sprintf(cmd, "iwlist wlan0 scan",AP_PREFIX,(radioIndex==0)?0:1);	//suppose ap0 mapping to radio0
		_syscmd(cmd, buf, sizeof(buf));
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
		pt->ap_ChannelUtilization=0;*/
	system("nmcli -f BSSID,SECURITY,RATE,WPA-FLAGS dev wifi > /tmp/wifiscanning.txt");

        if(radioIndex == 0)
        {
                GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		printf("NeighbouringAp Index is %d \n",radioIndex);
		wifihal_interfacestatus(wifi_status,interface_name);
	        if(strcmp(wifi_status,"RUNNING") == 0)
		{
                	sprintf(buf,"%s%s%s","iwlist ",interface_name," scan > /tmp/wifi-scan.txt");
                	sprintf(cmd,"%s%s%s","iw dev ",interface_name," scan ap-force > /tmp/wifiscan.txt");
		}
		else
		{
			printf("2.4G Private Wifi Driver status is down \n");
			*output_array_size = 0;
			*neighbor_ap_array = NULL;
			return RETURN_OK;
		}
			
        }
        else if(radioIndex == 1)
        {
                GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
		wifihal_interfacestatus(wifi_status,interface_name);
		printf("NeighbouringAp Index is %d \n",radioIndex);
                if(strcmp(wifi_status,"RUNNING") == 0)
                {
                        sprintf(buf,"%s%s%s","iwlist ",interface_name," scan > /tmp/wifi-scan.txt");
                        sprintf(cmd,"%s%s%s","iw dev ",interface_name," scan ap-force > /tmp/wifiscan.txt");
                }
                else
                {
                        printf("5G Private Wifi Driver status is down \n");
                        *output_array_size = 0;
                        *neighbor_ap_array = NULL;
                        return RETURN_OK;
                }

        }
#if 0
        else if(radioIndex == 4)
        {
                GetInterfaceName_virtualInterfaceName_2G(interface_name);
		wifihal_interfacestatus(wifi_status,interface_name);
		printf("NeighbouringAp Index is %d \n",radioIndex);
                if(strcmp(wifi_status,"RUNNING") == 0)
                {
                        sprintf(buf,"%s%s%s","iwlist ",interface_name," scan > /tmp/wifi-scan.txt");
                        sprintf(cmd,"%s%s%s","iw dev ",interface_name," scan > /tmp/wifiscan.txt");
                }
                else
                {
                        printf("2.4G Public Wifi Driver status is down \n");
                        *output_array_size = 0;
                        *neighbor_ap_array = NULL;
                        return RETURN_OK;
                }

        }
        else if(radioIndex == 5)
        {
                GetInterfaceName(interface_name,"/etc/hostapd_xfinity_5G.conf");
		wifihal_interfacestatus(wifi_status,interface_name);
		printf("NeighbouringAp Index is %d \n",radioIndex);
                if(strcmp(wifi_status,"RUNNING") == 0)
                {
                        sprintf(buf,"%s%s%s","iwlist ",interface_name," scan > /tmp/wifi-scan.txt");
                        sprintf(cmd,"%s%s%s","iw dev ",interface_name," scan > /tmp/wifiscan.txt");
                }
                else
                {
                        printf("5G Public Wifi Driver status is down \n");
                        *output_array_size = 0;
                        *neighbor_ap_array = NULL;
                        return RETURN_OK;
                }

        }
#endif
        system(buf);
        system(cmd);
        sleep(2);
        system("cat /tmp/wifi-scan.txt | grep Address | cut -d '-' -f2 | cut -d ' ' -f3 | tr '[:upper:]' '[:lower:]' > /tmp/f.t");
        system("cat /tmp/wifi-scan.txt | grep Mode | tr -s ' ' | sed 's/ //g' | cut -d ':' -f2 > /tmp/s.t");
        system("cat /tmp/wifi-scan.txt | grep Protocol | cut -d ':' -f2 | cut -d '.' -f2 | sed 's/11//g' > /tmp/t.t");
        system("paste /tmp/f.t /tmp/s.t /tmp/t.t  > /tmp/iwlist-scan.txt");
        sleep(2);
	wifihal_GettingNeighbouringAPScanningDetails(interface_name,neighbor_ap_array,output_array_size);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
#endif
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
	/*char cmd[128];  
	  char buf[1280];
	  char *pos=NULL;*/
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char interface_name[512] = {0};
	char *pos=NULL;
	char buf[1024] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	if (NULL == output_struct) {
		return RETURN_ERR;
	} 

	memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

	//RDKB-EMULATOR
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
	snprintf(cmd, sizeof(cmd), "ifconfig %s", interface_name);
	_syscmd(cmd,buf, sizeof(buf));

	pos = buf;
	if((pos=strstr(pos,"RX packets:"))==NULL)
		return RETURN_ERR;
	output_struct->wifi_PacketsReceived = atoi(pos+strlen("RX packets:"));

	if((pos=strstr(pos,"TX packets:"))==NULL)
		return RETURN_ERR;
	output_struct->wifi_PacketsSent = atoi(pos+strlen("TX packets:"));

	if((pos=strstr(pos,"RX bytes:"))==NULL)
		return RETURN_ERR;
	output_struct->wifi_BytesReceived = atoi(pos+strlen("RX bytes:"));

	if((pos=strstr(pos,"TX bytes:"))==NULL)
		return RETURN_ERR;
	output_struct->wifi_BytesSent = atoi(pos+strlen("TX bytes:"));
	}

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct)
{
		if (NULL == output_struct) 
		return RETURN_ERR;
	/*	} else {
		memset(output_struct, 0, sizeof(wifi_trafficStats_t));
		return RETURN_OK;
		}*/
	//RDKB-EMULATOR
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);	
	char tx_status[100] = {0},rx_status[50] = {0};
	int count = 0;//RDKB-EMULATOR
	char interface_name[512] = {0};
        char virtual_interface_name[512],buf[512],cmd[1024];
	if(apIndex == 0)//private_wifi with 2.4G
	{
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		if(strcmp(interface_name,"wlan0") == 0 )
			File_Reading("ifconfig wlan0 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
		else if(strcmp(interface_name,"wlan1") == 0 )
			File_Reading("ifconfig wlan1 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
		else if(strcmp(interface_name,"wlan2") == 0 )
			File_Reading("ifconfig wlan2 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
		else if(strcmp(interface_name,"wlan3") == 0 )
			File_Reading("ifconfig wlan3 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
		output_struct->wifi_ErrorsSent = atol(tx_status);
		
		if(strcmp(interface_name,"wlan0") == 0 )
			File_Reading("ifconfig wlan0 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
		else if(strcmp(interface_name,"wlan1") == 0 )
			File_Reading("ifconfig wlan1 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
		else if(strcmp(interface_name,"wlan2") == 0 )
			File_Reading("ifconfig wlan2 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
		else if(strcmp(interface_name,"wlan3") == 0 )
			File_Reading("ifconfig wlan3 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
		output_struct->wifi_ErrorsReceived = atol(rx_status);
	}
	else if(apIndex == 1)//private_wifi with 5G
        {
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
                if(strcmp(interface_name,"wlan0") == 0 )
                        File_Reading("ifconfig wlan0 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan1") == 0 )
                        File_Reading("ifconfig wlan1 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan2") == 0 )
                        File_Reading("ifconfig wlan2 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan3") == 0 )
                        File_Reading("ifconfig wlan3 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                output_struct->wifi_ErrorsSent = atol(tx_status);

		if(strcmp(interface_name,"wlan0") == 0 )
                        File_Reading("ifconfig wlan0 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan1") == 0 )
                        File_Reading("ifconfig wlan1 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan2") == 0 )
                        File_Reading("ifconfig wlan2 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan3") == 0 )
                        File_Reading("ifconfig wlan3 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                output_struct->wifi_ErrorsReceived = atol(rx_status);
        }

	else if(apIndex == 4)//public_wifi with 2.4G
	{
		sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
        if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
        {
                return RETURN_ERR;
        }
        if(buf[0] == '#')//tp-link
	{
	                GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
                if(strcmp(interface_name,"wlan0") == 0 )
                        File_Reading("ifconfig wlan0 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan1") == 0 )
                        File_Reading("ifconfig wlan1 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan2") == 0 )
                        File_Reading("ifconfig wlan2 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan3") == 0 )
                        File_Reading("ifconfig wlan3 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);

		if(strcmp(interface_name,"wlan0") == 0 )
                        File_Reading("ifconfig wlan0 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan1") == 0 )
                        File_Reading("ifconfig wlan1 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan2") == 0 )
                        File_Reading("ifconfig wlan2 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan3") == 0 )
                        File_Reading("ifconfig wlan3 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);

	}
	else //tenda
	{
		GetInterfaceName_virtualInterfaceName_2G(virtual_interface_name);
		if(strcmp(virtual_interface_name,"wlan0_0") == 0)
			File_Reading("ifconfig wlan0_0 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
		else if(strcmp(virtual_interface_name,"wlan1_0") == 0)
			File_Reading("ifconfig wlan1_0 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
		else if(strcmp(virtual_interface_name,"wlan2_0") == 0)
			File_Reading("ifconfig wlan2_0 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
		if(strcmp(virtual_interface_name,"wlan0_0") == 0)
			File_Reading("ifconfig wlan0_0 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
		else if(strcmp(virtual_interface_name,"wlan1_0") == 0)
			File_Reading("ifconfig wlan1_0 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
		else if(strcmp(virtual_interface_name,"wlan2_0") == 0)
			File_Reading("ifconfig wlan2_0 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
	}
		output_struct->wifi_ErrorsSent = atol(tx_status);
		output_struct->wifi_ErrorsReceived = atol(rx_status);
	}
	else if(apIndex == 5)//public_wifi with 5G
        {
		GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
                if(strcmp(interface_name,"wlan0") == 0 )
                        File_Reading("ifconfig wlan0 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan1") == 0 )
                        File_Reading("ifconfig wlan1 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan2") == 0 )
                        File_Reading("ifconfig wlan2 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
                else if(strcmp(interface_name,"wlan3") == 0 )
                        File_Reading("ifconfig wlan3 | grep TX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",tx_status);
	
                output_struct->wifi_ErrorsSent = atol(tx_status);

                if(strcmp(interface_name,"wlan0") == 0 )
                        File_Reading("ifconfig wlan0 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan1") == 0 )
                        File_Reading("ifconfig wlan1 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan2") == 0 )
                        File_Reading("ifconfig wlan2 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                else if(strcmp(interface_name,"wlan3") == 0 )
                        File_Reading("ifconfig wlan3 | grep RX | grep packets | tr -s ' ' | cut -d ' ' -f4 | cut -d ':' -f2",rx_status);
                output_struct->wifi_ErrorsReceived = atol(rx_status);
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getSSIDTrafficStats(INT apIndex, wifi_ssidTrafficStats_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	INT status = RETURN_ERR;
	//Below values should get updated from hal 
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_ulong || NULL == output_struct) 
		return RETURN_ERR;
	FILE *fp = NULL;
	char str[FILE_SIZE];
	int wificlientindex = 0 ;
	int count = 0;
	int arr[MACADDRESS_SIZE];
	int signalstrength = 0;
	int arr1[MACADDRESS_SIZE];
	unsigned char mac[MACADDRESS_SIZE];
	unsigned long wifi_count = 0;
	char interface_name[512];
	char virtual_interface_name[512],buf[512];
	if(apIndex == 0)
	{
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		if(strcmp(interface_name,"wlan0") == 0)
			fp = popen("iw dev wlan0 station dump | grep wlan0 | wc -l", "r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep wlan1 | wc -l", "r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep wlan2 | wc -l", "r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep wlan3 | wc -l", "r");
		if (fp == NULL) {
			printf("Failed to run command inside function %s\n",__FUNCTION__ );
			exit(1);
		}
		/* Read the output a line at a time - output it. */
		fgets(str, sizeof(str)-1, fp);
		wifi_count = (unsigned long) atol ( str );
		*output_ulong = wifi_count;
		printf(" In rdkbemu hal ,Wifi Client Counts = %lu\n",*output_ulong);
		pclose(fp);
		wifi_device_t* temp = NULL;
		temp = (wifi_device_t*)malloc(sizeof(wifi_device_t)*wifi_count) ;
		if(temp == NULL)
		{
			return -1;
		}

		if(strcmp(interface_name,"wlan0") == 0)	
			fp = popen("iw dev wlan0 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep Station | cut -d ' ' -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				wificlientindex = 0;
				while(  wificlientindex <= count)
				{
					fgets(str,FILE_SIZE,fp);
					wificlientindex++;
				}

				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr1[0],&arr1[1],&arr1[2],&arr1[3],&arr1[4],&arr1[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr1[wificlientindex];

					}
					memcpy(temp[count].wifi_devMacAddress,mac,(sizeof(unsigned char))*6);
				}
			}
		}
		pclose(fp);
		if(strcmp(interface_name,"wlan0") == 0)
			fp = popen("iw dev wlan0 station dump | grep avg | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_2.4G.txt","r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep avg | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_2.4G.txt","r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep avg | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_2.4G.txt","r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep avg | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_2.4G.txt","r");
		pclose(fp);
		fp = popen("cat /tmp/wifi_signalstrngth_2.4G.txt | tr -s ' ' | cut -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				wificlientindex = 0;
				while(  wificlientindex <= count)
				{
					fgets(str,FILE_SIZE,fp);
					wificlientindex++;
				}
				signalstrength= atoi(str);
				temp[count].wifi_devSignalStrength = signalstrength;
			}
		}
		pclose(fp);
		*output_struct = temp;
	}
	else if(apIndex == 1)
	{
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
		if(strcmp(interface_name,"wlan0") == 0)
			fp = popen("iw dev wlan0 station dump | grep wlan0 | wc -l", "r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep wlan1 | wc -l", "r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep wlan2 | wc -l", "r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep wlan3 | wc -l", "r");
		if (fp == NULL) {
			printf("Failed to run command inside function %s\n",__FUNCTION__ );
			exit(1);
		}
		/* Read the output a line at a time - output it. */
		fgets(str, sizeof(str)-1, fp);
		wifi_count = (unsigned long) atol ( str );
		*output_ulong = wifi_count;
		printf(" In rdkbemu hal ,Wifi Client wlan1 Counts = %lu\n",*output_ulong);
		pclose(fp);
		wifi_device_t* temp = NULL;
		temp = (wifi_device_t*)malloc(sizeof(wifi_device_t)*wifi_count) ;
		if(temp == NULL)
		{
			return -1;
		}
		if(strcmp(interface_name,"wlan0") == 0)
			fp = popen("iw dev wlan0 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep Station | cut -d ' ' -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				wificlientindex = 0;
				while(  wificlientindex <= count)
				{
					fgets(str,FILE_SIZE,fp);
					wificlientindex++;
				}

				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr1[0],&arr1[1],&arr1[2],&arr1[3],&arr1[4],&arr1[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr1[wificlientindex];

					}
					memcpy(temp[count].wifi_devMacAddress,mac,(sizeof(unsigned char))*6);
				}
			}
		}
		pclose(fp);
		if(strcmp(interface_name,"wlan0") == 0)
			fp = popen("iw dev wlan0 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_5G.txt","r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_5G.txt","r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_5G.txt","r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrngth_5G.txt","r");
		pclose(fp);
		fp = popen("cat /tmp/wifi_signalstrngth_5G.txt | tr -s ' ' | cut -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				wificlientindex = 0;
				while(  wificlientindex <= count)
				{
					fgets(str,FILE_SIZE,fp);
					wificlientindex++;
				}
				signalstrength= atoi(str);
				temp[count].wifi_devSignalStrength = signalstrength;
			}
		}
		pclose(fp);
		*output_struct = temp;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

INT wifi_getAssociatedDeviceDetail(INT apIndex, INT devIndex, wifi_device_t *output_struct)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if (NULL == output_struct) {
		return RETURN_ERR;
	} else {
		memset(output_struct, 0, sizeof(wifi_device_t));
		return RETURN_OK;
	}
}

INT wifi_kickAssociatedDevice(INT apIndex, wifi_device_t *device)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
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
	return RETURN_OK;
}     
       
// Outputs the index number in that corresponds to the SSID string
INT wifi_getIndexFromName(CHAR *inputSsidString, INT *output_int)
{
#if 0
	CHAR *pos=NULL;

	*ouput_int = -1;
	pos=strstr(inputSsidString, AP_PREFIX);
	if(pos) {
		sscanf(pos+sizeof(AP_PREFIX),"%d", ouput_int);
		return RETURN_OK;
	} 
	return RETURN_ERR;
#endif
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	INT status = RETURN_ERR;
	INT num_found = 0;

	printf("Invoked: inputSsidString='%s'\n", inputSsidString);

	*output_int = 0;
	if (inputSsidString != NULL)
	{
		num_found = sscanf(inputSsidString, "ath%d", output_int);
		printf("Return: status = %d, ouput_int=%d\n", status, *output_int);
	}

	if(num_found == 1)
	{
		status = RETURN_OK;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return status;
}

// Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i"
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={"beaconType",""};

	if (NULL == output_string)
		return RETURN_ERR;

	wifi_hostapdRead(apIndex,&params,output_string);
	wifi_dbg_printf("\n%s: output_string=%s\n",__func__,output_string);
	if (NULL == output_string)
		return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// Sets the beacon type enviornment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString)
{
	//save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	 struct params params={"beaconType",""};
        char *security_type = NULL;
        param_list_t list;
        if (NULL == beaconTypeString)
                return RETURN_ERR;
        printf("\nbeaconTypeString=%s",beaconTypeString);
        strncpy(params.value,beaconTypeString,strlen(beaconTypeString));
        memset(&list,0,sizeof(list));
        if(RETURN_ERR == list_add_param(&list,params))
        {
                return RETURN_ERR;
        }
        wifi_hostapdWrite(apIndex,&list);
        list_free_param(&list);
        //save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
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

// ouputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptionMode(INT apIndex, CHAR *output_string)
{	
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        struct params beacon={"beaconType",""};
        struct params params={"wpa_pairwise",""};
        char buf[32];

        if (NULL == output_string)
                return RETURN_ERR;

        memset(buf,'\0',32);
        wifi_hostapdRead(apIndex,&beacon,buf);

        if((strcmp(buf,"WPAand11i")==0))
        {
                strcpy(params.name,"rsn_pairwise");
        }
        else if((strcmp(buf,"11i")==0))
        {
                strcpy(params.name,"rsn_pairwise");
        }
        else if((strcmp(buf,"WPA")==0))
        {
                strcpy(params.name,"wpa_pairwise");
        }
        memset(output_string,'\0',32);
        wifi_hostapdRead(apIndex,&params,output_string);
        wifi_dbg_printf("\n%s output_string=%s",__func__,output_string);

        if (strcmp(output_string,"TKIP") == 0)
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
	//Save the encMode to wifi config and hostpad config. wait for wifi restart or hotapd restart to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

	struct params params={'\0'};
        int ret;
        param_list_t list;
        if(encMode ==  NULL)
                return RETURN_ERR;
        memset(&list,0,sizeof(list));
        wifi_dbg_printf("\n%s encMode=%s",__func__,encMode);
        strncpy(params.name,"rsn_pairwise",strlen("rsn_pairwise"));
	        if ( strcmp(encMode, "TKIPEncryption") == 0)
        {
                //strncpy(params.value, "TKIP", strlen("TKIP"));
                strncpy(params.value, "CCMP", strlen("CCMP"));
        } else if ( strcmp(encMode,"AESEncryption") == 0)
        {
                strncpy(params.value, "CCMP", strlen("CCMP"));
        } else if (strcmp(encMode,"TKIPandAESEncryption") == 0)
        {
                strncpy(params.value,"TKIP CCMP",strlen("TKIP CCMP"));
        }
	if(RETURN_ERR == list_add_param(&list,params))
        {
                return RETURN_ERR;
        }
        ret=wifi_hostapdWrite(apIndex,&list);
        list_free_param(&list);
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
//	return RETURN_ERR;
	//save to wifi config, and wait for wifi restart to apply
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        struct params params={'\0'};
        int ret;
        param_list_t list;
        if(authMode ==  NULL)
                return RETURN_ERR;
        memset(&list,0,sizeof(list));
        wifi_dbg_printf("\n%s AuthMode=%s",__func__,authMode);
        strncpy(params.name,"wpa_key_mgmt",strlen("wpa_key_mgmt"));
        if(strcmp(authMode,"PSKAuthentication") == 0)
                strcpy(params.value,"WPA-PSK");
        else if(strcmp(authMode,"EAPAuthentication") == 0)
                strcpy(params.value,"WPA-EAP");
        else if(strcmp(authMode,"None") == 0) //Donot change in case the authMode is None
                return RETURN_OK;                         //This is taken careof in beaconType
        if(RETURN_ERR == list_add_param(&list,params))
        {
                return RETURN_ERR;
        }
        ret=wifi_hostapdWrite(apIndex,&list);
        list_free_param(&list);
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return ret;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_getApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
        //save to wifi config, and wait for wifi restart to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        struct params params={"wpa_key_mgmt",""};
        char AuthenticationMode[50] = {0};
        int wpa_val;
        char BeaconType[50] = {0};

        if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
        {
                wifi_getApBeaconType(apIndex,BeaconType);
                printf("%s____%s \n",__FUNCTION__,BeaconType);
                if(strcmp(BeaconType,"None") == 0)
                        strcpy(authMode,"None");
                else
                {
                        wifi_hostapdRead(apIndex,&params,authMode);
                        wifi_dbg_printf("\n[%s]: AuthMode Name is : %s",__func__,authMode);
                        if(authMode==NULL)
                                return RETURN_ERR;
                        else
                        {
                                if(strcmp(authMode,"WPA-PSK") == 0)
                                        strcpy(authMode,"SharedAuthentication");
                                else if(strcmp(authMode,"WPA-EAP") == 0)
                                        strcpy(authMode,"EAPAuthentication");
                        }
                }
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}


// Outputs the number of stations associated per AP
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[128]={0};
	char buf[128]={0};
		
	sprintf(cmd, "wlanconfig %s%d list sta | grep -v HTCAP | wc -l", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));
	sscanf(buf,"%lu", output_ulong);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// manually removes any active wi-fi association with the device specified on this ap
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac) 	
{
	return RETURN_ERR;
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
	snprintf(macArray, buf_size, "11:22:33:44:55:66\n11:22:33:44:55:67\n");		
	return RETURN_OK;
}
	
// Get the list of stations assocated per AP
INT wifi_getApDevicesAssociated(INT apIndex, CHAR *macArray, UINT buf_size) 
{
	char cmd[128];
		
	sprintf(cmd, "wlanconfig %s%d list sta | grep -v HTCAP | cut -d' ' -f1", AP_PREFIX, apIndex);
	_syscmd(cmd, macArray, buf_size);
		
	return RETURN_OK;
}

// adds the mac address to the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress) 
{
	//Apply instantly		
	return RETURN_ERR;
}

// deletes the mac address from the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)        
{
	//Apply instantly
	return RETURN_ERR;
}

// outputs the number of devices in the filter list
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint)   
{
	if (NULL == output_uint) 
		return RETURN_ERR;
	*output_uint=0;
	return RETURN_ERR;   
}

// enable kick for devices on acl black list    
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable)    
{
	char aclArray[512]={0}, *acl=NULL;
	char assocArray[512]={0}, *asso=NULL;
	
	wifi_getApAclDevices( apIndex, aclArray, sizeof(aclArray));
    wifi_getApDevicesAssociated( apIndex, assocArray, sizeof(assocArray));

	// if there are no devices connected there is nothing to do
    if (strlen(assocArray) < 17) {
        return RETURN_OK;
    }
   
    if ( enable == TRUE ) {
		//kick off the MAC which is in ACL array (deny list)
		acl = strtok (aclArray,"\r\n");
		while (acl != NULL) {
			if(strlen(acl)>=17 && strcasestr(assocArray, acl)) {
				wifi_kickApAssociatedDevice(apIndex, acl); 
			}
			acl = strtok (NULL, "\r\n");
		}
    } else {
		//kick off the MAC which is not in ACL array (allow list)
		asso = strtok (assocArray,"\r\n");
		while (asso != NULL) {
			if(strlen(asso)>=17 && !strcasestr(aclArray, asso)) {
				wifi_kickApAssociatedDevice(apIndex, asso); 
			}
			asso = strtok (NULL, "\r\n");
		}
	}	    

    return RETURN_OK;
}

// sets the mac address filter control mode.  0 == filter disabled, 1 == filter as whitelist, 2 == filter as blacklist
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
	//apply instantly
	return RETURN_ERR;
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
	snprintf(bridgeName, 32, "br0");
	snprintf(IP, 64, "10.0.0.2");
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	defaultwifi_restarting_process();
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

 // stops hostapd	
INT wifi_stopHostApd()                                        
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        system("killall hostapd");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;	
}
// sets the AP enable status variable for the specified ap.
INT wifi_setApEnable(INT apIndex, BOOL enable)
{
	//Store the AP enable settings and wait for wifi up to apply
#if 1//LNT_EMU
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	int line_no;//ssid line number in /etc/hostapd.conf
	BOOL GetRadioEnable;
	char buf[50] = {0},command[50] ={0};
	//For Getting Radio Status
	wifi_getRadioEnable(apIndex,&GetRadioEnable);
	if(apIndex == 0)
	{
		sprintf(buf,"%s%d%s","echo ",GetRadioEnable," > /tmp/Get2gRadioEnable.txt");
		system("rm /tmp/Get2gssidEnable.txt");
		sprintf(command,"%s%d%s","echo ",enable," > /tmp/Get2gssidEnable.txt");
		system(buf);
	}
	else if(apIndex == 1)
	{
		sprintf(buf,"%s%d%s","echo ",GetRadioEnable," > /tmp/Get5gRadioEnable.txt");
		system("rm /tmp/Get5gssidEnable.txt");
		sprintf(command,"%s%d%s","echo ",enable," > /tmp/Get5gssidEnable.txt");
		system(buf);
	}
	else if(apIndex == 4)
	{
		system("rm /tmp/GetPub2gssidEnable.txt");
		sprintf(command,"%s%d%s","echo ",enable," > /tmp/GetPub2gssidEnable.txt");
	}
	else if(apIndex == 5)
	{
		system("rm /tmp/GetPub5gssidEnable.txt");
		sprintf(command,"%s%d%s","echo ",enable," > /tmp/GetPub5gssidEnable.txt");
	}
	system(command);

	if((apIndex == 0) || (apIndex == 4) || (apIndex == 1) || (apIndex == 5))
	{
		if(enable == false) 
			DisableWifi(apIndex);
		else
		{
			if((apIndex == 4) || (apIndex == 5))
				wifi_applyRadioSettings(apIndex);
		}
	}

	if((apIndex == 0) || (apIndex == 1))
	{
		if((GetRadioEnable == true) && (enable == true))
			wifi_applyRadioSettings(apIndex);
	}

#endif
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	//return RETURN_ERR;
	return RETURN_OK;
}     
// Outputs the setting of the internal variable that is set by wifi_setEnable().  
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
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
		if(apIndex == 4)
		{
			sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
			if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
			{
				return RETURN_ERR;
			}
			if(buf[0] == '#')//tp-link
				GetInterfaceName(IfName,"/nvram/hostapd4.conf");
			else //tenda
				GetInterfaceName_virtualInterfaceName_2G(IfName);
		}	
		if (NULL == output_bool)
                {
                        return RETURN_ERR;
                } else {
                        sprintf(cmd,"%s%s%s","ifconfig ",IfName," | grep RUNNING | tr -s ' ' | cut -d ' ' -f4");
                        _syscmd(cmd,buf,sizeof(buf));
                        if(strlen(buf)>0)
                        {
                                *output_bool=1;
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
				printf("tmp_status of %s and %d %s \n",tmp_status,apIndex,__FUNCTION__);
                                if(strcmp(tmp_status,"0") == 0)
                                        *output_bool = 0;
                                else
                                        *output_bool = 1;
				WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
                                return RETURN_OK;
                        }
                }
        }
	else
	{
		if((apIndex > 5) && (apIndex < 17))
			return RETURN_ERR;
		else
		        return RETURN_OK;
	}
}
 
// Outputs the AP "Enabled" "Disabled" status from driver 
INT wifi_getApStatus(INT apIndex, CHAR *output_string) 
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
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
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}

//Indicates whether or not beacons include the SSID name.
// outputs a 1 if SSID on the AP is enabled, else ouputs 0
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output_bool) 
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//get the running status
        char output[128] = {0};
        if(!output_bool)
                return RETURN_ERR;
        if((apIndex == 0) || (apIndex == 1))
        {
        struct params params={"ignore_broadcast_ssid",""};
        wifi_hostapdRead(apIndex,&params,output);
        wifi_dbg_printf("\n[%s]: ignore_broadcast_ssid Name is : %s",__func__,output);
        if(output==NULL)
                return RETURN_ERR;
        else
        {
                if(strcmp(output,"1") == 0)
                        *output_bool=FALSE;
                else
                        *output_bool=TRUE;
        }
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}

// sets an internal variable for ssid advertisement.  Set to 1 to enable, set to 0 to disable
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable) 
{
	//store the config, apply instantly
	//store the config, apply instantly
        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        char str[MAX_BUF_SIZE]={'\0'};
        char string[MAX_BUF_SIZE]={'\0'};
        char cmd[MAX_CMD_SIZE]={'\0'};
        char *ch;
        struct params params;
        param_list_t list;

        if(enable == TRUE)
                strcpy(string,"0");
        else
                strcpy(string,"1");

        strcpy(params.name,"ignore_broadcast_ssid");
        strcpy(params.value,string);
        printf("\n%s\n",__func__);
        memset(&list,0,sizeof(list));
        if(RETURN_ERR == list_add_param(&list,params))
        {
                return RETURN_ERR;
        }
        wifi_hostapdWrite(apIndex,&list);
        list_free_param(&list);
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
}

//The maximum number of retransmission for a packet. This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
INT wifi_getApRetryLimit(INT apIndex, UINT *output_uint)
{
	//get the running status
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!output_uint)
		return RETURN_ERR;
	*output_uint=15;	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;	
}

INT wifi_setApRetryLimit(INT apIndex, UINT number)
{
	//apply instantly
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	return RETURN_ERR;
}

//Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
INT wifi_getApWMMCapability(INT apIndex, BOOL *output)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!output)
		return RETURN_ERR;
	*output=TRUE;	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
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

//Enables or disables device isolation.	A value of true means that the devices connected to the Access Point are isolated from all other devices within the home network (as is typically the case for a Wireless Hotspot).	
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if(!output)
		return RETURN_ERR;
	*output=TRUE;	
	return RETURN_OK;
}
	
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
	//store the config, apply instantly
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!output)
		return RETURN_ERR;
	snprintf(output, 128, "None,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}		

//The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!output)
		return RETURN_ERR;
	//snprintf(output, 128, "WPA-WPA2-Personal");
	FILE *fp = NULL;
	char path[256] = {0},securitymode[256] = {0},output_string[50] = {0};
	int count = 0;
	char *SecurityMode;
	if(apIndex == 0)
		fp = popen("cat /nvram/hostapd0.conf | grep wpa=","r");
	else if(apIndex == 1)
		fp = popen("cat /nvram/hostapd1.conf | grep wpa=","r");
	if(fp == NULL)
	{
		printf("Command not Found ,%s\n",__FUNCTION__);
		return RETURN_ERR;
	}
	fgets(path, sizeof(path)-1, fp);
	if (path[0] == '#')
		strcpy(output,"None");
	else
	{
	SecurityMode = strchr(path,'=');
	strcpy(securitymode,SecurityMode+1);
	for(count=0;securitymode[count]!='\n';count++)
		output_string[count] = securitymode[count];
	output_string[count]='\0';
	pclose(fp);
	if(strcmp(output_string,"1") == 0)
		strcpy(output,"WPA-Personal");
	else if(strcmp(output_string,"2") == 0)
		strcpy(output,"WPA2-Personal");
	else if(strcmp(output_string,"3") == 0)
		strcpy(output,"WPA-WPA2-Personal");
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
  
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//store settings and wait for wifi up to apply
	//return RETURN_ERR;
	#if 1//LNT_EMU
        char buf[WORD_SIZE];
        char path[1024],security_mode[150],WEP_mode[512],wep_mode[512],security_mode_5g[512];
        int count = 0;
        FILE *fp = NULL;

        //For WPA-PSK  - 2.4Ghz
        if((strcmp(encMode,"WPA-Personal")==0) || (strcmp(encMode,"WPA2-Personal")==0) || (strcmp(encMode,"WPA-WPA2-Personal")==0) || (strcmp(encMode,"None")==0))
        {
        fp = popen("cat /nvram/hostapd0.conf | grep -w wpa | tail -1", "r");
        if (fp == NULL) {
                printf("Failed to run command in function %s\n",__FUNCTION__);
                return;
        }
        fgets(path, sizeof(path)-1, fp);
        for(count = 0;path[count]!='\n';count++)
                security_mode[count] = path[count];
        security_mode[count]='\0';
        pclose(fp);
        }

        //For WPA-PSK  - 5Ghz
        if((strcmp(encMode,"WPA-Personal")==0) || (strcmp(encMode,"WPA2-Personal")==0) || (strcmp(encMode,"WPA-WPA2-Personal")==0) ||(strcmp(encMode,"None")==0))
        {
        fp = popen("cat /nvram/hostapd1.conf | grep -w wpa | tail -1", "r");
        if (fp == NULL) {
                printf("Failed to run command in function %s\n",__FUNCTION__);
                return;
        }
        fgets(path, sizeof(path)-1, fp);
        for(count = 0;path[count]!='\n';count++)
                security_mode_5g[count] = path[count];
        security_mode_5g[count]='\0';
        pclose(fp);
        }


        if((strcmp(encMode,"WEP-64")==0) || (strcmp(encMode,"WEP-128")==0))
        {
        //For WEP Mode - 2.4Ghz
        fp = popen("cat /nvram/hostapd0.conf | grep -w wep_key_len_broadcast", "r");
        if (fp == NULL) {
			printf("Failed to run command in function %s\n",__FUNCTION__);
                return;
        }
        fgets(path, sizeof(path)-1, fp);
        for(count = 0;path[count]!='\n';count++)
                WEP_mode[count] = path[count];
        WEP_mode[count]='\0';
        pclose(fp);
        }

        if((strcmp(encMode,"WEP-64")==0) || (strcmp(encMode,"WEP-128")==0))
        {
        //For WEP Mode - 2.4Ghz
        fp = popen("cat /nvram/hostapd0.conf | grep -w wep_key_len_unicast", "r");
        if (fp == NULL) {
                printf("Failed to run command in function %s\n",__FUNCTION__);
                return;
        }
        fgets(path, sizeof(path)-1, fp);
        for(count = 0;path[count]!='\n';count++)
                wep_mode[count] = path[count];
        wep_mode[count]='\0';
        pclose(fp);
        }


        if(apIndex == 0)//private_wifi with 2.4G
        {
        if(strcmp(encMode,"None")==0)
        {
                sprintf(buf,"%s%c%c%s%s%s%c %s","sed -i ",'"','/',security_mode,"/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
       /*       sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_default_key=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key0=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_broadcast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_unicast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_rekey_period=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);*/
        }
        else if(strcmp(encMode,"WPA-Personal")==0)
	{

                sprintf(buf,"%s%c%s%s%s%c %s","sed -i -e ",'"',"s/",security_mode,"/wpa=1/g",'"',"/nvram/hostapd0.conf");//sed -i -e "s/wpa=2/wpa=1/g" /etc/hostapd.conf
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
        /*      sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_default_key=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key0=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_broadcast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_unicast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_rekey_period=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);*/

        }
        else if(strcmp(encMode,"WPA2-Personal")==0)
        {
                sprintf(buf,"%s%c%s%s%s%c %s","sed -i -e ",'"',"s/",security_mode,"/wpa=2/g",'"',"/nvram/hostapd0.conf");//sed -i -e "s/wpa=2/wpa=1/g" /etc/hostapd.conf
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
        /*      sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_default_key=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key0=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_broadcast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_unicast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_rekey_period=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);*/

        }
        else if(strcmp(encMode,"WPA-WPA2-Personal")==0)
        {
		sprintf(buf,"%s%c%s%s%s%c %s","sed -i -e ",'"',"s/",security_mode,"/wpa=3/g",'"',"/nvram/hostapd0.conf");//sed -i -e "s/wpa=2/wpa=1/g" /etc/hostapd.conf
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
        /*      sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_default_key=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key0=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_broadcast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_key_len_unicast=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wep_rekey_period=/ s/^/","#/",'"',"/etc/hostapd_2.4G.conf");
                system(buf);*/

        }
        else if(strcmp(encMode,"WEP-64")==0)
        {
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wep_default_key=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wep_key0=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%s%s","sed -i -e 's/",WEP_mode,"/wep_key_len_broadcast=\"5\"/g' /nvram/hostapd0.conf");//sed -i -e 's/wep_key_len_broadcast=\"5\"/wep_key_len_broadcast=\"10\"/g' /etc/hostapd_2.4G.conf
                system(buf);
                sprintf(buf,"%s%s%s","sed -i -e 's/",wep_mode,"/wep_key_len_unicast=\"5\"/g' /nvram/hostapd0.conf");//sed -i -e 's/wep_key_len_broadcast=\"5\"/wep_key_len_broadcast=\"10\"/g' /etc/hostapd_2.4G.conf
                printf(" Buffer %s \n",buf);
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wep_rekey_period=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa=2/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
        }
        else if(strcmp(encMode,"WEP-128")==0)
	{

                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wep_default_key=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wep_key0=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%s%s","sed -i -e 's/",WEP_mode,"/wep_key_len_broadcast=\"10\"/g' /nvram/hostapd0.conf");//sed -i -e 's/wep_key_len_broadcast=\"5\"/wep_key_len_broadcast=\"10\"/g' /etc/hostapd_2.4G.conf
                system(buf);
                sprintf(buf,"%s%s%s","sed -i -e 's/",wep_mode,"/wep_key_len_unicast=\"10\"/g' /nvram/hostapd0.conf");//sed -i -e 's/wep_key_len_broadcast=\"5\"/wep_key_len_broadcast=\"10\"/g' /etc/hostapd_2.4G.conf
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wep_rekey_period=/ s/^#*//",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa=2/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^/","#/",'"',"/nvram/hostapd0.conf");
                system(buf);
        }
        //KillHostapd();
        }
        else if(apIndex == 1) //private_wifi with 5G
        {
        if(strcmp(encMode,"None")==0)
        {
                sprintf(buf,"%s%c%c%s%s%s%c %s","sed -i ",'"','/',security_mode_5g,"/ s/^/","#/",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^/","#/",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^/","#/",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^/","#/",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^/","#/",'"',"/nvram/hostapd1.conf");
                system(buf);
        }
        else if(strcmp(encMode,"WPA-Personal")==0)
        {

                sprintf(buf,"%s%c%s%s%s%c %s","sed -i -e ",'"',"s/",security_mode_5g,"/wpa=1/g",'"',"/nvram/hostapd1.conf");//sed -i -e "s/wpa=2/wpa=1/g" /etc/hostapd.conf
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
        }
         else if(strcmp(encMode,"WPA2-Personal")==0)
        {
                sprintf(buf,"%s%c%s%s%s%c %s","sed -i -e ",'"',"s/",security_mode_5g,"/wpa=2/g",'"',"/nvram/hostapd1.conf");//sed -i -e "s/wpa=2/wpa=1/g" /etc/hostapd.conf
                system(buf);
		sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
        }
        else if(strcmp(encMode,"WPA-WPA2-Personal")==0)
        {
                sprintf(buf,"%s%c%s%s%s%c %s","sed -i -e ",'"',"s/",security_mode_5g,"/wpa=3/g",'"',"/nvram/hostapd1.conf");//sed -i -e "s/wpa=2/wpa=1/g" /etc/hostapd.conf
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_passphrase=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_key_mgmt=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wpa_pairwise=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
                sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/rsn_pairwise=/ s/^#*//",'"',"/nvram/hostapd1.conf");
                system(buf);
        }
        }
	hostapd_restarting_process(apIndex);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        return RETURN_OK;
#endif

}   


//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
// output_string must be pre-allocated as 64 character string by caller
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string)
{	
#if 0//LNT_EMU
	snprintf(output_string, 64, "E4A7A43C99DFFA57");
	return RETURN_OK;
#endif
#if 1//RDKB_EMU
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!output_string)
		return RETURN_ERR;
	char path[FILE_SIZE] = {0},output_pwd[FILE_SIZE] = {0};
        FILE *fp = NULL;
        char *password;
	int count = 0;
	if(apIndex == 0 ) 
	{
        fp = popen("cat /nvram/hostapd0.conf | grep -w wpa_passphrase ", "r");
        if (fp == NULL) {
                printf("Failed to run command inside function %s\n",__FUNCTION__ );
		return -1;
        }
        fgets(path, sizeof(path)-1, fp);
        if(path[0] != '#')
        {
                password = strchr(path,'=');
                strcpy(output_pwd,password+1);
		for(count = 0;output_pwd[count]!='\n';count++)
                        output_string[count] = output_pwd[count];
                output_string[count]='\0';
        }
        else
        {
                strcpy(output_string,"");
        }
        pclose(fp);
	}
	else if(apIndex == 1 )
        {
        fp = popen("cat /nvram/hostapd1.conf | grep -w wpa_passphrase ", "r");
        if (fp == NULL) {
                printf("Failed to run command inside function %s\n",__FUNCTION__ );
                return -1;
        }
        fgets(path, sizeof(path)-1, fp);
        if(path[0] != '#')
        {
                password = strchr(path,'=');
                strcpy(output_pwd,password+1);
		for(count = 0;output_pwd[count]!='\n';count++)
                        output_string[count] = output_pwd[count];
                output_string[count]='\0';
        }
        else
        {
                strcpy(output_string,"");
        }
        pclose(fp);
        }
	else if((apIndex == 4 ) || (apIndex == 5 ))
			strcpy(output_string,"");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
#endif
}

// sets an enviornment variable for the psk. Input string preSharedKey must be a maximum of 64 characters
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey)        
{	
	//save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
	//return RETURN_ERR;//LNT_EMU
	//save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        struct params params={'\0'};
        int ret;
        param_list_t list;

        if(NULL == preSharedKey)
            return RETURN_ERR;
        strcpy(params.name,"wpa_passphrase");
        strcpy(params.value,preSharedKey);
        if(strlen(preSharedKey)<8 || strlen(preSharedKey)>63)
        {
                wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
                return RETURN_ERR;
        }
        else
        {
                memset(&list,0,sizeof(list));
                if(RETURN_ERR == list_add_param(&list,params))
                {
                        return RETURN_ERR;
                }
                ret=wifi_hostapdWrite(apIndex,&list);
                list_free_param(&list);
                return ret;
        }
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
// outputs the passphrase, maximum 63 characters
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	struct params params={"wpa_passphrase",""};
	wifi_dbg_printf("\nFunc=%s\n",__func__);
	if (NULL == output_string)
		return RETURN_ERR;
	wifi_hostapdRead(apIndex,&params,output_string);
	wifi_dbg_printf("\noutput_string=%s\n",output_string);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	if(output_string==NULL)
		return RETURN_ERR;
	else
		return RETURN_OK;
}

// sets the passphrase enviornment variable, max 63 characters
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase)
{	
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	//save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
	struct params params={'\0'};
        int ret;
        param_list_t list;

        if(NULL == passPhrase)
            return RETURN_ERR;
        strcpy(params.name,"wpa_passphrase");
        strcpy(params.value,passPhrase);
        if(strlen(passPhrase)<8 || strlen(passPhrase)>63)
        {
                wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
                return RETURN_ERR;
        }
        else
        {
                memset(&list,0,sizeof(list));
                if(RETURN_ERR == list_add_param(&list,params))
                {
                        return RETURN_ERR;
                }
                ret=wifi_hostapdWrite(apIndex,&list);
                list_free_param(&list);
                return ret;
        }
	hostapd_restarting_process(apIndex);	
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!IP_output || !Port_output || !RadiusSecret_output)
		return RETURN_ERR;
	snprintf(IP_output, 64, "75.56.77.78");
	*Port_output=123;
	snprintf(RadiusSecret_output, 64, "12345678");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[128] = {0};
	char interface_name[64] = {0};
        char Hconf[64] = {0};
        char cmd[128] = {0};
	if(!output_bool)
		return RETURN_ERR;
	//*output_bool=TRUE;
	if((apIndex == 0) || (apIndex == 1))
	{
	if(apIndex == 0)
	{
	       GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
               strcpy(Hconf,"/nvram/hostapd0.conf");
	}
	else if(apIndex == 1)
	{
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
                strcpy(Hconf,"/nvram/hostapd1.conf");
	}
	else
	{
		printf(" Invalid apIndex Value \n");
	}
	sprintf(cmd,"%s%s%s","cat ",Hconf," | grep wps_state | cut -d '=' -f1");
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
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}        

// sets the WPS enable enviornment variable for this ap to the value of enableValue, 1==enabled, 0==disabled     
INT wifi_setApWpsEnable(INT apIndex, BOOL enableValue)
{
	//store the paramters, and wait for wifi up to apply
	//return RETURN_ERR;
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[256] = {0};
	char interface_name[128] = {0};
	char Hconf[128] = {0};
	//store the paramters, and wait for wifi up to apply
	if((apIndex == 0) || (apIndex == 1))
	{
		if(apIndex == 0)
		{
			GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
			strcpy(Hconf,"/nvram/hostapd0.conf");
		}
		else if(apIndex == 1)
		{
			GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
			strcpy(Hconf,"/nvram/hostapd1.conf");
		}
		if(enableValue == FALSE)
		{
			sprintf(buf,"%s%c%s%s%c %s","sed -i ",'"',"/wps_state=2/ s/^/","#/",'"',Hconf);
		}
		else
		{
			sprintf(buf,"%s%c%s%c %s","sed -i ",'"',"/wps_state=2/ s/^#*//",'"',Hconf);
		}
		system(buf);
		wifi_applyRadioSettings(apIndex);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}        

//Comma-separated list of strings. Indicates WPS configuration methods supported by the device. Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	if(!output)
		return RETURN_ERR;
	snprintf(output, 128, "PushButton,Label,Display,Keypad");
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}			

//Comma-separated list of strings. Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter. Indicates WPS configuration methods enabled on the device.
// Outputs a common separated list of the enabled WPS config methods, 64 bytes max
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[128] = {0};
	char cmd[256] = {0};
	char interface_name[64] ={0};
	char Hconf[64] ={0};
	if(!output)
		return RETURN_ERR;
	//snprintf(output, 128, "PushButton,PIN");
	if((apIndex == 0) || (apIndex == 1))
	{
		if(apIndex == 0)
		{
			GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
			strcpy(Hconf,"/nvram/hostapd0.conf");
		}
		else if(apIndex == 1)
		{
			GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
			strcpy(Hconf,"/nvram/hostapd1.conf");
		}
		sprintf(cmd,"%s%s%s","cat ",Hconf," | grep config_methods | cut -d '=' -f2 | sed 's/ /,/g' | sed 's/,$/ /g'");
		_syscmd(cmd,buf, sizeof(buf));
		if(strlen(buf) > 0)
		{
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
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// sets an enviornment variable that specifies the WPS configuration method(s).  methodString is a comma separated list of methods USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString)
{
	//apply instantly. No setting need to be stored. 
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[128] = {0};
	char cmd[256] = {0};
	char Hconf[64] = {0};
	char local_config_methods[128] = {0};
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
		if(apIndex == 0)
		{
			strcpy(Hconf,"/nvram/hostapd0.conf");
		}
		else if(apIndex == 1)
		{
			strcpy(Hconf,"/nvram/hostapd1.conf");
		}
		sprintf(buf,"sed -i '/config_methods=/d' %s",Hconf);
		sleep(2);
		system(buf);
		if(strcmp(local_config_methods,"push_button") == 0)
			sprintf(buf,"echo config_methods=%s >> %s",local_config_methods,Hconf);
		else if(strcmp(local_config_methods,"keypad label display") == 0)
			sprintf(buf,"echo config_methods=%s >> %s",local_config_methods,Hconf);
		else if(strcmp(local_config_methods,"push_button keypad label display") == 0)
			sprintf(buf,"echo config_methods=%s >> %s",local_config_methods,Hconf);
		system(buf);
		wifi_applyRadioSettings(apIndex);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
	//return RETURN_ERR;
}

// outputs the pin value, ulong_pin must be allocated by the caller
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[128] = {0};
	char cmd[256] = {0};
	char Hconf[64] = {0};
	if(!output_ulong)
		return RETURN_ERR;
	if((apIndex == 0) || (apIndex == 1))
	{
		if(apIndex == 0)
		{
			strcpy(Hconf,"/nvram/hostapd0.conf");
		}
		else if(apIndex == 1)
		{
			strcpy(Hconf,"/nvram/hostapd1.conf");
		}
		sprintf(cmd,"%s%s%s","cat ",Hconf," | grep ap_pin | cut -d '=' -f2");
		_syscmd(cmd,buf, sizeof(buf));
		if(strlen(buf) > 0)
			*output_ulong=atoi(buf);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// set an enviornment variable for the WPS pin for the selected AP. Normally, Device PIN should not be changed.
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char buf[128] ={0};
	char Hconf[64] = {0};
	char ap_pin[128] = {0};
	//set the pin to wifi config and hostpad config. wait for wifi reset or hostapd reset to apply 
	ULONG prev_pin = 0;
        sprintf(ap_pin, "%ld", pin);
        wifi_getApWpsDevicePIN(apIndex,&prev_pin);
	if((apIndex == 0) || (apIndex == 1))
	{
	if(apIndex == 0)
	{
		strcpy(Hconf,"hostapd0.conf");
	}
	else if(apIndex == 1)
	{
		strcpy(Hconf,"hostapd1.conf");
	}
	sprintf(buf,"%s%ld%s%ld%s%s","sed -i 's/ap_pin=",prev_pin,"/ap_pin=",pin,"/g' /nvram/",Hconf);
	system(buf);
	wifi_applyRadioSettings(apIndex);
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
	//return RETURN_ERR;
}    

// Output string is either Not configured or Configured, max 32 characters
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[64];
	char buf[512]={0};
	char interface_name[64] = {0};
	char *pos=NULL;

	snprintf(output_string, 64, "Not configured");
	if((apIndex == 0) || (apIndex == 1))
	{
	if(apIndex == 0)
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	else if(apIndex == 1)
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
	sprintf(cmd, "hostapd_cli -i %s get_config",interface_name);
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
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[64];
	char buf[256]={0};
	char interface_name[64] = {0};
	BOOL enable;
	if((apIndex == 0) || (apIndex == 1))
	{
	wifi_getApEnable(apIndex, &enable);
	if (!enable) 
	{
		return RETURN_ERR; 
	}

	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable) 
	{
		return RETURN_ERR; 
	}
	if(apIndex == 0)
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	else if(apIndex == 1)
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
	snprintf(cmd, 64, "hostapd_cli -i%s wps_pin any %s", interface_name,pin);
	_syscmd(cmd,buf, sizeof(buf));
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	if((strstr(buf, "OK"))!=NULL) 
		return RETURN_OK;
	else
		return RETURN_ERR;
	}
}

INT SetWPSButton(char *interface_name)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[256] = {0};
	char buf[256] = {0};
	snprintf(cmd, 64, "hostapd_cli -i%s wps_pbc",interface_name);
        _syscmd(cmd,buf, sizeof(buf));
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
        if((strstr(buf, "OK"))!=NULL)
                return RETURN_OK;
        else
                return RETURN_ERR;
}
// This function is called when the WPS push button has been pressed for this AP
INT wifi_setApWpsButtonPush(INT apIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[64];
	char buf[256]={0};
	char interface_name[64] = {0},ifname[64] = {0};
	BOOL WPS_FLAG_2g = FALSE,WPS_FLAG_5g = FALSE;
	BOOL enable;

	if((apIndex == 0) || (apIndex == 1))  //private-wifi 2g /5g
	{
	wifi_getApEnable(apIndex, &enable);
	if (!enable) 
		return RETURN_ERR; 

	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable) 
		return RETURN_ERR; 

	if(apIndex == 0)
	{
                GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
		WPS_FLAG_2g = TRUE;
		WPS_FLAG_5g = FALSE;
	}
        else if(apIndex == 1)
	{
                GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
		WPS_FLAG_5g = TRUE;
		WPS_FLAG_2g = FALSE;
	}


	if(( WPS_FLAG_2g == TRUE ) && (WPS_FLAG_5g == FALSE))
	{
		SetWPSButton(interface_name);
		WPSSessionStarted = TRUE;		
	}
        if(( WPS_FLAG_5g == TRUE ) && (WPS_FLAG_2g == FALSE))
        {
		#if 0
		GetInterfaceName(ifname,"/nvram/hostapd0.conf");	
		snprintf(cmd, 64, "hostapd_cli -i%s wps_cancel",ifname);
		system(cmd);
		sleep(2);
		#endif
		SetWPSButton(interface_name);
		if(WPSSessionStarted == TRUE)
		{
			snprintf(cmd, 64, "hostapd_cli -i%s wps_cancel",interface_name);
			system(cmd);
			WPSSessionStarted = FALSE;
		}
        }
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}

// cancels WPS mode for this AP
INT wifi_cancelApWPS(INT apIndex)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	char cmd[64];
	char buf[256]={0};
	char interface_name[64] = {0};
	if((apIndex == 0) || (apIndex == 1))
        {
	if(apIndex == 0)
		GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	else if(apIndex == 1)
		GetInterfaceName(interface_name,"/nvram/hostapd1.conf");

	snprintf(cmd, 64, "hostapd_cli -i%s wps_cancel",interface_name);
	_syscmd(cmd,buf, sizeof(buf));
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	if((strstr(buf, "OK"))!=NULL) 
		return RETURN_OK;
	else
		return RETURN_ERR;
	}
}                                 

INT wifihal_AssociatedDevicesstats(INT apIndex,CHAR *interface_name,wifi_associated_dev_t **associated_dev_array, UINT *output_array_size)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
	char str[FILE_SIZE];
	int wificlientindex = 0 ;
	int count = 0;
	int arr[MACADDRESS_SIZE];
	int signalstrength = 0;
	int arr1[MACADDRESS_SIZE];
	unsigned char mac[MACADDRESS_SIZE];
	UINT wifi_count = 0;
	char virtual_interface_name[512],buf[512];
	if(strcmp(interface_name,"wlan0") == 0)
		fp = popen("iw dev wlan0 station dump | grep wlan0 | wc -l", "r");
	else if(strcmp(interface_name,"wlan1") == 0)
		fp = popen("iw dev wlan1 station dump | grep wlan1 | wc -l", "r");
	else if(strcmp(interface_name,"wlan0_0") == 0)
		fp = popen("iw dev wlan0_0 station dump | grep wlan0_0 | wc -l", "r");
	else if(strcmp(interface_name,"wlan1_0") == 0)
		fp = popen("iw dev wlan1_0 station dump | grep wlan1_0 | wc -l", "r");
	else if(strcmp(interface_name,"wlan2_0") == 0)
		fp = popen("iw dev wlan2_0 station dump | grep wlan2_0 | wc -l", "r");
	else if(strcmp(interface_name,"wlan2") == 0)
		fp = popen("iw dev wlan2 station dump | grep wlan2 | wc -l", "r");
	else if(strcmp(interface_name,"wlan3") == 0)
		fp = popen("iw dev wlan3 station dump | grep wlan3 | wc -l", "r");
	if (fp == NULL) {
		printf("Failed to run command inside function %s\n",__FUNCTION__ );
		exit(1);
	}
	/* Read the output a line at a time - output it. */
	fgets(str, sizeof(str)-1, fp);
	wifi_count = (unsigned int) atoi ( str );
	*output_array_size = wifi_count;
	printf(" In rdkbemu hal ,Wifi Client Counts and index %d and  %d\n",*output_array_size,apIndex);
	pclose(fp);
	if(wifi_count == 0)
	{
		wifi_associated_dev_t* temp = NULL;
		return RETURN_OK;
	}
	else
	{
		wifi_associated_dev_t* temp = NULL;
		temp = (wifi_associated_dev_t*)malloc(sizeof(wifi_associated_dev_t)*wifi_count) ;
		if(temp == NULL)
		{
			printf("Error Statement \n");
			return -1;
		}


		if(strcmp(interface_name,"wlan0") == 0)
			fp = popen("iw dev wlan0 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan0_0") == 0)
			fp = popen("iw dev wlan0_0 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan1_0") == 0)
			fp = popen("iw dev wlan1_0 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan2_0") == 0)
			fp = popen("iw dev wlan2_0 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep Station | cut -d ' ' -f 2","r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep Station | cut -d ' ' -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				wificlientindex = 0;
				while(  wificlientindex <= count)
				{
					fgets(str,FILE_SIZE,fp);
					wificlientindex++;
				}
				if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr1[0],&arr1[1],&arr1[2],&arr1[3],&arr1[4],&arr1[5]) )
				{
					for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
					{
						mac[wificlientindex] = (unsigned char) arr1[wificlientindex];

					}
					memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
				}
			}
		}
		pclose(fp);
		if(strcmp(interface_name,"wlan0") == 0)
			fp = popen("iw dev wlan0 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt","r");
		else if(strcmp(interface_name,"wlan1") == 0)
			fp = popen("iw dev wlan1 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt","r");
		else if(strcmp(interface_name,"wlan0_0") == 0)
			fp = popen("iw dev wlan0_0 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt","r");
		else if(strcmp(interface_name,"wlan1_0") == 0)
			fp = popen("iw dev wlan1_0 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt","r");
		else if(strcmp(interface_name,"wlan2_0") == 0)
			fp = popen("iw dev wlan2_0 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt","r");
		else if(strcmp(interface_name,"wlan2") == 0)
			fp = popen("iw dev wlan2 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt","r");
		else if(strcmp(interface_name,"wlan3") == 0)
			fp = popen("iw dev wlan3 station dump | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt","r");
		pclose(fp);
		fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
		if(fp)
		{
			for(count =0 ; count < wifi_count ;count++)
			{
				wificlientindex = 0;
				while(  wificlientindex <= count)
				{
					fgets(str,FILE_SIZE,fp);
					wificlientindex++;
				}
				signalstrength= atoi(str);
				temp[count].cli_SignalStrength = signalstrength;
				temp[count].cli_RSSI = signalstrength;
				temp[count].cli_SNR = signalstrength + 95;
			}
		}
		pclose(fp);
		if((apIndex == 0) || (apIndex == 4))
		{
			strcpy(temp->cli_OperatingStandard,"g");
			strcpy(temp->cli_OperatingChannelBandwidth,"20MHz");
			if(strcmp(interface_name,"wlan0") == 0)
				fp = popen("iw dev wlan0 station dump | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt","r");
			else if(strcmp(interface_name,"wlan1") == 0)
				fp = popen("iw dev wlan1 station dump | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt","r");
			else if(strcmp(interface_name,"wlan0_0") == 0)
				fp = popen("iw dev wlan0_0 station dump | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt","r");
			else if(strcmp(interface_name,"wlan1_0") == 0)
				fp = popen("iw dev wlan1_0 station dump | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt","r");
			else if(strcmp(interface_name,"wlan2_0") == 0)
				fp = popen("iw dev wlan2_0 station dump | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt","r");
			else if(strcmp(interface_name,"wlan2") == 0)
				fp = popen("iw dev wlan2 station dump | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt","r");
			else if(strcmp(interface_name,"wlan3") == 0)
				fp = popen("iw dev wlan3 station dump | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt","r");
			pclose(fp);
			fp = popen("cat /tmp/Ass_Bytes_Send.txt | tr -s ' ' | cut -f 2","r");
			if(fp)
			{
				for(count =0 ; count < wifi_count ;count++)
				{
					wificlientindex = 0;
					while(  wificlientindex <= count)
					{
						fgets(str,FILE_SIZE,fp);
						wificlientindex++;
					}
					temp[count].cli_BytesSent = atol(str);
				}
			}
			pclose(fp);
			if(strcmp(interface_name,"wlan0") == 0)
				fp = popen("iw dev wlan0 station dump | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt","r");
			else if(strcmp(interface_name,"wlan1") == 0)
				fp = popen("iw dev wlan1 station dump | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt","r");
			else if(strcmp(interface_name,"wlan0_0") == 0)
				fp = popen("iw dev wlan0_0 station dump | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt","r");
			else if(strcmp(interface_name,"wlan1_0") == 0)
				fp = popen("iw dev wlan1_0 station dump | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt","r");
			else if(strcmp(interface_name,"wlan2_0") == 0)
				fp = popen("iw dev wlan2_0 station dump | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt","r");
			else if(strcmp(interface_name,"wlan2") == 0)
				fp = popen("iw dev wlan2 station dump | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt","r");
			else if(strcmp(interface_name,"wlan3") == 0)
				fp = popen("iw dev wlan3 station dump | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt","r");
			pclose(fp);
			fp = popen("cat /tmp/Ass_Bytes_Received.txt | tr -s ' ' | cut -f 2","r");
			if(fp)
			{
				for(count =0 ; count < wifi_count ;count++)
				{
					wificlientindex = 0;
					while(  wificlientindex <= count)
					{
						fgets(str,FILE_SIZE,fp);
						wificlientindex++;
					}
					temp[count].cli_BytesReceived = atol(str);
				}
			}
			pclose(fp);
			if(strcmp(interface_name,"wlan0") == 0)
				fp = popen("iw dev wlan0 station dump | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt","r");
			else if(strcmp(interface_name,"wlan1") == 0)
				fp = popen("iw dev wlan1 station dump | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt","r");
			else if(strcmp(interface_name,"wlan0_0") == 0)
				fp = popen("iw dev wlan0_0 station dump | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt","r");
			else if(strcmp(interface_name,"wlan1_0") == 0)
				fp = popen("iw dev wlan1_0 station dump | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt","r");
			else if(strcmp(interface_name,"wlan2_0") == 0)
				fp = popen("iw dev wlan2_0 station dump | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt","r");
			else if(strcmp(interface_name,"wlan2") == 0)
				fp = popen("iw dev wlan2 station dump | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt","r");
			else if(strcmp(interface_name,"wlan3") == 0)
				fp = popen("iw dev wlan3 station dump | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt","r");
			pclose(fp);
			fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2","r");
			if(fp)
			{
				for(count =0 ; count < wifi_count ;count++)
				{
					wificlientindex = 0;
					while(  wificlientindex <= count)
					{
						fgets(str,FILE_SIZE,fp);
						wificlientindex++;
					}
					temp[count].cli_LastDataDownlinkRate = atol(str);
					temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate /1024);
				}
			}
			pclose(fp);
			if(strcmp(interface_name,"wlan0") == 0)
				fp = popen("iw dev wlan0 station dump | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt","r");
			else if(strcmp(interface_name,"wlan1") == 0)
				fp = popen("iw dev wlan1 station dump | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt","r");
			else if(strcmp(interface_name,"wlan0_0") == 0)
				fp = popen("iw dev wlan0_0 station dump | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt","r");
			else if(strcmp(interface_name,"wlan1_0") == 0)
				fp = popen("iw dev wlan1_0 station dump | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt","r");
			else if(strcmp(interface_name,"wlan2_0") == 0)
				fp = popen("iw dev wlan2_0 station dump | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt","r");
			else if(strcmp(interface_name,"wlan2") == 0)
				fp = popen("iw dev wlan2 station dump | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt","r");
			else if(strcmp(interface_name,"wlan3") == 0)
				fp = popen("iw dev wlan3 station dump | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt","r");
			pclose(fp);
			fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2","r");
			if(fp)
			{
				for(count =0 ; count < wifi_count ;count++)
				{
					wificlientindex = 0;
					while(  wificlientindex <= count)
					{
						fgets(str,FILE_SIZE,fp);
						wificlientindex++;
					}
					temp[count].cli_LastDataUplinkRate = atol(str);
					temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate /1024);
				}
			}
			pclose(fp);

		}
		else if((apIndex == 1) || (apIndex == 5))
		{
			strcpy(temp->cli_OperatingStandard,"a");
			strcpy(temp->cli_OperatingChannelBandwidth,"20MHz");
			temp->cli_BytesSent = 0;
			temp->cli_BytesReceived = 0;
			temp->cli_LastDataUplinkRate = 0;
			temp->cli_LastDataDownlinkRate = 0;
		}
		temp->cli_Retransmissions = 0;
		temp->cli_DataFramesSentAck=0;
		temp->cli_DataFramesSentNoAck=0;
		temp->cli_MinRSSI = 0;
		temp->cli_MaxRSSI = 0;
		strncpy(temp->cli_InterferenceSources, "", 64);
		memset(temp->cli_IPAddress, 0, 64);
		*associated_dev_array = temp;
	}
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
	return RETURN_OK;
}
int wifihal_interfacestatus(CHAR *wifi_status,CHAR *interface_name)
{
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
	FILE *fp = NULL;
	char path[512] = {0},status[512] = {0};
	int count = 0;
	if(strcmp(interface_name,"wlan0") == 0)
		fp = popen("ifconfig wlan0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
	else if(strcmp(interface_name,"wlan1") == 0)
		fp = popen("ifconfig wlan1 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
	else if(strcmp(interface_name,"wlan0_0") == 0)
		fp = popen("ifconfig wlan0_0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
	else if(strcmp(interface_name,"wlan1_0") == 0)
		fp = popen("ifconfig wlan1_0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
	else if(strcmp(interface_name,"wlan2_0") == 0)
		fp = popen("ifconfig wlan2_0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
	else if(strcmp(interface_name,"wlan2") == 0)
		fp = popen("ifconfig wlan2 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
	else if(strcmp(interface_name,"wlan3") == 0)
		fp = popen("ifconfig wlan3 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
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
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.*
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (apIndex < 0) {
        return RETURN_ERR;
    }
#if 0	
	char cmd[256];    
    char buf[2048];
    wifi_associated_dev_t *dev=NULL;
    unsigned int assoc_cnt = 0;
    char *pos;
    FILE *f;
	char *mac=NULL;
	char *aid =NULL;
	char *chan = NULL;
	char *txrate = NULL;
	char *rxrate = NULL;
	char *rssi = NULL;
    
    *output_array_size = 0;
    *associated_dev_array = NULL;
   
    if (apIndex < 0) {
        return RETURN_ERR;
    }

    sprintf(cmd,  "wlanconfig %s%d list sta  2>/dev/null | grep -v HTCAP >/tmp/ap_%d_cli.txt; cat /tmp/ap_%d_cli.txt | wc -l" , AP_PREFIX, apIndex, apIndex, apIndex);
    _syscmd(cmd,buf,sizeof(buf));

    *output_array_size = atoi(buf);

    if (*output_array_size <= 0) 
		return RETURN_OK;
	
	dev=(wifi_associated_dev_t *) calloc (*output_array_size, sizeof(wifi_associated_dev_t));
	*associated_dev_array = dev;      

    sprintf(cmd, "cat /tmp/ap_%d_cli.txt" , apIndex);
    if ((f = popen(cmd, "r")) == NULL) {
        printf("%s: popen %s error\n",__func__, cmd);
        return -1;
    }

    while (!feof(f)) {
        pos = buf;
        *pos = 0;
        fgets(pos,200,f);

        if (strlen(pos) == 0) {
            break;
        }
        if (assoc_cnt >= *output_array_size) {
            break;
        }
         
		char *mac=strtok(pos," ");
		char *aid = strtok('\0'," ");
		char *chan = strtok('\0'," ");
		char *txrate = strtok('\0'," ");
		char *rxrate = strtok('\0'," ");
		char *rssi = strtok('\0'," ");

		// Should be Mac Address line
		if (mac) { 
			sscanf(mac, "%x:%x:%x:%x:%x:%x",
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[0], 
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[1], 
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[2], 
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[3], 
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[4], 
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[5] );
		}

		memset(dev[assoc_cnt].cli_IPAddress, 0, 64);
		dev[assoc_cnt].cli_AuthenticationState = 1;

		dev[assoc_cnt].cli_AuthenticationState =  (rssi != NULL) ? atoi(rssi) - 100 : 0;
		dev[assoc_cnt].cli_LastDataDownlinkRate =  (txrate != NULL) ? atoi(strtok(txrate,"M")) : 0; 
		dev[assoc_cnt].cli_LastDataUplinkRate =  (rxrate != NULL) ? atoi(strtok(rxrate,"M")) : 0;
		
		//zqiu: TODO: fill up the following items
		dev[assoc_cnt].cli_SignalStrength=-100;
		dev[assoc_cnt].cli_Retransmissions=0;
		dev[assoc_cnt].cli_Active=TRUE;
		strncpy(dev[assoc_cnt].cli_OperatingStandard, "", 64);
		strncpy(dev[assoc_cnt].cli_OperatingChannelBandwidth, "20MHz", 64);
		dev[assoc_cnt].cli_SNR=20;
		strncpy(dev[assoc_cnt].cli_InterferenceSources, "", 64);
		dev[assoc_cnt].cli_DataFramesSentAck=0;
		dev[assoc_cnt].cli_DataFramesSentNoAck=0;
		dev[assoc_cnt].cli_BytesSent=0;
		dev[assoc_cnt].cli_BytesReceived=0;
		dev[assoc_cnt].cli_RSSI=30;
		
		assoc_cnt++;      
        
    }
    pclose(f);
#endif
#if 1
    CHAR interface_name[64] = {0},wifi_status[64] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    if(apIndex == 0)
    {
	    GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	    wifihal_interfacestatus(wifi_status,interface_name);
	    if(strcmp(wifi_status,"RUNNING") == 0)
	    {
		    wifihal_AssociatedDevicesstats(apIndex,interface_name,associated_dev_array,output_array_size);
	    }
	    else
		    *associated_dev_array = NULL;
    }
    else if(apIndex == 1)
    {
	    GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
	    wifihal_interfacestatus(wifi_status,interface_name);
	    if(strcmp(wifi_status,"RUNNING") == 0)
		    wifihal_AssociatedDevicesstats(apIndex,interface_name,associated_dev_array,output_array_size);
	    else
		    *associated_dev_array = NULL;
    }
    else if(apIndex == 4)
    {
	    sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
	    if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
	    {
		    return RETURN_ERR;
	    }
	    if(buf[0] == '#')//tp-link
		    GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
	    else //tenda
		    GetInterfaceName_virtualInterfaceName_2G(interface_name);
	    wifihal_interfacestatus(wifi_status,interface_name);
	    if(strcmp(wifi_status,"RUNNING") == 0)
		    wifihal_AssociatedDevicesstats(apIndex,interface_name,associated_dev_array,output_array_size);
	    else
		    *associated_dev_array = NULL;
    }
    else if(apIndex == 5)
    {
	    GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
	    wifihal_interfacestatus(wifi_status,interface_name);
	    if(strcmp(wifi_status,"RUNNING") == 0)
		    wifihal_AssociatedDevicesstats(apIndex,interface_name,associated_dev_array,output_array_size);
	    else
		    *associated_dev_array = NULL;
    }
#endif
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
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
    char cmd[128];
    char buf[1024];
    
	snprintf(cmd, sizeof(cmd), "iwconfig %s%d essid \"%s\"",AP_PREFIX, apIndex, ssid);
    _syscmd(cmd, buf, sizeof(buf));

    return RETURN_OK;
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

#ifdef _WIFI_HAL_TEST_
int main(int argc,char **argv)
{
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
	return 0;
}
#endif

/**************************************************************************************************
			WIFI MAC FILTERING FUNCTIONS
****************************************************************************************************/
int do_MacFilter_Startrule()
{
        char cmd[1024];
	printf("\nStartRule\n");
        sprintf(cmd,"iptables -F  WifiServices  ");
        sprintf(cmd,"iptables -D INPUT  -j WifiServices  ");
        sprintf(cmd,"iptables -X  WifiServices  ");
        system(cmd);
        sprintf(cmd,"iptables -N  WifiServices  ");
        system(cmd);
        sprintf(cmd,"iptables -I INPUT  -j WifiServices  ");
        system(cmd);
}

int do_MacFilter_Flushrule()
{
        char cmd[1024];
	printf("\nFlushRule\n");
        sprintf(cmd,"iptables -F  WifiServices  ");
        system(cmd);
}


int do_MacFilter_Update(char *Operation, int i_macFiltCnt,COSA_DML_WIFI_AP_MAC_FILTER  *i_macFiltTabPtr ,int Count,struct hostDetails *hostPtr)
{
	int i,list,ret;
        char command[256];
	printf("\nFlter Update\n");

	if(!strcmp(Operation,"ACCEPT"))
	{
		printf("\nFlter Update Accept\n");
	        for(i = 0; i < Count; i++)
	        {
	            /* filter unwelcome device */
        	    if(!strcmp(hostPtr->InterfaceType,"Device.WiFi.SSID.1"))
	            {
	                 snprintf(command,sizeof(command),"hostapd_cli deauthenticate %s",hostPtr->hostName);
                	 system(command);
	                 sprintf(command, "iptables -I WifiServices -m mac --mac-source %s -j %s\n",hostPtr->hostName,"DROP");
                	 system(command);
	             }
		     hostPtr++;	
	        }
	        for(list=0;list<i_macFiltCnt;list++)
	        {
	              sprintf(command, "iptables -I WifiServices -m mac --mac-source %s -j %s\n",i_macFiltTabPtr->MACAddress,Operation);
	              system(command);
		      i_macFiltTabPtr++; 
       		}
	}
	else if(!strcmp(Operation,"DROP"))
        {
		printf("\nFlter Update Drop\n");
                snprintf(command,sizeof(command),"iptables -P INPUT  ACCEPT");
                system(command);
                for(i=0;i<i_macFiltCnt;i++)
                {
                   snprintf(command,sizeof(command),"hostapd_cli deauthenticate %s",i_macFiltTabPtr->MACAddress);
                   ret = system(command);
                   snprintf(command,sizeof(command),"iptables -I WifiServices -m mac --mac-source %s -j %s",i_macFiltTabPtr->MACAddress,Operation);
                   ret = system(command);
	      	   i_macFiltTabPtr++; 
                }

        }else
        {
		printf("\nFlter Update Allow All\n");

                snprintf(command,sizeof(command),"iptables -P INPUT ACCEPT");
                system(command);
        }

        return 1; 
 }

//<<
