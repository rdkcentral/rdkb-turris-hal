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

#include<stdio.h>
#include<fcntl.h>
#include<string.h>
#include<malloc.h>
#include<stdlib.h>
#include"wifi_hal.h"

#ifdef WIFI_DEBUG
#define wifi_dbg_printf printf
#else
#define wifi_dbg_printf(format,args...) printf("")
#endif


#define wifi_printf printf
#define MAX_APS 2
#define NULL_CHAR '\0'
#define NEW_LINE '\n'
int _syscmd(char *cmd, char *retBuf, int retBufSize);
int wifi_readHostapd(int ap,struct hostap_conf *conf);
struct  hostap_conf conf[MAX_APS];
int wifi_writeHostapd(int ap,struct params *params);
struct  params params;
int wifi_readHostapd_all_aps();

int wifi_hostapdRead(int ap,struct params *params,char *output)
{
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
}

int wifi_hostapdWrite(int ap,param_list_t *list)
{
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
			if( ('3' == wpa_val[0]) && ( wifi_getApIndexForWiFiBand(band_2_4) == ap) )
			{
				wifi_dbg_printf("\n Current value of param wpa is 3, setting it to 2.\n");
				strcpy(list->parameter_list[loop_ctr].value, "2");
			}


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
	//system("systemctl restart hostapd.service");
	if(ap == 0)
	{
		wifi_RestartPrivateWifi_2G();
		system("/usr/sbin/hostapd -B /nvram/hostapd0.conf");
	}
	else if(ap == 1)
	{
		wifi_RestartHostapd_5G(ap);
		system("/usr/sbin/hostapd -B /nvram/hostapd1.conf");
		File_Reading("cat /tmp/GetPub5gssidEnable.txt",&ssid_cur_value);
		if(strcmp(ssid_cur_value,"1") == 0)
		{
			restarthostapd_all("/nvram/hostapd5.conf");
		}
	}
	else if(ap == 4)
	{
		wifi_RestartHostapd_2G();
		system("/usr/sbin/hostapd -B /nvram/hostapd4.conf");
	}
	else if(ap == 5)
	{
		wifi_RestartHostapd_5G(ap);
		system("/usr/sbin/hostapd -B /nvram/hostapd5.conf");
		//For Alias interface of 5G
		File_Reading("cat /tmp/Get5gssidEnable.txt",&ssid_cur_value);
		if(strcmp(ssid_cur_value,"1") == 0)
		{
			restarthostapd_all("/nvram/hostapd1.conf");
		}
#if 0
		else
		{
			if((strlen(buf)>0) && (priv_Sflag == TRUE))
			{
				restarthostapd_all("/nvram/hostapd1.conf");
				priv_Sflag = FALSE;
			}
		}
#endif

	}
	return RETURN_OK;
}
