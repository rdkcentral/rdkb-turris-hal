/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

#include "platform_hal.h" 

/* Note that 0 == RETURN_OK == STATUS_OK    */
/* Note that -1 == RETURN_ERR == STATUS_NOK */
#define MAX_CMD_SIZE 512
#define MAX_BUF_SIZE 256

static int _syscmd(char *cmd, char *buf, int size)
{
    FILE *fp;
    char *ptr = buf;
    int bufsize=size, bufbytes=0, readbytes=0, cmd_ret=0;

    if((fp = popen(cmd, "r")) == NULL) {
        fprintf(stderr,"\npopen %s error\n", cmd);
        return RETURN_ERR;
    }

    while(!feof(fp))
    {
        *ptr = 0;
        if(bufsize>=128) {
            bufbytes=128;
        } else {
            bufbytes=bufsize-1;
        }

        fgets(ptr,bufbytes,fp);
        readbytes=strlen(ptr);

        if(!readbytes)
            break;

        bufsize-=readbytes;
        ptr += readbytes;
    }
    buf[bufsize-1]=0;
    cmd_ret = pclose(fp);

    return cmd_ret >> 8;
}

#define DEVICE_TYPE_NONE     0
#define DEVICE_TYPE_GATEWAY  1
#define DEVICE_TYPE_EXTENDER 2

INT platform_hal_GetDeviceConfigStatus(CHAR *pValue) { strcpy(pValue, "Complete"); return RETURN_OK; }

INT platform_hal_GetTelnetEnable(BOOLEAN *pFlag) { *pFlag = FALSE; return RETURN_OK; }
INT platform_hal_SetTelnetEnable(BOOLEAN Flag) { return RETURN_ERR; }
INT platform_hal_GetSSHEnable(BOOLEAN *pFlag) { *pFlag = FALSE; return RETURN_OK; }
INT platform_hal_SetSSHEnable(BOOLEAN Flag) { return RETURN_ERR; }

INT platform_hal_GetSNMPEnable(CHAR* pValue) { return RETURN_ERR; }
INT platform_hal_SetSNMPEnable(CHAR* pValue) { return RETURN_ERR; }
INT platform_hal_GetWebUITimeout(ULONG *pValue) { return RETURN_ERR; }
INT platform_hal_SetWebUITimeout(ULONG value) { return RETURN_ERR; }
INT platform_hal_GetWebAccessLevel(INT userIndex, INT ifIndex, ULONG *pValue) { return RETURN_ERR; }
INT platform_hal_SetWebAccessLevel(INT userIndex, INT ifIndex, ULONG value) { return RETURN_ERR; }

INT platform_hal_PandMDBInit(void) { return RETURN_OK; }
INT platform_hal_DocsisParamsDBInit(void) { return RETURN_OK; }

static int getDeviceType()
{
    int deviceType = DEVICE_TYPE_GATEWAY;
    const char *cmd = "cat /version.txt | grep imagename | cut -d':' -f2 | cut -d'-' -f3";
    FILE *fp = popen(cmd, "r");
    if (fp)
    {
       char buf[64] = {0};
        fgets(buf, sizeof(buf), fp);
        if (strstr(buf, "extender"))
       {
            deviceType = DEVICE_TYPE_EXTENDER;
       }
        pclose(fp);
    }
    return deviceType;
}

INT platform_hal_GetModelName(CHAR* pValue)
{
    if (pValue)
    {
        const char *src = (getDeviceType() == DEVICE_TYPE_EXTENDER)
            ? "RTROM01-2G-EX"
            : "RTROM01-2G";

       strcpy(pValue, src);
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT platform_hal_GetSerialNumber(CHAR* pValue)
{
    if (pValue)
    {
        const char *src = (getDeviceType() == DEVICE_TYPE_EXTENDER)
            ? "5544332211"
            : "1122334455";

        strcpy(pValue, src);
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT platform_hal_GetHardwareVersion(CHAR* pValue) { strcpy(pValue, "Hardware Version"); return RETURN_OK; }
INT platform_hal_GetSoftwareVersion(CHAR* pValue, ULONG maxSize) { strcpy(pValue, "Software Version"); return RETURN_OK; }
INT platform_hal_GetBootloaderVersion(CHAR* pValue, ULONG maxSize) { strcpy(pValue, "Bootloader Version"); return RETURN_OK; }

INT platform_hal_GetFirmwareName(CHAR* pValue, ULONG maxSize)
{
    if (pValue != NULL && maxSize > 0)
    {
        snprintf(pValue, maxSize, "%s", "rdk-yocto-turris-1");
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT platform_hal_GetBaseMacAddress(CHAR *pValue)
{
    if (pValue)
    {
        const char *path = "/sys/class/net/eth1/address";
        FILE *fp = fopen(path, "r");
        if (fp)
        {
            char *end;
            char buf[64] = {0};
            fgets(buf, sizeof(buf), fp);
            fclose(fp);

            end = strchr(buf, '\n');
            if (end)
            {
                *end = '\0';
            }
            strcpy(pValue, buf);
            return RETURN_OK;
        }
    }
    return RETURN_ERR;
}

INT platform_hal_GetTotalMemorySize(ULONG *pulSize) { *pulSize = 512*1024; return RETURN_OK; }

INT platform_hal_GetHardware(CHAR *pValue)
{
    char cmd[MAX_CMD_SIZE], output[MAX_BUF_SIZE];
    unsigned long flash_size_bytes, flash_size_mb;

    if (!pValue)
        return RETURN_ERR;

    //Getting the number of sectors
    snprintf(cmd, sizeof(cmd), "cat /sys/block/mmcblk0/size");
    _syscmd(cmd, output, sizeof(output));
    flash_size_bytes = atol(output)*512;
    flash_size_mb= flash_size_bytes/(1024*1024);
    snprintf(pValue, 16, "%lu", flash_size_mb);

    return RETURN_OK;
}

INT platform_hal_GetHardware_MemUsed(CHAR *pValue)
{
    if (pValue == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
	*pValue='0';
        return RETURN_OK;
    }
}

INT platform_hal_GetHardware_MemFree(CHAR *pValue)
{
    if (pValue == NULL)
    {   
        return RETURN_ERR;
    }
    else
    {
	*pValue='0';
        return RETURN_OK;
    }
}

INT platform_hal_GetFreeMemorySize(ULONG *pulSize)
{
        if (pulSize == NULL)
        {
           return RETURN_ERR;
        }
        *pulSize = 0;
        return RETURN_OK;
}

INT platform_hal_GetUsedMemorySize(ULONG *pulSize)
{
        if (pulSize == NULL)
        {
           return RETURN_ERR;
        }
        *pulSize = 0;
        return RETURN_OK;
}

INT platform_hal_GetFactoryResetCount(ULONG *pulSize)
{
        if (pulSize == NULL)
        {
           return RETURN_ERR;
        }
        *pulSize = 2;
        return RETURN_OK;
}

INT platform_hal_ClearResetCount(BOOLEAN bFlag)
{
        return RETURN_OK;
}

INT platform_hal_getTimeOffSet(CHAR *pValue)
{ 
	return RETURN_OK; 
} 

INT platform_hal_SetDeviceCodeImageTimeout(INT seconds)
{ 
	return RETURN_OK; 
} 

INT platform_hal_SetDeviceCodeImageValid(BOOLEAN flag)
{ 
	return RETURN_OK; 
}

INT platform_hal_getCMTSMac(CHAR *pValue)
{
	return platform_hal_GetBaseMacAddress(pValue);
}

/* platform_hal_SetSNMPOnboardRebootEnable() function */
/**
* @description : Set SNMP Onboard Reboot Enable value
*                to allow or ignore SNMP reboot
* @param IN    : pValue - SNMP Onboard Reboot Enable value
                 ("disable" or "enable")
*
* @return      : The status of the operation
* @retval      : RETURN_OK if successful
* @retval      : RETURN_ERR if any error is detected
*/
INT platform_hal_SetSNMPOnboardRebootEnable(CHAR* pValue)
{
	return RETURN_OK;
}
INT platform_hal_GetRouterRegion(CHAR* pValue)
{
	return RETURN_OK;
}

/* Utility apis to return common parameters from firewall_lib.c */
char *get_current_wan_ifname()
{
    return "0";
}

INT platform_hal_GetDhcpv4_Options ( dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
    if ((req_opt_list == NULL) || (send_opt_list == NULL))
    {
        return RETURN_ERR;
    }
    return RETURN_OK;
}

INT platform_hal_GetDhcpv6_Options ( dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
    if (req_opt_list == NULL)
    {
        return RETURN_ERR;
    }
    return RETURN_OK;
}

INT platform_hal_GetFirmwareBankInfo(FW_BANK bankIndex, PFW_BANK_INFO pFW_Bankinfo)
{
    return RETURN_OK;
}
