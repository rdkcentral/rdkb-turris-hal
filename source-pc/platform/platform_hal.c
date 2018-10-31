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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform_hal.h" 

/* Note that 0 == RETURN_OK == STATUS_OK    */
/* Note that -1 == RETURN_ERR == STATUS_NOK */

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
INT platform_hal_GetModelName(CHAR* pValue) { strcpy(pValue, "Model Name"); return RETURN_OK; }
INT platform_hal_GetHardwareVersion(CHAR* pValue) { strcpy(pValue, "Hardware Version"); return RETURN_OK; }
INT platform_hal_GetBootloaderVersion(CHAR* pValue, ULONG maxSize) { strcpy(pValue, "Bootloader Version"); return RETURN_OK; }
INT platform_hal_GetBaseMacAddress(CHAR *pValue) { strcpy(pValue, "BasMac"); return RETURN_OK; }
INT platform_hal_GetHardware(CHAR *pValue) { strcpy(pValue, "Hard"); return RETURN_OK; }
INT platform_hal_GetTotalMemorySize(ULONG *pulSize) { *pulSize = 512*1024; return RETURN_OK; }

//open a file and read that line
INT File_Reading(CHAR *file,char *Value)
{
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
        return RETURN_OK;
}


INT platform_hal_GetFirmwareName(CHAR* pValue, ULONG maxSize) 
{ 
        char status[256] = {0};
	File_Reading("cat /fss/gw/version.txt | grep imagename | cut -d ':' -f2",status);
        strcpy(pValue, status);
        return RETURN_OK;
}

INT platform_hal_GetSoftwareVersion(CHAR* pValue, ULONG maxSize) { 
	char status[256] = {0};
	File_Reading("cat /fss/gw/version.txt | grep imagename | cut -d ':' -f2",status);
	strcpy(pValue, status);
	return RETURN_OK;
}

INT platform_hal_GetSerialNumber(CHAR* pValue)
{
	//	strcpy(pValue, "Serial Number"); 
	char status[100] ={0},serial_no[256] ={0};
	strcpy(serial_no,"RDKBEMULATOR-");
	system("ifconfig eth0 | grep HWaddr | tr -s ' ' | cut -d ' ' -f5 > /tmp/WAN_MAC.txt");
        system("sed -i '/:/s///g' /tmp/WAN_MAC.txt");
	File_Reading("cat /tmp/WAN_MAC.txt",status);
        strcat(serial_no,status);
        strcpy(pValue,serial_no);
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
