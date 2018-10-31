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

#include "cm_hal.h" 

INT cm_hal_InitDB(void) { return RETURN_OK; }
INT docsis_InitDS(void) { return RETURN_OK; }
INT docsis_InitUS(void) { return RETURN_OK; }
INT docsis_ClearDocsisEventLog(void) { return RETURN_OK; }
INT docsis_GetCert(CHAR* pCert) { return RETURN_ERR; }
INT cm_hal_GetCPEList(PCMMGMT_DML_CPE_LIST * ppCPEList, ULONG* InstanceNum, CHAR* LanMode) { return RETURN_ERR; }

INT docsis_GetCertStatus(ULONG* pVal) { 
    *pVal = 0; 
    return RETURN_OK; 
}

INT docsis_getCMStatus(CHAR *cm_status) { 
    strcpy(cm_status, "Registration Complete"); 
    return RETURN_OK;
}

static CMMGMT_CM_DS_CHANNEL g_CmDsChannel = {
    .ChannelID          = 11,
    .Frequency          = "6440",
    .PowerLevel         = "75",
    .SNRLevel           = "50",
    .Modulation         = "QPSK",
    .Octets             = 123,
    .Correcteds         = 100,
    .Uncorrectables     = 12,
    .LockStatus         = "Locked",
};

INT docsis_GetDSChannel(PCMMGMT_CM_DS_CHANNEL * ppInfo) {    
    memcpy(*ppInfo, &g_CmDsChannel, sizeof(CMMGMT_CM_DS_CHANNEL));
    return RETURN_OK;
}

static CMMGMT_CM_US_CHANNEL g_CmUsChannel = {
    .ChannelID          = 12,
    .Frequency          = "12750",
    .PowerLevel         = "60",
    .ChannelType        = "Dummy",
    .SymbolRate         = "115200",
    .Modulation         = "QAM",
    .LockStatus         = "Locked",
};

INT docsis_GetUSChannel(PCMMGMT_CM_US_CHANNEL * ppInfo) {
    memcpy(*ppInfo, &g_CmUsChannel, sizeof(CMMGMT_CM_US_CHANNEL));
    return RETURN_OK;

}

INT docsis_GetNumOfActiveTxChannels(ULONG * cnt) {
    *cnt = 1; // DsChannels
    return RETURN_OK;
}

INT docsis_GetNumOfActiveRxChannels(ULONG * cnt) {
    *cnt = 1; // UsChannls
    return RETURN_OK;
}

CMMGMT_CM_DOCSIS_INFO g_CmDocsisInfo = {
    .DOCSISVersion              = "3.0",
    .DOCSISDownstreamScanning   = "Complete",
    .DOCSISDownstreamRanging    = "Complete",
    .DOCSISUpstreamScanning     = "InProgress",
    .DOCSISUpstreamRanging      = "InProgress",
    .DOCSISTftpStatus           = "NotStarted",
    .DOCSISDataRegComplete      = "Complete",
    .DOCSISDHCPAttempts         = 3,
    .DOCSISConfigFileName       = "goldenjim.cm",
    .DOCSISTftpAttempts         = 1,
    .ToDStatus                  = "NotStarted",
    .BPIState                   = TRUE,
    .NetworkAccess              = FALSE,
    .UpgradeServerIP.Dot        = {192, 168, 0, 1},
    .MaxCpeAllowed              = 5,
    .UpstreamServiceFlowParams  = "Dummy",
    .DownstreamServiceFlowParams= "Dummy",
    .DOCSISDownstreamDataRate   = "20000",
    .DOCSISUpstreamRanging      = "10000",
    .CoreVersion                = "1.0",
};
 
INT docsis_GetDOCSISInfo(PCMMGMT_CM_DOCSIS_INFO pInfo) {

    memcpy(pInfo, &g_CmDocsisInfo, sizeof(CMMGMT_CM_DOCSIS_INFO));
    return RETURN_OK;

}

CMMGMT_CM_ERROR_CODEWORDS CMErrorCodewords = { 1111, 1112, 1113};
 
INT docsis_GetErrorCodewords(PCMMGMT_CM_ERROR_CODEWORDS * ppInfo) {

    // just one
    memcpy(*ppInfo, &CMErrorCodewords, sizeof(CMMGMT_CM_ERROR_CODEWORDS) );

    return RETURN_OK;

}

static char g_MddIpOverride[64] = "honorMDD";

INT docsis_GetMddIpModeOverride(CHAR *pValue) {
    strcpy(pValue, g_MddIpOverride);
    return RETURN_OK;
}

INT docsis_SetMddIpModeOverride(CHAR *pValue) {
    if(pValue && strlen(pValue) < sizeof(g_MddIpOverride) -1) {
        strcpy(g_MddIpOverride, pValue);
        return RETURN_OK;
    }
    else return RETURN_ERR;
}

static  ULONG                       gLockedUpstreamChannelId    = 0;

UINT8 docsis_GetUSChannelId(void) {
    return gLockedUpstreamChannelId;
}

void docsis_SetUSChannelId(INT index) {
    gLockedUpstreamChannelId = index;
}

static  ULONG                       gStartDsFrequency           = 0;

ULONG docsis_GetDownFreq(void) {
    return gStartDsFrequency;
}
void docsis_SetStartFreq(ULONG value) {
    gStartDsFrequency = value;
}

CMMGMT_CM_EventLogEntry_t DocsisLog[2];

INT docsis_GetDocsisEventLogItems(CMMGMT_CM_EventLogEntry_t *entryArray, INT len){
    
    memset(DocsisLog, 0, sizeof(CMMGMT_CM_EventLogEntry_t)*2);

    DocsisLog[0].docsDevEvIndex = 1;
    DocsisLog[0].docsDevEvCounts = 1;
    DocsisLog[0].docsDevEvLevel = 1;
    DocsisLog[0].docsDevEvId = 1;
    strcpy(DocsisLog[0].docsDevEvText, "This is entry 1");

    DocsisLog[1].docsDevEvIndex = 2;
    DocsisLog[1].docsDevEvCounts = 2;
    DocsisLog[1].docsDevEvLevel = 2;
    DocsisLog[1].docsDevEvId = 2;
    strcpy(DocsisLog[1].docsDevEvText, "This is entry 2");

    memcpy(entryArray, DocsisLog, sizeof(CMMGMT_CM_EventLogEntry_t)*2);

    return 2;
}

static CMMGMT_CM_DHCP_INFO g_CmDhcpInfo = {
    .IPAddress.Dot      = {192, 168, 0, 100},
    .BootFileName       = "ccsp.boot",
    .SubnetMask.Dot     = {255, 255, 255, 0},
    .Gateway.Dot        = {192, 168, 0, 1},
    .TFTPServer.Dot     = {192, 168, 0, 10},
    .TimeServer         = "ntp.cisco.com",
    .TimeOffset         = 8,
    .LeaseTimeRemaining = 3600,
    .RebindTimeRemaining = "3700",
    .RenewTimeRemaining = "1200",
    .MACAddress         = "00:1A:2B:11:22:33",
    .DOCSISDHCPStatus   = "Complete",
};

INT cm_hal_GetDHCPInfo(PCMMGMT_CM_DHCP_INFO pInfo) {
    memcpy(pInfo, &g_CmDhcpInfo, sizeof(*pInfo));
    return RETURN_OK;
}

static CMMGMT_CM_IPV6DHCP_INFO g_CmDhcpv6Info = {
    .IPv6Address        = "2012:cafe:100::1",
    .IPv6BootFileName   = "ccsp.v6.boot",
    .IPv6Prefix         = "2012:cafe::/32",
    .IPv6Router         = "2012:cafe::1",
    .IPv6TFTPServer     = "2012:cafe::2",
    .IPv6TimeServer     = "ntp.cisco.com",
    .IPv6LeaseTimeRemaining = 3600,
    .IPv6RebindTimeRemaining = 3700,
    .IPv6RenewTimeRemaining = 1200,
};

INT cm_hal_GetIPv6DHCPInfo(PCMMGMT_CM_IPV6DHCP_INFO pInfo) {
    memcpy(pInfo, &g_CmDhcpv6Info, sizeof(*pInfo));
    return RETURN_OK;
}


INT cm_hal_GetMarket(CHAR* market) {
    strcpy(market, "Dummy-Market");
    return RETURN_OK;
}

INT cm_hal_Set_HTTP_Download_Url (char* pHttpUrl, char* pfilename)
{
    if ((pHttpUrl == NULL) || (pfilename==NULL))
    {
        return RETURN_ERR;
    }
    else
    {
        return RETURN_OK;
    }
}

INT cm_hal_Get_HTTP_Download_Url (char *pHttpUrl, char* pfilename)
{
    if ((pHttpUrl == NULL) || (pfilename==NULL))
    {
        return RETURN_ERR;
    }
    else
    {
        return RETURN_OK;
    }
}

INT cm_hal_Set_HTTP_Download_Interface(unsigned int interface)
{
   return RETURN_OK;
}

INT cm_hal_Get_HTTP_Download_Interface(unsigned int* pinterface)
{
    if (pinterface == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
       return RETURN_OK;
    }
}

INT cm_hal_HTTP_Download ()
{
    return RETURN_OK;
}

INT cm_hal_Get_HTTP_Download_Status()
{
    return RETURN_OK;
}

INT cm_hal_Reboot_Ready(ULONG *pValue)
{
    if (pValue == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
        return RETURN_OK;
    }
}

INT cm_hal_HTTP_Download_Reboot_Now()
{
    return RETURN_OK;
}

INT cm_hal_ReinitMac()
{
    return RETURN_OK;
}

INT docsis_GetProvIpType(CHAR *pValue)
{
    return RETURN_OK;
}

//reset count apis

INT cm_hal_Get_CableModemResetCount(ULONG *resetcnt)
{
    if (resetcnt == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
		*resetcnt = 1;
        return RETURN_OK;
    }
}

INT cm_hal_Get_LocalResetCount(ULONG *resetcnt)
{
    if (resetcnt == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
		*resetcnt = 2;
        return RETURN_OK;
    }
}

INT cm_hal_Get_DocsisResetCount(ULONG *resetcnt)
{
    if (resetcnt == NULL)
    {
        return RETURN_ERR;
    }
    else
    {  
		*resetcnt = 3;
        return RETURN_OK;
    }
}

INT cm_hal_Get_ErouterResetCount(ULONG *resetcnt)
{
    if (resetcnt == NULL)
    {
	
        return RETURN_ERR;
    }
    else
    { 
		*resetcnt = 6;
        return RETURN_OK;
    }
}
