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

    module: mta_hal.h

        For CCSP Component:  CcspMtaAgent

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 2014
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This header file gives the function call prototypes and 
        structure definitions used for the RDK-Broadband 
        hardware abstraction layer for Cable Modem

        NOTE:
        THIS VERSION IS AN EARLY DRAFT INTENDED TO GET COMMENTS FROM COMCAST.
        TESTING HAS NOT YET BEEN COMPLETED.  
       
    ---------------------------------------------------------------

    environment:

        This HAL layer is intended to support cable modem drivers 
        through an open API.  
        Changes may be needed to support different hardware enviornments.

    ---------------------------------------------------------------

    author:

        Cisco

**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mta_hal.h"

#define _ERROR_ "NOT SUPPORTED"

// COSA_DML_MTA_LOG MtaLog = { TRUE, TRUE };

INT   mta_hal_InitDB(void) { return RETURN_OK; }

INT   mta_hal_GetDHCPInfo(PMTAMGMT_MTA_DHCP_INFO pInfo) {

    memset(pInfo, 0, sizeof(MTAMGMT_MTA_DHCP_INFO));

    pInfo->LeaseTimeRemaining = 6;

    pInfo->PrimaryDHCPServer.Value = 0x06060606U;
    pInfo->SecondaryDHCPServer.Value = 0x06060606U;

    pInfo->IPAddress.Value = 0x06060606U;
    pInfo->SubnetMask.Value = 0x06060606U;
    pInfo->Gateway.Value = 0x06060606U;
    pInfo->PrimaryDNS.Value = 0x06060606U;
    pInfo->SecondaryDNS.Value = 0x06060606U;

    strcpy(pInfo->BootFileName, "BootFileName");
    strcpy(pInfo->FQDN, "FQDN");
    strcpy(pInfo->RebindTimeRemaining, "RebindTimeRemaining");
    strcpy(pInfo->RenewTimeRemaining, "RenewTimeRemaining");
    strcpy(pInfo->DHCPOption3, "DHCPOption3");
    strcpy(pInfo->DHCPOption6, "DHCPOption6");
    strcpy(pInfo->DHCPOption7, "DHCPOption7");
    strcpy(pInfo->DHCPOption8, "DHCPOption8");
    strcpy(pInfo->PCVersion, "PCVersion");
    strcpy(pInfo->MACAddress, "66:66:66:66:66:66");

    return RETURN_OK;
}

/*
COSA_MTA_PKTC g_mta_pktc = {FALSE,6,6,6,6,6,6,6,6,6,6};

ANSC_STATUS
CosaDmlMTAGetPktc
    (
        ANSC_HANDLE                 hContext,
        PCOSA_MTA_PKTC              pPktc
    )
{
    AnscCopyMemory(pPktc, &g_mta_pktc, sizeof(COSA_MTA_PKTC));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlMTASetPktc
    (
        ANSC_HANDLE                 hContext,
        PCOSA_MTA_PKTC              pPktc
    )
{
    AnscCopyMemory(&g_mta_pktc, pPktc, sizeof(COSA_MTA_PKTC));
    return ANSC_STATUS_SUCCESS;
}
*/

ULONG mta_hal_LineTableGetNumberOfEntries() { return 1; }

INT   mta_hal_LineTableGetEntry(ULONG Index, PMTAMGMT_MTA_LINETABLE_INFO pEntry) {

    memset(pEntry, 0, sizeof(MTAMGMT_MTA_LINETABLE_INFO));

	pEntry->InstanceNumber = Index + 1;	

    pEntry->LineNumber = 6;
    pEntry->Status = 1;
    pEntry->CAPort = 6;
    pEntry->MWD = 6;

    strcpy(pEntry->ForeignEMF, "ForeignEMF");
    strcpy(pEntry->HazardousPotential, "HazardousPotential");
    strcpy(pEntry->ResistiveFaults, "ResistiveFaults");
    strcpy(pEntry->ReceiverOffHook, "ReceiverOffHook");
    strcpy(pEntry->RingerEquivalency, "RingerEquivalency");
    strcpy(pEntry->CAName, "CAName");

    return RETURN_OK;
}

INT   mta_hal_TriggerDiagnostics(ULONG Index) { return RETURN_OK; }

INT   mta_hal_GetServiceFlow(ULONG* Count, PMTAMGMT_MTA_SERVICE_FLOW *ppCfg) {

    *Count = 1;

    *ppCfg = (PMTAMGMT_MTA_SERVICE_FLOW)malloc(sizeof(MTAMGMT_MTA_SERVICE_FLOW));
    memset(*ppCfg, 0, sizeof(MTAMGMT_MTA_SERVICE_FLOW));

    strcpy((*ppCfg)->Direction, "upstream");
    (*ppCfg)->MaxTrafficBurst = 6;
    (*ppCfg)->MaxTrafficRate = 6;
    (*ppCfg)->MinReservedPkt = 6;
    (*ppCfg)->MinReservedRate = 6;
    (*ppCfg)->NomGrantInterval = 6;
    (*ppCfg)->NomPollInterval = 6;
    (*ppCfg)->ScheduleType = 6;
    (*ppCfg)->SFID = 6;
    (*ppCfg)->TolGrantJitter = 6;
    (*ppCfg)->UnsolicitGrantSize = 6;

    return RETURN_OK;
}

INT   mta_hal_DectGetEnable(BOOLEAN *pBool) { *pBool = FALSE; return RETURN_OK; }


INT mta_hal_DectSetEnable(BOOLEAN bBool)
{
	return RETURN_OK;
}


INT mta_hal_DectGetRegistrationMode(BOOLEAN* pBool)
{
	return RETURN_OK;
}

INT mta_hal_DectSetRegistrationMode(BOOLEAN bBool)
{
	return RETURN_OK;
}

INT mta_hal_DectDeregisterDectHandset(ULONG uValue)
{
	return RETURN_OK;
}

INT mta_hal_GetDect(PMTAMGMT_MTA_DECT pDect)
{
	return RETURN_OK;
}

INT mta_hal_GetDectPIN(char* pPINString)
{
	return RETURN_OK;
}

INT mta_hal_SetDectPIN(char* pPINString)
{
	return RETURN_OK;
}

INT mta_hal_GetHandsets(ULONG* pulCount, PMTAMGMT_MTA_HANDSETS_INFO* ppHandsets)
{
	return RETURN_OK;
}


/*
COSA_MTA_DECT g_mta_dect = {6,6, "Hardware", "RFPI", "Software"};

ANSC_STATUS
CosaDmlMTAGetDect
    (
        ANSC_HANDLE                 hContext,
        PCOSA_MTA_DECT              pDect
    )
{
    AnscCopyMemory(pDect, &g_mta_dect, sizeof(COSA_MTA_DECT));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlMTASetDect
    (
        ANSC_HANDLE                 hContext,
        PCOSA_MTA_DECT              pDect
    )
{
    AnscCopyMemory(&g_mta_dect, pDect, sizeof(COSA_MTA_DECT));
    return ANSC_STATUS_SUCCESS;
}

ULONG
CosaDmlMTAHandsetsGetNumberOfEntries
    (
        ANSC_HANDLE                 hContext
    )
{
    return 1;
}

ANSC_STATUS
CosaDmlMTAHandsetsGetEntry
    (
        ANSC_HANDLE                 hContext,
        ULONG                       ulIndex,
        PCOSA_MTA_HANDSETS_INFO     pEntry
    )
{
    pEntry->Status = FALSE;
    strcpy(pEntry->HandsetFirmware, "HandsetFirmware");
    strcpy(pEntry->HandsetName, "HandsetName");
    strcpy(pEntry->LastActiveTime, "LastActiveTime");

    return ANSC_STATUS_SUCCESS;
}

*/

INT   mta_hal_GetCalls(ULONG InstanceNumber, ULONG *pulCount, PMTAMGMT_MTA_CALLS *ppCfg) {

    *pulCount = 1;

    *ppCfg = (PMTAMGMT_MTA_CALLS)malloc(sizeof(MTAMGMT_MTA_CALLS));
    memset(*ppCfg, 0, sizeof(MTAMGMT_MTA_CALLS));

    strcpy((*ppCfg)->CallEndTime, "2000-01-01");
    strcpy((*ppCfg)->CallStartTime, "2000-01-01");
    strcpy((*ppCfg)->PktLossConcealment, "Standard");
    strcpy((*ppCfg)->CWErrorRate, "CWErrorRate");

	strcpy((*ppCfg)->CWErrors, "CWErrors");
	strcpy((*ppCfg)->SNR, "122");
	strcpy((*ppCfg)->DownstreamPower, "5.1");	
	strcpy((*ppCfg)->RemoteJBAbsMaxDelay, "20.2");

    return RETURN_OK;
}

INT   mta_hal_GetCALLP(ULONG LineNumber, PMTAMGMT_MTA_CALLP pCallp) {

    strcpy(pCallp->LCState, "Idle");
    strcpy(pCallp->CallPState, "Idle");
    strcpy(pCallp->LoopCurrent, "Normal");

    return RETURN_OK;
}

INT   mta_hal_GetDSXLogs(ULONG *Count, PMTAMGMT_MTA_DSXLOG *ppDSXLog) { *Count = 0; *ppDSXLog = NULL; return RETURN_OK; }
INT   mta_hal_GetDSXLogEnable(BOOLEAN *pBool) { *pBool = FALSE; return RETURN_OK; }
INT   mta_hal_SetDSXLogEnable(BOOLEAN Bool) { return RETURN_OK; }


MTAMGMT_MTA_MTALOG_FULL MtaLog[] = 
{
    { 1, 1, "1", "1998-05-14", "this is a log for matLog1"},
    { 2, 2, "2", "1998-05-14", "this is a log for matLog2"}
};

INT   mta_hal_GetMtaLog(ULONG *Count, PMTAMGMT_MTA_MTALOG_FULL *ppConf) {

    ULONG              i = 0;

    *Count = 2;

    *ppConf = (PMTAMGMT_MTA_MTALOG_FULL)malloc(sizeof(MTAMGMT_MTA_MTALOG_FULL)*2);
    memset(*ppConf, 0, sizeof(MTAMGMT_MTA_MTALOG_FULL)*2);

    memcpy(*ppConf, &MtaLog, sizeof(MtaLog) );

    for ( i=0; i<2; i++)
    {
        if ( MtaLog[i].pDescription ) {
            (*ppConf)[i].pDescription = (CHAR*)malloc(sizeof(CHAR)*(strlen(MtaLog[i].pDescription) + 1));
            strcpy((*ppConf)[i].pDescription, MtaLog[i].pDescription);
        }
        else
            (*ppConf)[i].pDescription = NULL;
    }

    return RETURN_OK;
}

INT mta_hal_ClearDSXLog(BOOLEAN Bool)
{
	 return RETURN_OK; 
}

INT mta_hal_GetCallSignallingLogEnable(BOOLEAN *pBool) 
{ 
	*pBool = FALSE; 
	return RETURN_OK; 
}

INT mta_hal_SetCallSignallingLogEnable(BOOLEAN Bool) 
{ 
	return RETURN_OK;
}
 
INT mta_hal_ClearCallSignallingLog(BOOLEAN Bool) 
{ 
	return RETURN_OK;
}

/*
COSA_DML_DECTLOG_FULL DectLog[] = 
{
    { 1, 1, 1, "1998-05-14", "this is a log for dectLog1"},
    { 2, 2, 2, "1998-05-14", "this is a log for dectLog2"}
};

ANSC_STATUS
CosaDmlMtaGetDectLog
    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount,
        PCOSA_DML_DECTLOG_FULL      *ppConf        
    )    
{
    *pulCount = 2;
    *ppConf = (PCOSA_DML_DECTLOG_FULL)AnscAllocateMemory( sizeof(DectLog) );

    AnscCopyMemory(*ppConf, &DectLog, sizeof(DectLog) );

    return ANSC_STATUS_SUCCESS;
}
*/

INT mta_hal_BatteryGetInstalled(BOOLEAN* Val)     { *Val = TRUE; return RETURN_OK; }
INT mta_hal_BatteryGetTotalCapacity(ULONG* Val)   { *Val = 1500; return RETURN_OK; }
INT mta_hal_BatteryGetActualCapacity(ULONG* Val)  { *Val = 1600; return RETURN_OK; }
INT mta_hal_BatteryGetRemainingCharge(ULONG* Val) { *Val = 1300; return RETURN_OK; }
INT mta_hal_BatteryGetRemainingTime(ULONG* Val)   { *Val = 1;    return RETURN_OK; }
INT mta_hal_BatteryGetNumberofCycles(ULONG* Val)  { *Val = 4321; return RETURN_OK; }

INT mta_hal_BatteryGetPowerStatus(CHAR *Val, ULONG *len) { strcpy(Val, "Battery");          *len=strlen(Val)+1; return RETURN_OK; }
INT mta_hal_BatteryGetCondition(CHAR *Val, ULONG *len)   { strcpy(Val, "Good");             *len=strlen(Val)+1; return RETURN_OK; }
INT mta_hal_BatteryGetStatus(CHAR* Val, ULONG *len)      { strcpy(Val, "Discharging");      *len=strlen(Val)+1; return RETURN_OK; }
INT mta_hal_BatteryGetLife(CHAR* Val, ULONG *len)        { strcpy(Val, "Need Replacement"); *len=strlen(Val)+1; return RETURN_OK; }

INT mta_hal_BatteryGetInfo(PMTAMGMT_MTA_BATTERY_INFO pInfo) {

    strcpy(pInfo->ModelNumber,    "ModelNumber1.0");
    strcpy(pInfo->SerialNumber,   "SerialNumber1.0");
    strcpy(pInfo->PartNumber,     "PartNumber1.0");
    strcpy(pInfo->ChargerFirmwareRevision, "ChargerFirmwareRevision1.0");

    return RETURN_OK;
}

INT mta_hal_Get_MTAResetCount(ULONG *resetcnt)
{
    if (resetcnt == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
		*resetcnt = 4;
        return RETURN_OK;
    }
}

INT mta_hal_Get_LineResetCount(ULONG *resetcnt)
{
    if (resetcnt == NULL)
    {
        return RETURN_ERR;
    }
    else
    { 
		*resetcnt = 5;
        return RETURN_OK;
    }
}

INT mta_hal_BatteryGetPowerSavingModeStatus(ULONG *pValue) { *pValue = 2; return RETURN_OK; }

