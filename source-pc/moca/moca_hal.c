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

    module: moca_hal.c

        For CCSP Component:  MoCA_Provisioning_and_management

    ---------------------------------------------------------------

    description:

        This header file gives the function call prototypes and 
        structure definitions used for the RDK-Broadband 
        MoCA hardware abstraction layer

        NOTE:
        THIS VERSION IS AN EARLY DRAFT INTENDED TO GET COMMENTS FROM COMCAST.
        TESTING HAS NOT YET BEEN COMPLETED.  
       
    ---------------------------------------------------------------

    environment:

        This HAL layer is intended to support MoCA drivers 
        through an open API.  The current implementation created
        below this HAL supports MoCA.
        Changes may be needed to support other MoCA enviornments.

    ---------------------------------------------------------------

    author:

        Cisco

**********************************************************************/

#include <stdio.h>
#include <string.h>
#include "moca_hal.h"

/**********************************************************************************
 *
 *  MoCA Subsystem level function prototypes 
 *
**********************************************************************************/
/* moca_GetIfConfig() function */
/**
* @description Gets the MoCA Configuration Parameters that were previously set.
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_config - Configuration Parameters
*		\n\n Instance Number when Multiple MoCA interfaces exist.
*		\n 0 - In the case of only one interface.
*		\n Get the Alias Name for the interface
*		\n Flag if the interface is Enabled.
*		\n Flag if the Local Node's preference to be Network Coordinator
*		\n Flag if Privacy is Enabled
*		\n Current Frequency Mask (bitmask)
*		\n Privacy password (Valid if Privacy is Enabled)
*		\n Maximum Tx Power Limit
*		\n AutoPowerControlPhyRate: PowerCtrlPhyTarget
*		\n Used as a reference to achieve the PHY rate by adjusting power.
*		\n Tx Power Limit for transmitting beacons
*		\n Maximum Ingress/Egress Bandwidth Thresholds
*		\n Reset Condition of the MoCA Node
*		\n Flag if the Node is configured to operate in mixed mode (both 1.0 & 1.1 versions).
*		\n Flag if the Node is Scanning
*		\n Flag if the Auto Power Control is Enabled
*		\n Node Taboo Mask (indicates what frequencies Node should avoid)
*		\n Channel Scan Mask (indicated what frequencies Node should scan for beacons)
* 
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
INT moca_GetIfConfig(ULONG ifIndex, moca_cfg_t *pmoca_config)
{
	if (NULL == pmoca_config) {
		return STATUS_FAILURE;
	} else {
		memset(pmoca_config, 0, sizeof(moca_cfg_t));
		return STATUS_SUCCESS;
	}
}

/* moca_SetIfConfig() function */
/**
* @description Sets the MoCA Configuration Parameters.
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_config - Configuration Parameters
*		\n\n Instance Number when Multiple MoCA interfaces exist.
*		\n 0 - In the case of only one interface.
*		\n Set the Alias Name for the interface
*		\n Enable/Disable the interface.
*		\n Enable/Disable the Node's preference to be Network Coordinator
*		\n Enable/Disable Privacy
*		\n Set of Frequencies that can be used for forming network (bitmask)
*		\n Privacy password (Valid if Privacy is Enabled)
*		\n Maximum Tx Power Limit
*		\n AutoPowerControlPhyRate: PowerCtrlPhyTarget
*		\n Used as a reference to achieve the PHY rate by adjusting power.
*		\n Tx Power Limit for transmitting beacons
*		\n Maximum Ingress/Egress Bandwidth Thresholds
*		\n Reset MoCA Node
*		\n Enable/Disable the Node to operate in mixed mode (both 1.0 & 1.1 versions).
*		\n Enable/Disable the Node to operate in single frequency mode or scanning mode.
*		\n Enable/Disable Auto Power Control.
*		\n Set of Frequencis to Avoid (bitmask)
*		\n Set of Frequencies to Scan for Beacons (bitmask)
* 
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
INT moca_SetIfConfig(ULONG ifIndex, moca_cfg_t *pmoca_config)
{
	if (NULL == pmoca_config) {
		return STATUS_FAILURE;
	} else {
		return STATUS_SUCCESS;
	}
}

/* moca_IfGetDynamicInfo() function */
/**
* @description Gets the Dynamic Status information on the interface & its 
*				associated network.
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_dynamic_info_t - 
*		Dynamic Information on the interface and its associated network.
*		The Following information is expected.
* 		\n Status of the Local Interface Inferface (Up/Down/ etc.)
*		\n Last Link Status Change (Up/Down/ etc.)
*		\n Maximum Ingress/Egress Bandwidth
*		\n Current Version of the MoCA Protocol
*		\n Node ID of the Network Coordinator
*		\n Local Interface Node ID
*		\n Node ID of the Backup Network Coordinator
*		\n If Privacy is enabled on the network
*		\n Current Frequency Mask
*		\n Current Operating Frequency
*		\n Last Operating Frequency
*		\n Tx Broadcast Rate
*		\n Flag if MaxIngress/MaxEgress Bandwidth Threshold Reached
*		\n Number of Client Devices Connected
*		\n Network Coordinator MAC Address
* 
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
INT moca_IfGetDynamicInfo(ULONG ifIndex, moca_dynamic_info_t *pmoca_dynamic_info)
{
	if (NULL == pmoca_dynamic_info) {
		return STATUS_FAILURE;
	} else {
		memset(pmoca_dynamic_info, 0, sizeof(moca_dynamic_info_t));
		return STATUS_SUCCESS;
	}
}

/* moca_IfGetStaticInfo() function */
/**
* @description Gets the Static Information from the Local Node
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_static_info - Static Information of the interface
*		\n Interface Name (for example: moca0)
*		\n MAC Address of the Interface
*		\n Firmware Version of the MoCA Firmware
*		\n Maximum PHY rate in Mbps
*		\n Highest Version of MoCA Protocol that the Node Supports
*		\n Frequencies that Node can Operate on (Bit Mask)
*		\n Frequenies to Avoid on Network (Bit Mask)
*		\n Beacon Backoff in dB
*		\n Flag if Node is Capable of QAM-256.
*		\n Flag that indicates if Node is capable of Packet Aggregation.
* 
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
INT moca_IfGetStaticInfo(ULONG ifIndex, moca_static_info_t *pmoca_static_info)
{
	if (NULL == pmoca_static_info) {
		return STATUS_FAILURE;
	} else {
		memset(pmoca_static_info, 0, sizeof(moca_static_info_t));
		return STATUS_SUCCESS;
	}
}

/* moca_IfGetStats() function */
/**
* @description Gets the Statistics on the Interface at Network Layer
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_stats - Statistics on the interface (Network layer)
*		\n\n Number of Bytes Sent & Received
*		\n Number of Packets Sent & Received
*		\n Number of Errors in Sent & Received Packets
*		\n Number of Unicast Packets Sent & Received
*		\n Number of Packets Discard (Tx & Rx side)
*		\n Number of Multicast Packets Sent & Received
*		\n Number of Broadcast Packets Sent & Received
*		\n Number of Unknown Protocol Packets Received
*		\n Aggregate Averages of Packet Counts (Tx & Rx)
* 
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
INT moca_IfGetStats(ULONG ifIndex, moca_stats_t *pmoca_stats)
{
	if (NULL == pmoca_stats) {
		return STATUS_FAILURE;
	} else {
		memset(pmoca_stats, 0, sizeof(moca_stats_t));
		return STATUS_SUCCESS;
	}
}

/* moca_GetNumAssociatedDevices() function */
/**
* @description Gets the Number of Nodes on the MoCA network.
* @param ifIndex - Index of the MoCA Interface.
* @param pulCount - Number of Nodes on the network.
* 
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
INT moca_GetNumAssociatedDevices(ULONG ifIndex, ULONG *pulCount)
{
	if (NULL == pulCount) {
		return STATUS_FAILURE;
	} else {
		*pulCount = 0;
		return STATUS_SUCCESS;
	}
}

/* moca_IfGetExtCounter() function */
/**
* @description Gets the Statistics on the Interface at MoCA MAC Layer.
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_mac_counters - MoCA MAC Layer Statiscs
*		\n\n Number of MAP packets
*		\n Number of Reservation Request Packets
*		\n Number of Link Control Packets
*		\n Number of Admission Request Packets
*		\n Number of Probes
*		\n Number of Beacons
*	** Please Note that this API is valid only if the Node is 
*		Network Coordinator.
* 
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
INT moca_IfGetExtCounter(ULONG ifIndex, moca_mac_counters_t *pmoca_mac_counters)
{
	if (NULL == pmoca_mac_counters) {
		return STATUS_FAILURE;
	} else {
		memset(pmoca_mac_counters, 0, sizeof(moca_mac_counters_t));
		return STATUS_SUCCESS;
	}
}

/* moca_IfGetExtAggrCounter() function */
/**
* @description Gets the Aggregate DATA units Transferred (Tx & Rx)
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_aggregate_counts - Aggregate Tx/Rx Counters
*		\n\n Aggregate Tx Payload Data Units (Not MoCA Control Packets).
*		\n Aggregate Rx Payload Data Units (Not MoCA Control Packets).
*
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
INT moca_IfGetExtAggrCounter(ULONG ifIndex, moca_aggregate_counters_t *pmoca_aggregate_counts)
{
	if (NULL == pmoca_aggregate_counts) {
		return STATUS_FAILURE;
	} else {
		memset(pmoca_aggregate_counts, 0, sizeof(moca_aggregate_counters_t));
		return STATUS_SUCCESS;
	}
}

/* moca_GetMocaCPEs() function */
/**
* @description Get MAC Address of all the Nodes Connected on MoCA Network.
* @param ifIndex - Index of the MoCA Interface.
* @param pmoca_cpes - List of MAC Addresses of MoCA Nodes.
* @param pnum_cpes - Number of MoCA Nodes in the List.
*
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
INT moca_GetMocaCPEs(ULONG ifIndex, moca_cpe_t *cpes, INT *pnum_cpes)
{
	if (NULL == pnum_cpes || NULL == cpes) {
		return STATUS_FAILURE;
	} else {
		*pnum_cpes = 0;
		memset(cpes, 0, sizeof(moca_cpe_t));
		return STATUS_SUCCESS;
	}
}

/* moca_GetAssociatedDevices() function */
/**
* @description Get Information on all the associated Devices on the network.
* @param ifIndex - Index of the MoCA Interface.
* @param ppdevice_array - Array of set of information for each Node on the network.
*		\n\n MAC Address of the Associated Device 
*		\n Node ID of the Associated Device
*		\n Whether this Node is a Preferred NC.
*		\n Highest MoCA Protocol Version that this Node supports
*		\n Tx PHY Rate of this Node
*		\n Rx PHY Rate of this Node
*		\n Tx Power Reduced by this Node
*		\n Rx Power Level read by this Node
*		\n Tx Broadcast PHY Rate
*		\n Rx Broadcast Power Level read by this Node
*		\n Number of Transmitted Packets from this Node
*		\n Number of Recieved Packets by this Node
*		\n Number of (Rx) Error or Missed Packets by this Node
*		\n Flag if this Node is capable of QAM-256
*		\n Flag if this Node is capable of Packet Aggregation
*		\n Receive Signal to Noise Ration
*		\n Flag if this Node is Active
*		\n Recevie Broadcast PHY Rate
*		\n Number of Clients connected to this Node
*
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
INT moca_GetAssociatedDevices(ULONG ifIndex, moca_associated_device_t **ppDeviceArray)
{
	if (NULL == ppDeviceArray) {
		return STATUS_FAILURE;
	} else {
		return STATUS_SUCCESS;
	}
}

/* moca_FreqMaskToValue() function */
/**
* @description A utility function that converts Mask Value to Frequency Number.
* @param mask - Bit Mask of the Frequency.
*
* @return Frequency Value for the given Mask.
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT moca_FreqMaskToValue(UCHAR *mask)
{
	return STATUS_FAILURE;
}

/* moca_HardwareEquipped() function */
/**
* @description Functio that returns whether the MoCA Hardware is Equipped or Not.
* @param None.
*
* @return Flag Indicating whether the Hardware is Equipped or not.
* @retval TRUE if Hardware is present.
* @retval FALSE if Hardware is not present.
* 
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
BOOL moca_HardwareEquipped(void)
{
	return FALSE;
}

/* moca_IfGetFullMeshRates() function */
/**
* @description Gets the MoCA Mesh Table.
* @param ifIndex - Index of the MoCA Interface.
* @param moca_mesh_table_t - pointer to a mesh table entry
* @param pulCount - number of entries in the table
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
INT moca_GetFullMeshRates(ULONG ifIndex, moca_mesh_table_t *pDeviceArray, ULONG *pulCount)
{
	int status=STATUS_SUCCESS;
	if (NULL == pDeviceArray) {
		return STATUS_FAILURE;
	}
    memset(pDeviceArray, 0, sizeof(moca_mesh_table_t));
    pDeviceArray->TxNodeID=0;
    pDeviceArray->RxNodeID=0;
    pDeviceArray->TxRate=0;
    pulCount=0;

    return status;
}

/* moca_GetFlowStatistics() function */
/**
* @description Gets the MoCA Flow Table.
* @param ifIndex - Index of the MoCA Interface.
* @param moca_flow_table_t - pointer to a flow table entry
* @param pulCount - number of entries in the table
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
INT moca_GetFlowStatistics(ULONG ifIndex, moca_flow_table_t *pDeviceArray, ULONG *pulCount)
{
	int status=STATUS_SUCCESS;
	if (NULL == pDeviceArray) {
		return STATUS_FAILURE;
	}
    memset(pDeviceArray, 0, sizeof(moca_flow_table_t));
    pDeviceArray->FlowID=0;
    pDeviceArray->IngressNodeID=0;
    pDeviceArray->EgressNodeID=0;
    pDeviceArray->FlowTimeLeft=0;
    memset(pDeviceArray->DestinationMACAddress, 0, sizeof(pDeviceArray->DestinationMACAddress));
    pDeviceArray->PacketSize=0;
    pDeviceArray->PeakDataRate=0;
    pDeviceArray->BurstSize=0;
    pDeviceArray->FlowTag=0;
    pDeviceArray->LeaseTime=0;
    pulCount=0;

    return status;
}

/* moca_GetResetCount() function */
/**
* @description Gets the MoCA reset count.
* @param resetcnt - number of reset 
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

INT moca_GetResetCount(ULONG *resetcnt)
{
    if (resetcnt == NULL)
    {
        return STATUS_FAILURE;
    }
    else
    {  
		*resetcnt = 3;
        return STATUS_SUCCESS;
    }
}
