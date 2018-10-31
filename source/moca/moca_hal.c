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

    copyright:

        Cisco Systems, Inc., 2014
        All Rights Reserved.

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
* Description: Gets the MoCA Configuration Parameters that were previously set.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pmoca_config - Configuration Parameters
*		* Instance Number when Multiple MoCA interfaces exist.
*		*	0 - In the case of only one interface.
*		* Get the Alias Name for the interface
*		* Flag if the interface is Enabled.
*		* Flag if the Local Node's preference to be Network Coordinator
*		* Flag if Privacy is Enabled
*		* Current Frequency Mask (bitmask)
*		* Privacy password (Valid if Privacy is Enabled)
*		* Maximum Tx Power Limit
*		* AutoPowerControlPhyRate: PowerCtrlPhyTarget
*		*  	Used as a reference to achieve the PHY rate by adjusting power.
*		* Tx Power Limit for transmitting beacons
*		* Maximum Ingress/Egress Bandwidth Thresholds
*		* Reset Condition of the MoCA Node
*		* Flag if the Node is configured to operate in mixed mode (both 1.0 & 1.1 versions).
*		* Flag if the Node is Scanning
*		* Flag if the Auto Power Control is Enabled
*		* Node Taboo Mask (indicates what frequencies Node should avoid)
*		* Channel Scan Mask (indicated what frequencies Node should scan for beacons)
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
* Description: Sets the MoCA Configuration Parameters.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pmoca_config - Configuration Parameters
*		* Instance Number when Multiple MoCA interfaces exist.
*		*	0 - In the case of only one interface.
*		* Set the Alias Name for the interface
*		* Enable/Disable the interface.
*		* Enable/Disable the Node's preference to be Network Coordinator
*		* Enable/Disable Privacy
*		* Set of Frequencies that can be used for forming network (bitmask)
*		* Privacy password (Valid if Privacy is Enabled)
*		* Maximum Tx Power Limit
*		* AutoPowerControlPhyRate: PowerCtrlPhyTarget
*		*  	Used as a reference to achieve the PHY rate by adjusting power.
*		* Tx Power Limit for transmitting beacons
*		* Maximum Ingress/Egress Bandwidth Thresholds
*		* Reset MoCA Node
*		* Enable/Disable the Node to operate in mixed mode (both 1.0 & 1.1 versions).
*		* Enable/Disable the Node to operate in single frequency mode or scanning mode.
*		* Enable/Disable Auto Power Control.
*		* Set of Frequencis to Avoid (bitmask)
*		* Set of Frequencies to Scan for Beacons (bitmask)
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
* Description: Gets the Dynamic Status information on the interface & its 
*				associated network.
* Parameters: 
*	ifIndex - Index of the MoCA Interface.
* 	pmoca_dynamic_info_t - 
*		Dynamic Information on the interface and its associated network.
*		The Following information is expected.
* 		* Status of the Local Interface Inferface (Up/Down/ etc.)
*		* Last Link Status Change (Up/Down/ etc.)
*		* Maximum Ingress/Egress Bandwidth
*		* Current Version of the MoCA Protocol
*		* Node ID of the Network Coordinator
*		* Local Interface Node ID
*		* Node ID of the Backup Network Coordinator
*		* If Privacy is enabled on the network
*		* Current Frequency Mask
*		* Current Operating Frequency
*		* Last Operating Frequency
*		* Tx Broadcast Rate
*		* Flag if MaxIngress/MaxEgress Bandwidth Threshold Reached
*		* Number of Client Devices Connected
*		* Network Coordinator MAC Address
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
* Description: Gets the Static Information from the Local Node
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pmoca_static_info - Static Information of the interface
*		* Interface Name (for example: moca0)
*		* MAC Address of the Interface
*		* Firmware Version of the MoCA Firmware
*		* Maximum PHY rate in Mbps
*		* Highest Version of MoCA Protocol that the Node Supports
*		* Frequencies that Node can Operate on (Bit Mask)
*		* Frequenies to Avoid on Network (Bit Mask)
*		* Beacon Backoff in dB
*		* Flag if Node is Capable of QAM-256.
*		* Flag that indicates if Node is capable of Packet Aggregation.
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
* Description: Gets the Statistics on the Interface at Network Layer
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pmoca_stats - Statistics on the interface (Network layer)
*		* Number of Bytes Sent & Received
*		* Number of Packets Sent & Received
*		* Number of Errors in Sent & Received Packets
*		* Number of Unicast Packets Sent & Received
*		* Number of Packets Discard (Tx & Rx side)
*		* Number of Multicast Packets Sent & Received
*		* Number of Broadcast Packets Sent & Received
*		* Number of Unknown Protocol Packets Received
*		* Aggregate Averages of Packet Counts (Tx & Rx)
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
* Description: Gets the Number of Nodes on the MoCA network.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pulCount - Number of Nodes on the network.
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
* Description: Gets the Statistics on the Interface at MoCA MAC Layer.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pmoca_mac_counters - MoCA MAC Layer Statiscs
*		* Number of MAP packets
*		* Number of Reservation Request Packets
*		* Number of Link Control Packets
*		* Number of Admission Request Packets
*		* Number of Probes
*		* Number of Beacons
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
* Description: Gets the Aggregate DATA units Transferred (Tx & Rx)
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pmoca_aggregate_counts - Aggregate Tx/Rx Counters
*		* Aggregate Tx Payload Data Units (Not MoCA Control Packets).
*		* Aggregate Rx Payload Data Units (Not MoCA Control Packets).
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
* Description: Get MAC Address of all the Nodes Connected on MoCA Network.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    pmoca_cpes - List of MAC Addresses of MoCA Nodes.
*	 pnum_cpes - Number of MoCA Nodes in the List.
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
* Description: Get Information on all the associated Devices on the network.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    ppdevice_array - Array of set of information for each Node on the network.
*       * MAC Address of the Associated Device 
*       * Node ID of the Associated Device
*       * Whether this Node is a Preferred NC.
*       * Highest MoCA Protocol Version that this Node supports
*       * Tx PHY Rate of this Node
*       * Rx PHY Rate of this Node
*       * Tx Power Reduced by this Node
*       * Rx Power Level read by this Node
*       * Tx Broadcast PHY Rate
*       * Rx Broadcast Power Level read by this Node
*       * Number of Transmitted Packets from this Node
*       * Number of Recieved Packets by this Node
*       * Number of (Rx) Error or Missed Packets by this Node
*       * Flag if this Node is capable of QAM-256
*       * Flag if this Node is capable of Packet Aggregation
*       * Receive Signal to Noise Ration
*       * Flag if this Node is Active
*       * Recevie Broadcast PHY Rate
*       * Number of Clients connected to this Node
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
* Description: A utility function that converts Mask Value to Frequency Number.
* Parameters : 
*    mask - Bit Mask of the Frequency.
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
* Description: Functio that returns whether the MoCA Hardware is Equipped or Not.
* Parameters : None.
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
* Description: Gets the MoCA Mesh Table.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    moca_mesh_table_t - pointer to a mesh table entry
*    pulCount - number of entries in the table
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
* Description: Gets the MoCA Flow Table.
* Parameters : 
*    ifIndex - Index of the MoCA Interface.
*    moca_flow_table_t - pointer to a flow table entry
*    pulCount - number of entries in the table
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
* Description: Gets the MoCA reset count.
*    resetcnt - number of reset 
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
