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

    File: ccsp_hal_ethsw.c

        For CCSP Component:  Ccsp Provisioning & Managment

    ---------------------------------------------------------------

    copyright:

        Cisco Systems, Inc., 2014
        All Rights Reserved.

    ---------------------------------------------------------------

    description:

        This is the stub implementation of Ethernet Switch control.
       
    ---------------------------------------------------------------

    environment:

        platform dependent

    ---------------------------------------------------------------

    author:

        Cisco


    ---------------------------------------------------------------

    author:

        Ding Hua

    ---------------------------------------------------------------

    revision:

        02/28/2013  initial revision.

**********************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccsp_hal_ethsw.h" 


/**********************************************************************
                    DEFINITIONS
**********************************************************************/

#define  CcspHalEthSwTrace(msg)                     printf("%s - ", __FUNCTION__); printf msg;

/**********************************************************************
                            MAIN ROUTINES
**********************************************************************/

/* CcspHalEthSwInit :  */
/**
* Description: Do what needed to intialize the Eth hal.
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
INT
CcspHalEthSwInit
    (
        void
    )
{
    return  RETURN_OK;
}


/* CcspHalEthSwGetPortStatus :  */
/**
* Description: Retrieve the current port status -- link speed, duplex mode, etc.

* Parameters :
    PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
    pLinkRate   -- Receives the current link rate, as in CCSP_HAL_ETHSW_LINK_RATE
    pDuplexMode -- Receives the current duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE
    pStatus     -- Receives the current link status, as in CCSP_HAL_ETHSW_LINK_STATUS

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
    switch (PortId)
    {
        case CCSP_HAL_ETHSW_EthPort1:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_100Mbps;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Full;
            *pStatus        = CCSP_HAL_ETHSW_LINK_Up;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort2:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_1Gbps;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Full;
            *pStatus        = CCSP_HAL_ETHSW_LINK_Up;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort3:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
            *pStatus        = CCSP_HAL_ETHSW_LINK_Disconnected;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort4:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
            *pStatus        = CCSP_HAL_ETHSW_LINK_Disconnected;

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
* Description: Retrieve the current port config -- link speed, duplex mode, etc.

* Parameters :
    PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
    pLinkRate   -- Receives the current link rate, as in CCSP_HAL_ETHSW_LINK_RATE
    pDuplexMode -- Receives the current duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE

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
* Description: Set the port configuration -- link speed, duplex mode

* Parameters :
    PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
    LinkRate    -- Set the link rate, as in CCSP_HAL_ETHSW_LINK_RATE
    DuplexMode  -- Set the duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE

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
* Description: Retrieve the current port admin status.

* Parameters :
    PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
    pAdminStatus-- Receives the current admin status

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
    switch (PortId)
    {
        case CCSP_HAL_ETHSW_EthPort1:
        {
            *pAdminStatus   = CCSP_HAL_ETHSW_AdminUp;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort2:
        {
            *pAdminStatus   = CCSP_HAL_ETHSW_AdminUp;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort3:
        {
            *pAdminStatus   = CCSP_HAL_ETHSW_AdminDown;

            break;
        }

        case CCSP_HAL_ETHSW_EthPort4:
        {
            *pAdminStatus   = CCSP_HAL_ETHSW_AdminTest;

            break;
        }

        default:
            CcspHalEthSwTrace(("Unsupported port id %d", PortId));
            return  RETURN_ERR;
    }

    return  RETURN_OK;
}


/* CcspHalEthSwSetPortAdminStatus :  */
/**
* Description: Set the ethernet port admin status

* Parameters :
    AdminStatus -- set the admin status, as defined in CCSP_HAL_ETHSW_ADMIN_STATUS

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


/* CcspHalEthSwSetAgingSpeed :  */
/**
* Description: Set the ethernet port configuration -- admin up/down, link speed, duplex mode

* Parameters :
    PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
    AgingSpeed  -- integer value of aging speed
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
* Description: Retrieve the port number that the specificed MAC address is associated with (seen)

* Parameters :
    pMacAddr    -- Specifies the MAC address -- 6 bytes
    pPortId     -- Receives the found port number that the MAC address is seen on

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
