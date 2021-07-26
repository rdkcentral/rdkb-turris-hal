/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
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
   Copyright [2017] [Technicolor, Inc.]

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
#include <sys/types.h>

#include "fwupgrade_hal.h"

/* FW Download HAL API Prototype */
/* fwupgrade_hal_set_download_url  - 1 */
/* Description: Set Download Settings
Parameters : char* pUrl;
Parameters : char* pfilename;

@return the status of the operation
@retval RETURN_OK if successful.
@retval RETURN_ERR if any Downloading is in process or Url string is invalided.
*/
INT fwupgrade_hal_set_download_url (char* pUrl, char* pfilename)
{
    if ((pUrl == NULL) || (pfilename==NULL))
    {
        return RETURN_ERR;
    }
    else
    {
        printf("Entering %s\n", __func__);
        return RETURN_OK;
    }
}


/* fwupgrade_hal_get_download_Url: */
/* Description: Get FW Download Url
Parameters : char* pUrl
Parameters : char* pfilename;
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if http url string is empty.
*/
INT fwupgrade_hal_get_download_url (char *pUrl, char* pfilename)
{
    if ((pUrl == NULL) || (pfilename==NULL))
    {
        return RETURN_ERR;
    }
    else
    {
        printf("Entering %s\n", __func__);
        return RETURN_OK;
    }
}

/* interface=0 for wan0, interface=1 for erouter0 */
INT fwupgrade_hal_set_download_interface(unsigned int interface)
{
    printf("Entering %s\n", __func__);

    if( interface > 1 )
    {
        printf("Invalid interface: %d\n", interface);
        printf("Exiting %s\n", __func__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}


/* interface=0 for wan0, interface=1 for erouter0 */
INT fwupgrade_hal_get_download_interface(unsigned int* pinterface)
{
    if (pinterface == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
        printf("Entering %s\n", __func__);
        return RETURN_OK;
    }
}


/* fwupgrade_hal_download */
/**
Description: Start FW Download
Parameters: <None>
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any Downloading is in process.

*/
INT fwupgrade_hal_download ()
{
    printf("Entering %s\n", __func__);
    return RETURN_OK;
}


/* fwupgrade_hal_get_download_status */
/**
Description: Get the FW Download Status
Parameters : <None>
@return the status of the HTTP Download.
?   0 ? Download is not started.
?   Number between 0 to 100: Values of percent of download.
?   200 ? Download is completed and waiting for reboot.
?   400 -  Invalided Http server Url
?   401 -  Cannot connect to Http server
?   402 -  File is not found on Http server
?   403 -  HW_Type_DL_Protection Failure
?   404 -  HW Mask DL Protection Failure
?   405 -  DL Rev Protection Failure
?   406 -  DL Header Protection Failure
?   407 -  DL CVC Failure
?   500 -  General Download Failure
?   */
INT fwupgrade_hal_get_download_status()
{
    printf("Entering %s\n", __func__);
    return RETURN_OK;
}

/* fwupgrade_hal_reboot_ready */
/*
Description: Get the Reboot Ready Status
Parameters:
ULONG *pValue- Values of 1 for Ready, 2 for Not Ready
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any error is detected

*/
INT fwupgrade_hal_reboot_ready(ULONG *pValue)
{
    printf("Entering %s\n", __func__);

    if (pValue == NULL)
    {
        printf("Input pValue is NULL !!!\n");
        return RETURN_ERR;
    }

    return RETURN_OK;
}

/* fwupgrade_hal_reboot_now */
/*
Description:  Http Download Reboot Now
Parameters : <None>
@return the status of the reboot operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any reboot is in process.
*/
INT fwupgrade_hal_download_reboot_now()
{
    printf("Entering %s\n", __func__);
	return RETURN_OK;
}

/* fwupgrade_hal_update_and_factoryreset */
/*
Description:  Do FW update and Factory reset
Parameters : <None>
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any reboot/Download is in process.
*/
INT fwupgrade_hal_update_and_factoryreset()
{
    printf("Entering %s\n", __func__);

    // Image Download to temp
    if(RETURN_OK != fwupgrade_hal_download())
    {
        printf("failed download the image to CPE\n");
        return RETURN_ERR;
    }

    // Will do signature checks , switch banks and reboot
    if(RETURN_OK != fwupgrade_hal_download_reboot_now())
    {
        printf("failed download_Reboot the CPE\n");
        return RETURN_ERR;
    }

    return RETURN_OK;
}

/*  fwupgrade_hal_download_install: */
/**
* @description: Downloads and upgrades the firmware
* @param None
* @return the status of the Firmware download and upgrade status
* @retval RETURN_OK if successful.
* @retval RETURN_ERR in case of remote server not reachable
*/
INT fwupgrade_hal_download_install(const char *url)
{
    return RETURN_OK;
}
