/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mso_mgmt_hal.h"

/* mso_getpwd() function */
/**
* Description: Gets the password of the day for mso user.
* Parameters : pwd:a pointer to a buffer that was preallocated by the caller.  This is where the output is written 
* Newer Broadband Devices MUST decrypt the seed on demand when this HAL is called.
* 
* @return The status of the operation.
* @retval mso_pwd_ret_status
            Invalid_PWD,
            Good_PWD,
            Unique_PWD,
            Expired_PWD, 
            TimeError
*
* @execution Synchronous.
* @sideeffect None.
*
*
*/
mso_pwd_ret_status mso_validatepwd(char *pwd)
{
  mso_pwd_ret_status ReturnVal = Invalid_PWD;
  return ReturnVal;
}

/* mso_set_pod_seed : */
/**
* Description: Sets the PoD seed for mso password validation,
* Parameters: 
*    CHAR* seed - PoD seed
*
* @return the status of the operation.
* @returnval RETURN_OK if successful.
* @returnval RETURN_ERR if any error is detected.
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system 
* calls. It should probably just send a message to a driver event handler task. 
*
*/
INT mso_set_pod_seed(char* pSeed)
{
    if (pSeed == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
        return RETURN_OK;
    }
}

/* mso_get_pod_seed : */
/**
* Description: Gets the PoD seed for mso password validation,
* Parameters: 
*    CHAR* pSseed - a pointer to a buffer that was preallocated by the caller.  This is where the output is written
*
* @return the status of the operation.
* @returnval RETURN_OK if successful.
* @returnval RETURN_ERR if any error is detected.
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function retrieves the decrypted seed set in the Config file 
*       and SNMP OID rdkbEncryptedClientSeed. pSeed for security reasons MUST be manually
*       overwritten after use.
*/
INT mso_get_pod_seed(char* pSeed)
{
    if (pSeed == NULL)
    {
        return RETURN_ERR;
    }
    else
    {
        return RETURN_OK;
    }
}
