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
#include "mso_mgmt_hal.h"

/* mso_getpwd() function */
/**
* @description Gets the password of the day for mso user.
* @param pwd - a pointer to a buffer that was preallocated by the caller.  This is where the output is 
written.
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

