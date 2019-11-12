// SPDX-License-Identifier: Apache-2.0
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
 *
 *  module: wifi_hal.c
 *
 *      For CCSP Component:  Wifi_Provisioning_and_management
 *
 *  ---------------------------------------------------------------
 *
 *  description:
 *
 *      This sample implementation file gives the function call prototypes and
 *      structure definitions used for the RDK-Broadband
 *      Wifi hardware abstraction layer
 *
 *
 *  ---------------------------------------------------------------
 *
 *  environment:
 *
 *      This HAL layer is intended to support Wifi drivers
 *      through an open API.
 *
 *  ---------------------------------------------------------------
 *
 *  author:
 *
 *      zhicheng_qiu@cable.comcast.com
 *
 *********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include "wifi_hal.h"

#ifndef AP_PREFIX
#define AP_PREFIX	"wifi"
#endif

#ifndef RADIO_PREFIX
#define RADIO_PREFIX	"wlan"
#endif

#include <ev.h>
#include <wpa_ctrl.h>
#include <errno.h>
#define MAX_SUPPORTED_IFACES 6 // 2 x home 2 x backhaul 2x secure onboard

/*
 * EXTERNAL HELPERS
 */

#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024

#ifdef WIFI_DEBUG
#define wifi_dbg_printf printf
#define WIFI_ENTRY_EXIT_DEBUG printf
#else
#define wifi_dbg_printf(format, args...) printf("")
#define WIFI_ENTRY_EXIT_DEBUG(format, args...) printf("")
#endif
#define CONFIG_PREFIX "/nvram/hostapd"
#define ACL_PREFIX "/tmp/hostapd-acl"
#define SOCK_PREFIX "/var/run/hostapd/wifi"

static int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
	FILE *f;
	char *ptr = retBuf;
	int bufSize = retBufSize, bufbytes = 0, readbytes = 0, cmd_ret = 0;

	if ((f = popen(cmd, "r")) == NULL) {
		printf("popen %s error\n", cmd);
		return -1;
	}

	while (!feof(f)) {
		*ptr = 0;
		if (bufSize >= 128)
			bufbytes = 128;
		else
			bufbytes = bufSize-1;

		fgets(ptr, bufbytes, f);
		readbytes = strlen(ptr);

		if (readbytes == 0)
			break;
		bufSize -= readbytes;
		ptr += readbytes;
	}
	cmd_ret = pclose(f);
	retBuf[retBufSize-1] = 0;
	return cmd_ret >> 8;
}

static int wifi_hostapdRead(char *conf_file, char *param, char *output, int output_size)
{
	char cmd[MAX_CMD_SIZE] = {'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	int ret = 0;

	sprintf(cmd, "cat %s | grep \"^%s=\" | cut -d \"=\"  -f 2 | head -n1 | tr -d \"\\n\"", conf_file, param);
	ret = _syscmd(cmd, buf, sizeof(buf));

	if ((ret != 0) && (strlen(buf) == 0))
		return -1;

	strncpy(output, buf, output_size);

	return 0;
}
struct params {
	char *name;
	char *value;
};

static int wifi_hostapdWrite(char *conf_file, struct params *list, int item_count)
{
	char cmd[MAX_CMD_SIZE] = {'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	int ret = 0;

	for (int i = 0; i < item_count; i++) {
		wifi_hostapdRead(conf_file, list[i].name, buf, MAX_BUF_SIZE);
		if (strlen(buf) == 0) {
			//Insert
			sprintf(cmd, "echo \"%s=%s\" >> %s", list[i].name, list[i].value, conf_file);
		} else {
			//Update
			sprintf(cmd, "sed -i \"s/^%s=.*/%s=%s/\" %s", list[i].name, list[i].name, list[i].value, conf_file);
		}
		ret = _syscmd(cmd, buf, sizeof(buf));
		if (ret != 0)
			return -1;
	}

	return 0;
}


/* END OF EXTERNAL HELPERS */

/* rewritten helpers */
int GetInterfaceName(char *conf_file, char *interface_name)
{

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	wifi_hostapdRead(conf_file, "interface", interface_name, IF_NAMESIZE);

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

	return 0;

}

int GetInterfaceNameFromIdx(int radio_index, char *interface_name)
{
	char config_file[MAX_BUF_SIZE] = {0};

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radio_index);

	return GetInterfaceName(config_file, interface_name);
}

/**********************************************************************************
 *
 *  Wifi Subsystem level function prototypes
 *
 **********************************************************************************/
//---------------------------------------------------------------------------------------------------
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string)   //RDKB
{
	snprintf(output_string, 64, "%d.%d.%d", WIFI_HAL_MAJOR_VERSION, WIFI_HAL_MINOR_VERSION, WIFI_HAL_MAINTENANCE_VERSION);
	return RETURN_OK;
}


/* wifi_factoryReset() function */
/*
 * Description:
 *  Resets Implementation specifics may dictate some functionality since
 *  different hardware implementations may have different requirements.
 *  Parameters : None
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
INT wifi_factoryReset()
{
	// TODO Implement me!
	return RETURN_OK;

}

/* wifi_factoryResetRadios() function */
/*
 * Description:
 *  Resets Implementation specifics may dictate some functionality since
 *  different hardware implementations may have different requirements.
 *  Parameters : None
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
INT wifi_factoryResetRadios()
{
	if ((RETURN_OK == wifi_factoryResetRadio(0)) && (RETURN_OK == wifi_factoryResetRadio(1)))
		return RETURN_OK;

	return RETURN_ERR;
}


/* wifi_factoryResetRadio() function */
/*
 * Description:
 *  Resets Implementation specifics may dictate some functionality since
 *  different hardware implementations may have different requirements.
 *  Parameters : None
 *
 *
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected
 *
 * @execution Synchronous.
 *
 * @sideeffect None.
 *
 * @note This function must not suspend and must not invoke any blocking system
 * calls. It should probably just send a message to a driver event handler task.
 *
 */
INT wifi_factoryResetRadio(int radioIndex) //RDKB
{
	//TODO:Restore selected radio parameters without touch access point parameters
	return RETURN_OK;
}

/* wifi_initRadio() function */
/*
 * Description: This function call initializes the specified radio.
 *  Implementation specifics may dictate the functionality since
 *  different hardware implementations may have different initilization requirements.
 * Parameters : radioIndex - The index of the radio. First radio is index 0. 2nd radio is index 1   - type INT
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

INT wifi_initRadio(INT radioIndex)
{
	//TODO: Initializes the wifi subsystem (for specified radio)
	return RETURN_OK;
}

// Initializes the wifi subsystem (all radios)
INT wifi_init()                            //RDKB
{

	/* preparing hostapd configuration*/
	system("/usr/sbin/iw reg set US");
	system("systemctl start hostapd-global.service");

	//TODO: macfilter_init + check if adding to bridge is really needed

	return RETURN_OK;
}

/* wifi_reset() function */
/*
 * Description: Resets the Wifi subsystem.  This includes reset of all AP varibles.
 *  Implementation specifics may dictate what is actualy reset since
 *  different hardware implementations may have different requirements.
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
INT wifi_reset()
{
	//TODO: resets the wifi subsystem, deletes all APs
	return RETURN_OK;
}

/* wifi_down() function */
/*
 * Description:
 *  Turns off transmit power to all radios.
 *  Implementation specifics may dictate some functionality since
 *  different hardware implementations may have different requirements.
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
INT wifi_down()
{
	//TODO: turns off transmit power for the entire Wifi subsystem, for all radios
	return RETURN_OK;
}


/* wifi_createInitialConfigFiles() function */
/*
 * Description:
 *  This function creates wifi configuration files.  The format
 *  and content of these files are implementation dependent.  This function call is
 *  used to trigger this task if necessary. Some implementations may not need this
 *  function. If an implementation does not need to create config files the function call can
 *  do nothing and return RETURN_OK.
 *  Parameters : None
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
INT wifi_createInitialConfigFiles()
{
	//TODO: creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)

	return RETURN_OK;
}

// outputs the country code to a max 64 character string
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string)
{
	if (NULL == output_string)
		return RETURN_ERR;

	snprintf(output_string, 64, "841");
	return RETURN_OK;
}

INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode)
{
	//Set wifi config. Wait for wifi reset to apply
	return RETURN_OK;
}

/**********************************************************************************
 *
 *  Wifi radio level function prototypes
 *
 **********************************************************************************/

//Get the total number of radios in this wifi subsystem
INT wifi_getRadioNumberOfEntries(ULONG *output) //Tr181
{
	if (NULL == output)
		return RETURN_ERR;

	*output = 2;
	return RETURN_OK;
}

//Get the total number of SSID entries in this wifi subsystem
INT wifi_getSSIDNumberOfEntries(ULONG *output) //Tr181
{
	if (NULL == output)
		return RETURN_ERR;

	*output = 6;
	return RETURN_OK;
}

//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)	//RDKB
{
	char config_file[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	char ifname[IF_NAMESIZE] = {0};
	int ret = 0;

	if (NULL == output_bool)
		return RETURN_ERR;

	// Check only supported radios
	if (!((radioIndex == 0) || (radioIndex == 1)))
		return RETURN_ERR;

	ret = GetInterfaceNameFromIdx(radioIndex, ifname);
	if (ret != 0)
		return RETURN_ERR;

	sprintf(cmd, "ifconfig %s%d | grep RUNNING ", AP_PREFIX, radioIndex);
	_syscmd(cmd, buf, sizeof(buf));
	if (strlen(buf) > 0)
		*output_bool = TRUE;

	//TODO: check if hostapd with config is running

	*output_bool = FALSE;
	return RETURN_OK;
}

//Set the Radio enable config parameter
INT wifi_setRadioEnable(INT radioIndex, BOOL enable)		//RDKB
{
	//TODO: VERIFICATION IS NEEDED!!!!!!!!!!!!!!!!!!!!
	char ifname[IF_NAMESIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	BOOL tmp_enable = FALSE;
	char config_file[MAX_BUF_SIZE] = {0};
	int ret = 0;

	wifi_getRadioEnable(radioIndex, &tmp_enable);
	if (tmp_enable == enable)
		return RETURN_OK;

	ret = GetInterfaceNameFromIdx(radioIndex, ifname);
	if (ret != 0)
		return RETURN_ERR;
	//Set wifi config. Wait for wifi reset to apply
	sprintf(cmd, "ifconfig %s down", ifname);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if (ret != 0)
		return RETURN_ERR;

	sprintf(cmd, "hostapd_cli -i global raw REMOVE %s", ifname);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if ((ret != 0) || (strlen(buf) <= 0) || strncmp("OK", buf, 2))
		return RETURN_ERR;

	if (enable == FALSE)
		return RETURN_OK;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
	sprintf(cmd, "hostapd_cli -i global raw ADD bss_config=%s:%s", ifname, config_file);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if ((ret != 0) || (strlen(buf) <= 0) || strncmp("OK", buf, 2))
		return RETURN_ERR;

	return RETURN_OK;
}

//Get the Radio enable status
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool)	//RDKB
{
	if (NULL == output_bool)
		return RETURN_ERR;

	return wifi_getRadioEnable(radioIndex, output_bool);
}

//Get the Radio Interface name from platform, eg "wifi0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, "%s%d", RADIO_PREFIX, radioIndex);
	return RETURN_OK;
}

//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string)	//RDKB
{
	char cmd[MAX_CMD_SIZE];
	char buf[MAX_BUF_SIZE];
	char ifname[IF_NAMESIZE] = {0};
	int ret = 0;

	if (NULL == output_string)
		return RETURN_ERR;

	ret = GetInterfaceNameFromIdx(radioIndex, ifname);
	if (ret != 0)
		return RETURN_ERR;

	sprintf(cmd, "iwconfig %s | grep 'Bit Rate' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1,2", ifname);
	_syscmd(cmd, buf, sizeof(buf));

	snprintf(output_string, 64, "%s", buf);
	//TODO: CHECK VALID VALUE
	return RETURN_OK;
}

//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)	//RDKB
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, "2.4GHz,5GHz");
	return RETURN_OK;
}

//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex == 0)?"2.4GHz":"5GHz");
	return RETURN_OK;
}

//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex == 0)?"b,g,n":"n,ac");
	return RETURN_OK;
}

//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly)	//RDKB
{
	if (NULL == output_string)
		return RETURN_ERR;

	if (radioIndex == 0) {
		snprintf(output_string, 64, "n");		//"ht" needs to be translated to "n" or others
		*gOnly = FALSE;
		*nOnly = TRUE;
		*acOnly = FALSE;
	} else {
		snprintf(output_string, 64, "ac");		//"vht" needs to be translated to "ac"
		*gOnly = FALSE;
		*nOnly = FALSE;
		*acOnly = FALSE;
	}
	return RETURN_OK;

}

//Set the radio operating mode, and pure mode flag.
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag)	//RDKB
{
	return RETURN_ERR;
}


//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)	//RDKB
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex == 0)?"1-11":"36,40");
	return RETURN_OK;
}

//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string)	//RDKB
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 256, (radioIndex == 0)?"1,6,11":"36,40");
	return RETURN_OK;
}

//Get the running channel number
INT wifi_getRadioChannel(INT radioIndex, ULONG *output_ulong)	//RDKB
{
	char cmd[128] = {0};
	char buf[256] = {0};
	INT apIndex;

	if (NULL == output_ulong)
		return RETURN_ERR;

	snprintf(cmd, sizeof(cmd), "iw dev %s%d info |grep channel | awk '{ printf $2 }'", AP_PREFIX, radioIndex);
	_syscmd(cmd, buf, sizeof(buf));

	*output_ulong = 0;
	if (strlen(buf) >= 1)
		*output_ulong = atol(buf);

	if (*output_ulong <= 0) {
		//TODO: SSID is inactive, get channel from wifi config
		//FIXME: return valid value
		*output_ulong = 0;
		return RETURN_ERR;
	}
	return RETURN_OK;
}

//Set the running channel number
INT wifi_setRadioChannel(INT radioIndex, ULONG channel)	//RDKB	//AP only
{
	//Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
	return RETURN_ERR;
}

//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) //RDKB
{
	//Set to wifi config only. Wait for wifi reset to apply.
	return RETURN_ERR;
}

INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool)	//RDKB
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = FALSE;
	return RETURN_OK;
}

INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool)		//RDKB
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = FALSE;
	return RETURN_OK;
}

INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable)			//RDKB
{
	//Set to wifi config only. Wait for wifi reset to apply.
	return RETURN_ERR;
}

//Check if the driver support the Dfs
INT wifi_getRadioDfsSupport(INT radioIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = FALSE;
	return RETURN_OK;
}

//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
//The value of this parameter is a comma seperated list of channel number
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool)			//RDKB
{
	if (NULL == output_pool)
		return RETURN_ERR;
	snprintf(output_pool, 256, "1,2,3,4,5,6,7,8,9,10,11");
	return RETURN_OK;
}

INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool)			//RDKB
{
	//Set to wifi config. And apply instantly.
	return RETURN_OK;
}

INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds, INT *output_dwell_milliseconds)
{
	if (NULL == output_interval_seconds || NULL == output_dwell_milliseconds)
		return RETURN_ERR;
	*output_interval_seconds = 1800;
	*output_dwell_milliseconds = 40;
	return RETURN_OK;
}

INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds, INT dwell_milliseconds)
{
	//Set to wifi config. And apply instantly.
	return RETURN_OK;
}

//Get the Dfs enable status
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = FALSE;
	return RETURN_OK;
}

//Set the Dfs enable status
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enable)	//Tr181
{
	return RETURN_ERR;
}

//Check if the driver support the AutoChannelRefreshPeriod
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = FALSE;		//not support
	return RETURN_OK;
}

//Get the ACS refresh period in seconds
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) //Tr181
{
	if (NULL == output_ulong)
		return RETURN_ERR;
	*output_ulong = 300;
	return RETURN_OK;
}

//Set the ACS refresh period in seconds
INT wifi_setRadioDfsRefreshPeriod(INT radioIndex, ULONG seconds) //Tr181
{
	return RETURN_ERR;
}

//Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex == 0) ? "20MHz" : "40MHz");
	return RETURN_OK;
}

//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) //Tr181	//AP only
{
	return RETURN_ERR;
}

//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) //Tr181
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex == 0) ? "" : "BelowControlChannel");
	return RETURN_OK;
}

//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) //Tr181	//AP only
{
	return RETURN_ERR;
}

//Get the guard interval value. eg "400nsec" or "800nsec"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string)	//Tr181
{
	//save config and apply instantly
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, (radioIndex == 0) ? "400nsec" : "400nsec");
	return RETURN_OK;
}

//Set the guard interval value.
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string)	//Tr181
{
	//Apply setting instantly
	return RETURN_ERR;
}

//Get the Modulation Coding Scheme index, eg: "-1", "1", "15"
INT wifi_getRadioMCS(INT radioIndex, INT *output_int) //Tr181
{
	if (NULL == output_int)
		return RETURN_ERR;
	if (radioIndex == 0)
		*output_int = 1;
	else
		*output_int = 3;
	return RETURN_OK;
}

//Set the Modulation Coding Scheme index
INT wifi_setRadioMCS(INT radioIndex, INT MCS) //Tr181
{
	return RETURN_ERR;
}



//Get current Transmit Power, eg "75", "100"
//The transmite power level is in units of full power for this radio.
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong)	//RDKB
{
	char cmd[128] = {0};
	char buf[256] = {0};
	INT apIndex;
	//save config and apply instantly

	if (NULL == output_ulong)
		return RETURN_ERR;

	//zqiu:TODO:save config
	apIndex = (radioIndex == 0) ? 0 : 1;

	snprintf(cmd, sizeof(cmd), "iwlist %s%d txpower | grep Tx-Power | cut -d'=' -f2", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));
	*output_ulong = atol(buf);

	return RETURN_OK;
}

//Set Transmit Power
//The transmite power level is in units of full power for this radio.
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower)	//RDKB
{
	char cmd[128] = {0};
	char buf[256] = {0};
	INT apIndex;

	apIndex = (radioIndex == 0) ? 0 : 1;

	snprintf(cmd, sizeof(cmd),  "iwconfig %s%d txpower %lu", AP_PREFIX, apIndex, TransmitPower);
	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;
}

//get 80211h Supported.  80211h solves interference with satellites and radar using the same 5 GHz frequency band
INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported)  //Tr181
{
	if (NULL == Supported)
		return RETURN_ERR;
	*Supported = FALSE;
	return RETURN_OK;
}

//Get 80211h feature enable
INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) //Tr181
{
	if (NULL == enable)
		return RETURN_ERR;
	*enable = FALSE;
	return RETURN_OK;
}

//Set 80211h feature enable
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable)  //Tr181
{
	return RETURN_ERR;
}

//Indicates the Carrier Sense ranges supported by the radio. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output)  //P3
{
	if (NULL == output)
		return RETURN_ERR;
	*output = 100;
	return RETURN_OK;
}

//The RSSI signal level at which CS/CCA detects a busy condition. This attribute enables APs to increase minimum sensitivity to avoid detecting busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output)	//P3
{
	if (NULL == output)
		return RETURN_ERR;
	*output = -99;
	return RETURN_OK;
}

INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold)	//P3
{
	return RETURN_ERR;
}


//Time interval between transmitting beacons (expressed in milliseconds). This parameter is based ondot11BeaconPeriod from [802.11-2012].
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output)
{
	if (NULL == output)
		return RETURN_ERR;
	*output = 100;
	return RETURN_OK;
}

INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod)
{
	return RETURN_ERR;
}

//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output)
{
	if (NULL == output)
		return RETURN_ERR;
	snprintf(output, 64, (radioIndex == 0) ? "1,2" : "1.5,150");
	return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates)
{
	return RETURN_ERR;
}

//Get detail radio traffic static info
INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *output_struct) //Tr181
{
	if (NULL == output_struct)
		return RETURN_ERR;

	//ifconfig radio_x
	output_struct->radio_BytesSent = 250;	//The total number of bytes transmitted out of the interface, including framing characters.
	output_struct->radio_BytesReceived = 168;	//The total number of bytes received on the interface, including framing characters.
	output_struct->radio_PacketsSent = 25;	//The total number of packets transmitted out of the interface.
	output_struct->radio_PacketsReceived = 20; //The total number of packets received on the interface.

	output_struct->radio_ErrorsSent = 0;	//The total number of outbound packets that could not be transmitted because of errors.
	output_struct->radio_ErrorsReceived = 0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
	output_struct->radio_DiscardPacketsSent = 0; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->radio_DiscardPacketsReceived = 0; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->radio_PLCPErrorCount = 0;	//The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.
	output_struct->radio_FCSErrorCount = 0;	//The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
	output_struct->radio_InvalidMACCount = 0;	//The number of packets that were received with a detected invalid MAC header error.
	output_struct->radio_PacketsOtherReceived = 0;	//The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
	output_struct->radio_NoiseFloor = -99;	//The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
	output_struct->radio_ChannelUtilization = 35; //Percentage of time the channel was occupied by the radio’s own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
	output_struct->radio_ActivityFactor = 2; //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_CarrierSenseThreshold_Exceeded = 20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
	output_struct->radio_RetransmissionMetirc = 0; //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage

	output_struct->radio_MaximumNoiseFloorOnChannel = -1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
	output_struct->radio_MinimumNoiseFloorOnChannel = -1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_MedianNoiseFloorOnChannel = -1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
	output_struct->radio_StatisticsStartTime = 0;     //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

	return RETURN_OK;
}

//Set radio traffic static Measureing rules
INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) //Tr181
{
	//zqiu:  If the RadioTrafficStats process running, and the new value is different from old value, the process needs to be reset. The Statistics date, such as MaximumNoiseFloorOnChannel, MinimumNoiseFloorOnChannel and MedianNoiseFloorOnChannel need to be reset. And the "StatisticsStartTime" must be reset to the current time. Units in Seconds
	//       Else, save the MeasuringRate and MeasuringInterval for future usage

	return RETURN_OK;
}

//To start or stop RadioTrafficStats
INT wifi_setRadioTrafficStatsRadioStatisticsEnable(INT radioIndex, BOOL enable)
{
	//zqiu:  If the RadioTrafficStats process running
	//	if(enable)
	//					return RETURN_OK.
	//				else
	//					Stop RadioTrafficStats process
	//       Else
	//				if(enable)
	//					Start RadioTrafficStats process with MeasuringRate and MeasuringInterval, and reset "StatisticsStartTime" to the current time, Units in Seconds
	//				else
	//					return RETURN_OK.

	return RETURN_OK;
}

//Clients associated with the AP over a specific interval.  The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm end of the range.  Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included in the respective bin.  The bin associated with the client?s current received signal level MUST be incremented when a client associates with the AP.   Additionally, the respective bins associated with each connected client?s current received signal level MUST be incremented at the interval defined by "Radio Statistics Measuring Rate".  The histogram?s bins MUST NOT be incremented at any other time.  The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by "Radio Statistics Measuring Interval".  The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval?. If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of data, it MUST return -1. Units dBm
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) //Tr181
{
	//zqiu: Please ignor signalIndex.
	if (NULL == SignalLevel)
		return RETURN_ERR;
	*SignalLevel = (radioIndex == 0) ? -19 : -19;
	return RETURN_OK;
}

//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applyRadioSettings(INT radioIndex)
{
	return RETURN_OK;
}

//Get the radio index assocated with this SSID entry
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex)
{
	if (NULL == radioIndex)
		return RETURN_ERR;
	*radioIndex = ssidIndex%2;
	return RETURN_OK;
}

//Get SSID enable configuration parameters (not the SSID enable status)
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) //Tr181
{
	if (NULL == output_bool)
		return RETURN_ERR;
	return wifi_getApEnable(ssidIndex, output_bool);
}

//Set SSID enable configuration parameters
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) //Tr181
{
	return wifi_setApEnable(ssidIndex, enable);
}

//Get the SSID enable status
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) //Tr181
{
	char cmd[128] = {0};
	char buf[128] = {0};

	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(cmd, sizeof(cmd), "ifconfig %s%d | grep %s%d", AP_PREFIX, ssidIndex, AP_PREFIX, ssidIndex);
	_syscmd(cmd, buf, sizeof(buf));

	snprintf(output_string, 64, (strlen(buf) > 5)?"Enabled":"Disabled");

	return RETURN_OK;
}

// Outputs a 32 byte or less string indicating the SSID name.  Sring buffer must be preallocated by the caller.
INT wifi_getSSIDName(INT apIndex, CHAR *output)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};

	if (NULL == output)
		return RETURN_ERR;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "ssid", output, 64);

	return RETURN_OK;

}

// Set a max 32 byte string and sets an internal variable to the SSID name
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string)
{
	//Set to wifi config. wait for wifi reset or wifi_pushSSID to apply
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;

	if (NULL == ssid_string)
		return RETURN_ERR;
	list.name = "ssid";
	list.value = ssid_string;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);

	wifi_hostapdWrite(config_file, &list, 1);

	return RETURN_OK;
}

//Get the BSSID
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string)	//RDKB
{
	char cmd[128] = {0};

	if (NULL == output_string)
		return RETURN_ERR;

	sprintf(cmd, "iw dev %s%d info |grep addr | awk '{printf $2}'", AP_PREFIX, ssidIndex);
	_syscmd(cmd, output_string, 64);

	return RETURN_OK;
}

//Get the MAC address associated with this Wifi SSID
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) //Tr181
{
	char cmd[128] = {0};

	if (NULL == output_string)
		return RETURN_ERR;

	sprintf(cmd, "iw dev %s%d info |grep addr | awk '{printf $2}'", AP_PREFIX, ssidIndex);
	_syscmd(cmd, output_string, 64);

	return RETURN_OK;
}

//Get the basic SSID traffic static info
INT wifi_getSSIDTrafficStats2(INT ssidIndex, wifi_ssidTrafficStats2_t *output_struct) //Tr181
{
	char cmd[128] = {0};
	char buf[1024] = {0};

	sprintf(cmd, "ifconfig %s%d ", AP_PREFIX, ssidIndex);
	_syscmd(cmd, buf, sizeof(buf));

	output_struct->ssid_BytesSent = 2048;	//The total number of bytes transmitted out of the interface, including framing characters.
	output_struct->ssid_BytesReceived = 4096;	//The total number of bytes received on the interface, including framing characters.
	output_struct->ssid_PacketsSent = 128;	//The total number of packets transmitted out of the interface.
	output_struct->ssid_PacketsReceived = 128; //The total number of packets received on the interface.

	output_struct->ssid_RetransCount = 0;	//The total number of transmitted packets which were retransmissions. Two retransmissions of the same packet results in this counter incrementing by two.
	output_struct->ssid_FailedRetransCount = 0; //The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit. This parameter is based on dot11FailedCount from [802.11-2012].
	output_struct->ssid_RetryCount = 0;  //The number of packets that were successfully transmitted after one or more retransmissions. This parameter is based on dot11RetryCount from [802.11-2012].
	output_struct->ssid_MultipleRetryCount = 0; //The number of packets that were successfully transmitted after more than one retransmission. This parameter is based on dot11MultipleRetryCount from [802.11-2012].
	output_struct->ssid_ACKFailureCount = 0;  //The number of expected ACKs that were never received. This parameter is based on dot11ACKFailureCount from [802.11-2012].
	output_struct->ssid_AggregatedPacketCount = 0; //The number of aggregated packets that were transmitted. This applies only to 802.11n and 802.11ac.

	output_struct->ssid_ErrorsSent = 0;	//The total number of outbound packets that could not be transmitted because of errors.
	output_struct->ssid_ErrorsReceived = 0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
	output_struct->ssid_UnicastPacketsSent = 2;	//The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
	output_struct->ssid_UnicastPacketsReceived = 2;  //The total number of received packets, delivered by this layer to a higher layer, which were not addressed to a multicast or broadcast address at this layer.
	output_struct->ssid_DiscardedPacketsSent = 1; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->ssid_DiscardedPacketsReceived = 1; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
	output_struct->ssid_MulticastPacketsSent = 10; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a multicast address at this layer, including those that were discarded or not sent.
	output_struct->ssid_MulticastPacketsReceived = 0; //The total number of received packets, delivered by this layer to a higher layer, which were addressed to a multicast address at this layer.
	output_struct->ssid_BroadcastPacketsSent = 0;  //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
	output_struct->ssid_BroadcastPacketsRecevied = 1; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
	output_struct->ssid_UnknownPacketsReceived = 0;  //The total number of packets received via the interface which were discarded because of an unknown or unsupported protocol.
	return RETURN_OK;
}

//Apply SSID and AP (in the case of Acess Point devices) to the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applySSIDSettings(INT ssidIndex)
{
	return RETURN_OK;
}

//Start the wifi scan and get the result into output buffer for RDKB to parser. The result will be used to manage endpoint list
//HAL funciton should allocate an data structure array, and return to caller with "neighbor_ap_array"
INT wifi_getNeighboringWiFiDiagnosticResult2(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size) //Tr181
{
	INT status = RETURN_ERR;
	UINT index;
	wifi_neighbor_ap2_t *pt = NULL;
	char cmd[128] = {0};
	char buf[8192] = {0};

	sprintf(cmd, "iwlist %s%d scan", AP_PREFIX, (radioIndex == 0) ? 0 : 1);	//suppose ap0 mapping to radio0
	_syscmd(cmd, buf, sizeof(buf));


	*output_array_size = 2;
	//zqiu: HAL alloc the array and return to caller. Caller response to free it.
	*neighbor_ap_array = (wifi_neighbor_ap2_t *)calloc(sizeof(wifi_neighbor_ap2_t), *output_array_size);
	for (index = 0, pt = *neighbor_ap_array; index < *output_array_size; index++, pt++) {
		strcpy(pt->ap_SSID, "");
		strcpy(pt->ap_BSSID, "");
		strcpy(pt->ap_Mode, "");
		pt->ap_Channel = 1;
		pt->ap_SignalStrength = 0;
		strcpy(pt->ap_SecurityModeEnabled, "");
		strcpy(pt->ap_EncryptionMode, "");
		strcpy(pt->ap_OperatingFrequencyBand, "");
		strcpy(pt->ap_SupportedStandards, "");
		strcpy(pt->ap_OperatingStandards, "");
		strcpy(pt->ap_OperatingChannelBandwidth, "");
		pt->ap_BeaconPeriod = 1;
		pt->ap_Noise = 0;
		strcpy(pt->ap_BasicDataTransferRates, "");
		strcpy(pt->ap_SupportedDataTransferRates, "");
		pt->ap_DTIMPeriod = 1;
		pt->ap_ChannelUtilization = 0;
	}

	status = RETURN_OK;
	return status;
}

//>> Deprecated: used for old RDKB code.
INT wifi_getRadioWifiTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct)
{
	INT status = RETURN_ERR;

	output_struct->wifi_PLCPErrorCount = 0;
	output_struct->wifi_FCSErrorCount = 0;
	output_struct->wifi_InvalidMACCount = 0;
	output_struct->wifi_PacketsOtherReceived = 0;
	output_struct->wifi_Noise = 0;
	status = RETURN_OK;
	return status;
}

INT wifi_getBasicTrafficStats(INT apIndex, wifi_basicTrafficStats_t *output_struct)
{
	char cmd[128];
	char buf[1280];
	char *pos = NULL;

	if (NULL == output_struct)
		return RETURN_ERR;

	memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

	snprintf(cmd, sizeof(cmd), "ifconfig %s%d", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	pos = buf;
	if ((pos = strstr(pos, "RX packets:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_PacketsReceived = atoi(pos+strlen("RX packets:"));

	if ((pos = strstr(pos, "TX packets:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_PacketsSent = atoi(pos+strlen("TX packets:"));

	if ((pos = strstr(pos, "RX bytes:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_BytesReceived = atoi(pos+strlen("RX bytes:"));

	if ((pos = strstr(pos, "TX bytes:")) == NULL)
		return RETURN_ERR;
	output_struct->wifi_BytesSent = atoi(pos+strlen("TX bytes:"));

	sprintf(cmd, "wlanconfig %s%d list sta | grep -v HTCAP | wc -l", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));
	sscanf(buf, "%lu", &output_struct->wifi_Associations);

	return RETURN_OK;
}

INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct)
{
	if (NULL == output_struct)
		return RETURN_ERR;

	memset(output_struct, 0, sizeof(wifi_trafficStats_t));
	return RETURN_OK;
}

INT wifi_getSSIDTrafficStats(INT apIndex, wifi_ssidTrafficStats_t *output_struct)
{
	INT status = RETURN_ERR;
	//Below values should get updated from hal
	output_struct->wifi_RetransCount = 0;
	output_struct->wifi_FailedRetransCount = 0;
	output_struct->wifi_RetryCount = 0;
	output_struct->wifi_MultipleRetryCount = 0;
	output_struct->wifi_ACKFailureCount = 0;
	output_struct->wifi_AggregatedPacketCount = 0;

	status = RETURN_OK;
	return status;
}

INT wifi_getNeighboringWiFiDiagnosticResult(wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size)
{
	INT status = RETURN_ERR;
	UINT index;
	wifi_neighbor_ap_t *pt = NULL;

	*output_array_size = 2;
	//zqiu: HAL alloc the array and return to caller. Caller response to free it.
	*neighbor_ap_array = (wifi_neighbor_ap_t *)calloc(sizeof(wifi_neighbor_ap_t), *output_array_size);
	for (index = 0, pt = *neighbor_ap_array; index < *output_array_size; index++, pt++) {
		strcpy(pt->ap_Radio, "");
		strcpy(pt->ap_SSID, "");
		strcpy(pt->ap_BSSID, "");
		strcpy(pt->ap_Mode, "");
		pt->ap_Channel = 1;
		pt->ap_SignalStrength = 0;
		strcpy(pt->ap_SecurityModeEnabled, "");
		strcpy(pt->ap_EncryptionMode, "");
		strcpy(pt->ap_OperatingFrequencyBand, "");
		strcpy(pt->ap_SupportedStandards, "");
		strcpy(pt->ap_OperatingStandards, "");
		strcpy(pt->ap_OperatingChannelBandwidth, "");
		pt->ap_BeaconPeriod = 1;
		pt->ap_Noise = 0;
		strcpy(pt->ap_BasicDataTransferRates, "");
		strcpy(pt->ap_SupportedDataTransferRates, "");
		pt->ap_DTIMPeriod = 1;
		pt->ap_ChannelUtilization = 1;
	}

	status = RETURN_OK;
	return status;
}

//----------------- AP HAL -------------------------------

//>> Deprecated: used for old RDKB code.
INT wifi_getAllAssociatedDeviceDetail(INT apIndex, ULONG *output_ulong, wifi_device_t **output_struct)
{
	if (NULL == output_ulong || NULL == output_struct)
		return RETURN_ERR;

	*output_ulong = 0;
	*output_struct = NULL;
	return RETURN_OK;
}

INT wifi_getAssociatedDeviceDetail(INT apIndex, INT devIndex, wifi_device_t *output_struct)
{
	if (NULL == output_struct)
		return RETURN_ERR;
	memset(output_struct, 0, sizeof(wifi_device_t));
	return RETURN_OK;
}

INT wifi_kickAssociatedDevice(INT apIndex, wifi_device_t *device)
{
	if (NULL == device)
		return RETURN_ERR;
	return RETURN_OK;
}
//<<


//--------------wifi_ap_hal-----------------------------
//enables CTS protection for the radio used by this AP
INT wifi_setRadioCtsProtectionEnable(INT apIndex, BOOL enable)
{
	//save config and Apply instantly
	return RETURN_ERR;
}

// enables OBSS Coexistence - fall back to 20MHz if necessary for the radio used by this ap
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable)
{
	//save config and Apply instantly
	return RETURN_ERR;
}

//P3 // sets the fragmentation threshold in bytes for the radio used by this ap
INT wifi_setRadioFragmentationThreshold(INT apIndex, UINT threshold)
{
	char cmd[64];
	char buf[512];
	//save config and apply instantly

	//zqiu:TODO: save config
	if (threshold > 0)
		snprintf(cmd, sizeof(cmd),  "iwconfig %s%d frag %d", AP_PREFIX, apIndex, threshold);
	else
		snprintf(cmd, sizeof(cmd),  "iwconfig %s%d frag off", AP_PREFIX, apIndex);

	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;
}

// enable STBC mode in the hardwarwe, 0 == not enabled, 1 == enabled
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable)
{
	//Save config and Apply instantly
	return RETURN_ERR;
}

// outputs A-MSDU enable status, 0 == not enabled, 1 == enabled
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool)
{
	return RETURN_ERR;
}

// enables A-MSDU in the hardware, 0 == not enabled, 1 == enabled
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable)
{
	//Apply instantly
	return RETURN_ERR;
}

//P2  // outputs the number of Tx streams
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int)
{
	return RETURN_ERR;
}

//P2  // sets the number of Tx streams to an enviornment variable
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams)
{
	//save to wifi config, wait for wifi reset or wifi_pushTxChainMask to apply
	return RETURN_ERR;
}

//P2  // outputs the number of Rx streams
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int)
{
	if (NULL == output_int)
		return RETURN_ERR;
	*output_int = 1;
	return RETURN_OK;
}

//P2  // sets the number of Rx streams to an enviornment variable
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams)
{
	//save to wifi config, wait for wifi reset or wifi_pushRxChainMask to apply
	return RETURN_ERR;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantSupported(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Set radio RDG enable setting
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio ADDBA enable setting
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Set radio ADDBA enable setting
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio auto block ack enable setting
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Set radio auto block ack enable setting
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio 11n pure mode enable support
INT wifi_getRadio11nGreenfieldSupported(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Get radio 11n pure mode enable setting
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Set radio 11n pure mode enable setting
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get radio IGMP snooping enable setting
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool)
{
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

//Set radio IGMP snooping enable setting
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable)
{
	return RETURN_ERR;
}

//Get the Reset count of radio
INT wifi_getRadioResetCount(INT radioIndex, ULONG *output_int)
{

	if (NULL == output_int)
		return RETURN_ERR;
	if (radioIndex == 0)
		*output_int = 1;
	else
		*output_int = 3;
	return RETURN_OK;
}


//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------

// creates a new ap and pushes these parameters to the hardware
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid)
{
	char buf[1024];
	char cmd[128];

	if (NULL == essid)
		return RETURN_ERR;

	snprintf(cmd, sizeof(cmd), "wlanconfig %s%d create wlandev %s%d wlanmode ap", AP_PREFIX, apIndex, RADIO_PREFIX, radioIndex);
	_syscmd(cmd, buf, sizeof(buf));

	snprintf(cmd, sizeof(cmd), "iwconfig %s%d essid %s mode master", AP_PREFIX, apIndex, essid);
	_syscmd(cmd, buf, sizeof(buf));

	wifi_pushSsidAdvertisementEnable(apIndex, !hideSsid);

	snprintf(cmd, sizeof(cmd), "ifconfig %s%d txqueuelen 1000", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;

}

// deletes this ap entry on the hardware, clears all internal variables associaated with this ap
INT wifi_deleteAp(INT apIndex)
{
	char buf[1024];
	char cmd[128];

	snprintf(cmd, sizeof(cmd),  "wlanconfig %s%d destroy", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	wifi_removeApSecVaribles(apIndex);

	return RETURN_OK;
}

// Outputs a 16 byte or less name assocated with the AP.  String buffer must be pre-allocated by the caller
INT wifi_getApName(INT apIndex, CHAR *output_string)
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 16, "%s%d", AP_PREFIX, apIndex);
	return RETURN_OK;
}

// Outputs the index number in that corresponds to the SSID string
INT wifi_getIndexFromName(CHAR *inputSsidString, INT *ouput_int)
{
	CHAR *pos = NULL;

	*ouput_int = -1;
	pos = strstr(inputSsidString, AP_PREFIX);
	if (pos) {
		sscanf(pos+sizeof(AP_PREFIX), "%d", ouput_int);
		return RETURN_OK;
	}
	return RETURN_ERR;
}

// Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i"
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};

	if (NULL == output_string)
		return RETURN_ERR;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "wpa", buf, 64);
	if ((strcmp(buf, "3") == 0))
		snprintf(output_string, 32, "WPAand11i");
	else if ((strcmp(buf, "2") == 0))
		snprintf(output_string, 32, "11i");
	else if ((strcmp(buf, "1") == 0))
		snprintf(output_string, 32, "WPA");
	else
		snprintf(output_string, 32, "None");

	return RETURN_OK;

}

// Sets the beacon type enviornment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString)
{
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;

	if (NULL == beaconTypeString)
		return RETURN_ERR;
	list.name = "wpa";
	list.value = "0";
	if ((strcmp(beaconTypeString, "WPAand11i") == 0))
		list.value = "3";
	else if ((strcmp(beaconTypeString, "11i") == 0))
		list.value = "2";
	else if ((strcmp(beaconTypeString, "WPA") == 0))
		list.value = "1";

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdWrite(config_file, &list, 1);
	//save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
	return RETURN_OK;

}

// sets the beacon interval on the hardware for this AP
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval)
{
	//save config and apply instantly
	return RETURN_ERR;
}

INT wifi_setDTIMInterval(INT apIndex, INT dtimInterval)
{
	//save config and apply instantly
	return RETURN_ERR;
}

// Get the packet size threshold supported.
INT wifi_getApRtsThresholdSupported(INT apIndex, BOOL *output_bool)
{
	//save config and apply instantly
	if (NULL == output_bool)
		return RETURN_ERR;
	*output_bool = FALSE;
	return RETURN_OK;
}

// sets the packet size threshold in bytes to apply RTS/CTS backoff rules.
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold)
{
	char cmd[128];
	char buf[512];

	if (threshold > 0)
		snprintf(cmd, sizeof(cmd), "iwconfig %s%d rts %d", AP_PREFIX, apIndex, threshold);
	else
		snprintf(cmd, sizeof(cmd), "iwconfig %s%d rts off", AP_PREFIX, apIndex);

	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;
}

// ouputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptoinMode(INT apIndex, CHAR *output_string)
{
	if (NULL == output_string)
		return RETURN_ERR;
	snprintf(output_string, 32, "TKIPandAESEncryption");
	return RETURN_OK;

}

// sets the encyption mode enviornment variable.  Valid string format is "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode)
{
	//Save the encMode to wifi config and hostpad config. wait for wifi restart or hotapd restart to apply
	return RETURN_ERR;
}

// deletes internal security varable settings for this ap
INT wifi_removeApSecVaribles(INT apIndex)
{
	//TODO: remove the entry in hostapd config file
	//snprintf(cmd,sizeof(cmd), "sed -i 's/\\/nvram\\/etc\\/wpa2\\/WSC_%s%d.conf//g' /tmp/conf_filename", AP_PREFIX, apIndex);
	//_syscmd(cmd, buf, sizeof(buf));

	//snprintf(cmd,sizeof(cmd), "sed -i 's/\\/tmp\\//sec%s%d//g' /tmp/conf_filename", AP_PREFIX, apIndex);
	//_syscmd(cmd, buf, sizeof(buf));
	return RETURN_ERR;
}

// changes the hardware settings to disable encryption on this ap
INT wifi_disableApEncryption(INT apIndex)
{
	//Apply instantly
	return RETURN_ERR;
}

// set the authorization mode on this ap
// mode mapping as: 1: open, 2: shared, 4:auto
INT wifi_setApAuthMode(INT apIndex, INT mode)
{
	//Apply instantly
	return RETURN_ERR;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
	//save to wifi config, and wait for wifi restart to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	struct params params = {'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	int ret;

	if (authMode ==  NULL)
		return RETURN_ERR;
	wifi_dbg_printf("\n%s AuthMode=%s", __func__, authMode);
	params.name = "wpa_key_mgmt";
	if ((strcmp(authMode, "PSKAuthentication") == 0) || (strcmp(authMode, "SharedAuthentication") == 0))
		params.value = "WPA-PSK";
	else if (strcmp(authMode, "EAPAuthentication") == 0)
		params.value = "WPA-EAP";
	else if (strcmp(authMode, "None") == 0) //Donot change in case the authMode is None
		return RETURN_OK;                         //This is taken careof in beaconType
	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	ret = wifi_hostapdWrite(config_file, &params, 1);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return ret;

}

// Outputs the number of stations associated per AP
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
	char cmd[128] = {0};
	char buf[128] = {0};

	sprintf(cmd, "hostapd_cli -i %s%d list_sta | wc -l", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));
	sscanf(buf, "%lu", output_ulong);
	return RETURN_OK;
}

// manually removes any active wi-fi association with the device specified on this ap
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac)
{
	return RETURN_ERR;
}

// outputs the radio index for the specified ap. similar as wifi_getSsidRadioIndex
INT wifi_getApRadioIndex(INT apIndex, INT *output_int)
{
	*output_int = apIndex%2;
	return RETURN_OK;
}

// sets the radio index for the specific ap
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex)
{
	//set to config only and wait for wifi reset to apply settings
	return RETURN_ERR;
}

// Get the ACL MAC list per AP
INT wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size)
{
	char cmd[MAX_CMD_SIZE] = {'\0'};
	int ret = 0;
	//sprintf(cmd, "cat %s%d",ACL_PREFIX,apIndex);
	sprintf(cmd, "hostapd_cli -i %s%d accept_acl SHOW | awk '{print $1}'", AP_PREFIX, apIndex);
	ret = _syscmd(cmd, macArray, buf_size);
	if (ret != 0)
		return RETURN_ERR;
	return RETURN_OK;
}

// Get the list of stations assocated per AP
INT wifi_getApDevicesAssociated(INT apIndex, CHAR *macArray, UINT buf_size)
{
	char cmd[128];

	sprintf(cmd, "hostapd_cli -i %s%d list_sta", AP_PREFIX, apIndex);
	_syscmd(cmd, macArray, buf_size);

	return RETURN_OK;
}

// adds the mac address to the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
	char cmd[MAX_CMD_SIZE] = {'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	int ret = 0;

	sprintf(cmd, "hostapd_cli -i %s%d accept_acl ADD_MAC %s", AP_PREFIX, apIndex, DeviceMacAddress);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if (ret != 0)
		return RETURN_ERR;

	return RETURN_OK;

}

// deletes the mac address from the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
	char cmd[MAX_CMD_SIZE] = {'\0'};
	char buf[MAX_BUF_SIZE] = {'\0'};
	char acl_file[MAX_BUF_SIZE] = {0};
	int ret = 0;

	sprintf(cmd, "hostapd_cli -i %s%d accept_acl DEL_MAC %s", AP_PREFIX, apIndex, DeviceMacAddress);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if (ret != 0)
		return RETURN_ERR;

	return RETURN_OK;
}

// outputs the number of devices in the filter list
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint)
{
	if (NULL == output_uint)
		return RETURN_ERR;
	*output_uint = 0;
	return RETURN_ERR;
}

// enable kick for devices on acl black list
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable)
{
	char aclArray[512] = {0}, *acl = NULL;
	char assocArray[512] = {0}, *asso = NULL;

	wifi_getApAclDevices(apIndex, aclArray, sizeof(aclArray));
	wifi_getApDevicesAssociated(apIndex, assocArray, sizeof(assocArray));

	// if there are no devices connected there is nothing to do
	if (strlen(assocArray) < 17)
		return RETURN_OK;

	if (enable == TRUE) {
		//kick off the MAC which is in ACL array (deny list)
		acl = strtok(aclArray, "\r\n");
		while (acl != NULL) {
			if (strlen(acl) >= 17 && strcasestr(assocArray, acl))
				wifi_kickApAssociatedDevice(apIndex, acl);

			acl = strtok(NULL, "\r\n");
		}
	} else {
		//kick off the MAC which is not in ACL array (allow list)
		asso = strtok(assocArray, "\r\n");
		while (asso != NULL) {
			if (strlen(asso) >= 17 && !strcasestr(aclArray, asso))
				wifi_kickApAssociatedDevice(apIndex, asso);

			asso = strtok(NULL, "\r\n");
		}
	}

	return RETURN_OK;
}

// sets the mac address filter control mode.  0 == filter disabled, 1 == filter as whitelist, 2 == filter as blacklist
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	char acl_file[MAX_BUF_SIZE] = {0};
	struct params list[2];
	int items = 1;

	list[0].name = "macaddr_acl";
	sprintf(buf, "%d", filterMode);
	list[0].value = buf;

	if (filterMode == 1) {
		sprintf(acl_file, "%s%d", ACL_PREFIX, apIndex);
		list[1].name = "accept_mac_file";
		list[1].value = acl_file;
		items = 2;
	}

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdWrite(config_file, &list, items);
	return RETURN_OK;
}

// enables internal gateway VLAN mode.  In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.  VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE.
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled)
{
	return RETURN_ERR;
}

// gets the vlan ID for this ap from an internal enviornment variable
INT wifi_getApVlanID(INT apIndex, INT *output_int)
{
	if (apIndex == 0) {
		*output_int = 100;
		return RETURN_OK;
	}

	return RETURN_ERR;
}

// sets the vlan ID for this ap to an internal enviornment variable
INT wifi_setApVlanID(INT apIndex, INT vlanId)
{
	//save the vlanID to config and wait for wifi reset to apply (wifi up module would read this parameters and tag the AP with vlan id)
	return RETURN_ERR;
}

// gets bridgeName, IP address and Subnet. bridgeName is a maximum of 32 characters,
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
	snprintf(bridgeName, 32, "br-home");
	snprintf(IP, 64, "10.0.0.2");
	snprintf(subnet, 64, "255.255.255.0");

	return RETURN_OK;
}

//sets bridgeName, IP address and Subnet to internal enviornment variables. bridgeName is a maximum of 32 characters,
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
	//save settings, wait for wifi reset or wifi_pushBridgeInfo to apply.
	return RETURN_ERR;
}

// reset the vlan configuration for this ap
INT wifi_resetApVlanCfg(INT apIndex)
{
	//TODO: remove existing vlan for this ap

	//Reapply vlan settings
	wifi_pushBridgeInfo(apIndex);

	return RETURN_ERR;
}

// creates configuration variables needed for WPA/WPS.  These variables are implementation dependent and in some implementations these variables are used by hostapd when it is started.  Specific variables that are needed are dependent on the hostapd implementation. These variables are set by WPA/WPS security functions in this wifi HAL.  If not needed for a particular implementation this function may simply return no error.
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg)
{
	return RETURN_ERR;
}

// starts hostapd, uses the variables in the hostapd config with format compatible with the specific hostapd implementation
INT wifi_startHostApd()
{
	char cmd[128] = {0};
	char buf[128] = {0};

	sprintf(cmd, "hostapd  -B `cat /tmp/conf_filename` -e /nvram/etc/wpa2/entropy -P /tmp/hostapd.pid 1>&2");
	_syscmd(cmd, buf, sizeof(buf));
	return RETURN_OK;
}

 // stops hostapd
INT wifi_stopHostApd()
{
	char cmd[128] = {0};
	char buf[128] = {0};

	sprintf(cmd, "systemctl stop hostapd-global");
	_syscmd(cmd, buf, sizeof(buf));

	return RETURN_OK;
}

// sets the AP enable status variable for the specified ap.
INT wifi_setApEnable(INT apIndex, BOOL enable)
{
	char config_file[MAX_BUF_SIZE] = {0};

	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int ret = 0;

	if (enable == TRUE) {
		sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
		//Hostapd will bring up this interface
		sprintf(cmd, "hostapd_cli -i global raw ADD bss_config=%s%d:%s", AP_PREFIX, apIndex, config_file);
		_syscmd(cmd, buf, sizeof(buf));
	} else {

		sprintf(cmd, "hostapd_cli -i global raw REMOVE %s%d", AP_PREFIX, apIndex);
		_syscmd(cmd, buf, sizeof(buf));
		sprintf(cmd, "ip link set %s%d down", AP_PREFIX, apIndex);
		_syscmd(cmd, buf, sizeof(buf));

	}
	//Store the AP enable settings and wait for wifi up to apply
	return RETURN_OK;
}

// Outputs the setting of the internal variable that is set by wifi_setEnable().
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
	if (!output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

// Outputs the AP "Enabled" "Disabled" status from driver
INT wifi_getApStatus(INT apIndex, CHAR *output_string)
{
	char cmd[128] = {0};
	char buf[128] = {0};

	sprintf(cmd, "ifconfig  | grep %s%d", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	if (strlen(buf) > 3)
		snprintf(output_string, 32, "Up");
	else
		snprintf(output_string, 32, "Disable");
	return RETURN_OK;
}

//Indicates whether or not beacons include the SSID name.
// outputs a 1 if SSID on the AP is enabled, else ouputs 0
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output)
{
	//get the running status
	char config_file[MAX_BUF_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};

	if (!output)
		return RETURN_ERR;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "ignore_broadcast_ssid", buf, 64);
	*output = (strncmp("0", buf, 1) == 0);
	return RETURN_OK;
}

// sets an internal variable for ssid advertisement.  Set to 1 to enable, set to 0 to disable
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;

	list.name = "ignore_broadcast_ssid";
	list.value = enable?"0":"1";

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdWrite(config_file, &list, 1);

	return RETURN_OK;
}

//The maximum number of retransmission for a packet. This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
INT wifi_getApRetryLimit(INT apIndex, UINT *output_uint)
{
	//get the running status
	if (!output_uint)
		return RETURN_ERR;
	*output_uint = 15;
	return RETURN_OK;
}

INT wifi_setApRetryLimit(INT apIndex, UINT number)
{
	//apply instantly
	return RETURN_ERR;
}

//Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
INT wifi_getApWMMCapability(INT apIndex, BOOL *output)
{
	if (!output)
		return RETURN_ERR;
	*output = TRUE;
	return RETURN_OK;
}

//Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD). Note: U-APSD support implies WMM support.
INT wifi_getApUAPSDCapability(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if (!output)
		return RETURN_ERR;
	*output = TRUE;
	return RETURN_OK;
}

//Whether WMM support is currently enabled. When enabled, this is indicated in beacon frames.
INT wifi_getApWmmEnable(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if (!output)
		return RETURN_ERR;
	*output = TRUE;
	return RETURN_OK;
}

// enables/disables WMM on the hardwawre for this AP.  enable==1, disable == 0
INT wifi_setApWmmEnable(INT apIndex, BOOL enable)
{
	//Save config and apply instantly.
	return RETURN_ERR;
}

//Whether U-APSD support is currently enabled. When enabled, this is indicated in beacon frames. Note: U-APSD can only be enabled if WMM is also enabled.
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if (!output)
		return RETURN_ERR;
	*output = TRUE;
	return RETURN_OK;
}

// enables/disables Automatic Power Save Delivery on the hardwarwe for this AP
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable)
{
	//save config and apply instantly.
	return RETURN_ERR;
}

// Sets the WMM ACK polity on the hardware. AckPolicy false means do not acknowledge, true means acknowledge
INT wifi_setApWmmOgAckPolicy(INT apIndex, INT class, BOOL ackPolicy)  //RDKB
{
	//save config and apply instantly.
	return RETURN_ERR;
}

//Enables or disables device isolation.	A value of true means that the devices connected to the Access Point are isolated from all other devices within the home network (as is typically the case for a Wireless Hotspot).
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output)
{
	//get the running status from driver
	if (!output)
		return RETURN_ERR;
	*output = TRUE;
	return RETURN_OK;
}

INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
	//store the config, apply instantly
	return RETURN_ERR;
}

//The maximum number of devices that can simultaneously be connected to the access point. A value of 0 means that there is no specific limit.
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output_uint)
{
	//get the running status from driver
	if (!output_uint)
		return RETURN_ERR;
	*output_uint = 5;
	return RETURN_OK;
}

INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number)
{
	//store to wifi config, apply instantly
	return RETURN_ERR;
}

//The HighWatermarkThreshold value that is lesser than or equal to MaxAssociatedDevices. Setting this parameter does not actually limit the number of clients that can associate with this access point as that is controlled by MaxAssociatedDevices.	MaxAssociatedDevices or 50. The default value of this parameter should be equal to MaxAssociatedDevices. In case MaxAssociatedDevices is 0 (zero), the default value of this parameter should be 50. A value of 0 means that there is no specific limit and Watermark calculation algorithm should be turned off.
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output_uint)
{
	//get the current threshold
	if (!output_uint)
		return RETURN_ERR;
	*output_uint = 50;
	return RETURN_OK;
}

INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold)
{
	//store the config, reset threshold, reset AssociatedDevicesHighWatermarkThresholdReached, reset AssociatedDevicesHighWatermarkDate to current time
	return RETURN_ERR;
}

//Number of times the current total number of associated device has reached the HighWatermarkThreshold value. This calculation can be based on the parameter AssociatedDeviceNumberOfEntries as well. Implementation specifics about this parameter are left to the product group and the device vendors. It can be updated whenever there is a new client association request to the access point.
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output_uint)
{
	if (!output_uint)
		return RETURN_ERR;
	*output_uint = 3;
	return RETURN_OK;
}

//Maximum number of associated devices that have ever associated with the access point concurrently since the last reset of the device or WiFi module.
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output_uint)
{
	if (!output_uint)
		return RETURN_ERR;
	*output_uint = 3;
	return RETURN_OK;
}

//Date and Time at which the maximum number of associated devices ever associated with the access point concurrenlty since the last reset of the device or WiFi module (or in short when was X_COMCAST-COM_AssociatedDevicesHighWatermark updated). This dateTime value is in UTC.
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds)
{
	if (!output_in_seconds)
		return RETURN_ERR;
	*output_in_seconds = 0;
	return RETURN_OK;
}

//Comma-separated list of strings. Indicates which security modes this AccessPoint instance is capable of supporting. Each list item is an enumeration of: None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output)
{
	if (!output)
		return RETURN_ERR;
	snprintf(output, 128, "None,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise");
	return RETURN_OK;
}

//The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output)
{
	//save to wifi config, and wait for wifi restart to apply
	char config_file[MAX_BUF_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};

	if (!output)
		return RETURN_ERR;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "wpa", buf, 64);
	if ((strcmp(buf, "3") == 0))
		snprintf(output, 128, "WPA-WPA2-Personal");
	else if ((strcmp(buf, "2") == 0))
		snprintf(output, 128, "WPA2-Personal");
	else if ((strcmp(buf, "1") == 0))
		snprintf(output, 128, "WPA-Personal");

	//save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
	return RETURN_OK;

}

INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode)
{
	//store settings and wait for wifi up to apply
	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
	char securityType[32];
	char authMode[32];

	if (!encMode)
		return RETURN_ERR;

	printf("%s: apIndex %d, encMode %s\n", __func__, apIndex, encMode);

	if (strcmp(encMode, "None") == 0) {
		strcpy(securityType, "None");
		strcpy(authMode, "None");
	} else if (strcmp(encMode, "WPA-WPA2-Personal") == 0) {
		strcpy(securityType, "WPAand11i");
		 strcpy(authMode, "PSKAuthentication");
	} else if (strcmp(encMode, "WPA-WPA2-Enterprise") == 0) {
		strcpy(securityType, "WPAand11i");
		strcpy(authMode, "EAPAuthentication");
	} else if (strcmp(encMode, "WPA-Personal") == 0) {
		strcpy(securityType, "WPA");
		strcpy(authMode, "PSKAuthentication");
	} else if (strcmp(encMode, "WPA-Enterprise") == 0) {
		strcpy(securityType, "WPA");
		strcpy(authMode, "EAPAuthentication");
	} else if (strcmp(encMode, "WPA2-Personal") == 0) {
		strcpy(securityType, "11i");
		strcpy(authMode, "PSKAuthentication");
	} else if (strcmp(encMode, "WPA2-Enterprise") == 0) {
		strcpy(securityType, "11i");
		strcpy(authMode, "EAPAuthentication");
	} else {
		strcpy(securityType, "None");
		strcpy(authMode, "None");
	}
	wifi_setApBeaconType(apIndex, securityType);
	wifi_setApBasicAuthenticationMode(apIndex, authMode);
	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
	return RETURN_OK;

}

//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
// output_string must be pre-allocated as 64 character string by caller
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string)
{
	if (!output_string)
		return RETURN_ERR;
	snprintf(output_string, 64, "E4A7A43C99DFFA57");
	return RETURN_OK;
}

// sets an enviornment variable for the psk. Input string preSharedKey must be a maximum of 64 characters
// PSK Key of 8 to 63 characters is considered an ASCII string, and 64 characters are considered as HEX value
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey)
{
	//save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
	return RETURN_ERR;
}

//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
// outputs the passphrase, maximum 63 characters
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};

	if (NULL == output)
		return RETURN_ERR;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "wpa_passphrase", output, 64);

	return RETURN_OK;
}

// sets the passphrase enviornment variable, max 63 characters
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase)
{
	//save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
	struct params params = {'\0'};
	char config_file[MAX_BUF_SIZE] = {0};
	int ret;

	if (NULL == passPhrase)
		return RETURN_ERR;
	params.name = "wpa_passphrase";
	params.value = passPhrase;
	if (strlen(passPhrase) < 8 || strlen(passPhrase) > 63) {
		wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
		return RETURN_ERR;
	}

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	ret = wifi_hostapdWrite(config_file, &params, 1);
	return ret;
}

//When set to true, this AccessPoint instance's WiFi security settings are reset to their factory default values. The affected settings include ModeEnabled, WEPKey, PreSharedKey and KeyPassphrase.
INT wifi_setApSecurityReset(INT apIndex)
{
	//apply instantly
	return RETURN_ERR;
}

//The IP Address and port number of the RADIUS server used for WLAN security. RadiusServerIPAddr is only applicable when ModeEnabled is an Enterprise type (i.e. WPA-Enterprise, WPA2-Enterprise or WPA-WPA2-Enterprise).
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
	if (!IP_output || !Port_output || !RadiusSecret_output)
		return RETURN_ERR;
	snprintf(IP_output, 64, "75.56.77.78");
	*Port_output = 123;
	snprintf(RadiusSecret_output, 64, "12345678");
	return RETURN_OK;
}

INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
	//store the paramters, and apply instantly
	return RETURN_ERR;
}

INT wifi_getApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
	if (!IP_output || !Port_output || !RadiusSecret_output)
		return RETURN_ERR;
	snprintf(IP_output, 64, "75.56.77.78");
	*Port_output = 123;
	snprintf(RadiusSecret_output, 64, "12345678");
	return RETURN_OK;
}

INT wifi_setApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
	//store the paramters, and apply instantly
	return RETURN_ERR;
}

//RadiusSettings
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output)
{
	if (!output)
		return RETURN_ERR;

	output->RadiusServerRetries = 3;				//Number of retries for Radius requests.
	output->RadiusServerRequestTimeout = 5;		//Radius request timeout in seconds after which the request must be retransmitted for the # of retries available.
	output->PMKLifetime = 28800;					//Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs).
	output->PMKCaching = FALSE;					//Enable or disable caching of PMK.
	output->PMKCacheInterval = 300;				//Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes).
	output->MaxAuthenticationAttempts = 3;		//Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature.
	output->BlacklistTableTimeout = 600;			//Time interval in seconds for which a client will continue to be blacklisted once it is marked so.
	output->IdentityRequestRetryInterval = 5;	//Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.
	output->QuietPeriodAfterFailedAuthentication = 5;	//The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it.
	//snprintf(output->RadiusSecret, 64, "12345678");		//The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

	return RETURN_OK;
}

INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input)
{
	//store the paramters, and apply instantly
	return RETURN_ERR;
}

//Enables or disables WPS functionality for this access point.
// outputs the WPS enable state of this ap in output_bool
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool)
{
	if (!output_bool)
		return RETURN_ERR;
	*output_bool = TRUE;
	return RETURN_OK;
}

// sets the WPS enable enviornment variable for this ap to the value of enableValue, 1==enabled, 0==disabled
INT wifi_setApWpsEnable(INT apIndex, BOOL enableValue)
{
	//store the paramters, and wait for wifi up to apply
	return RETURN_ERR;
}

//Comma-separated list of strings. Indicates WPS configuration methods supported by the device. Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output)
{
	if (!output)
		return RETURN_ERR;
	snprintf(output, 128, "PushButton,PIN");
	return RETURN_OK;
}

//Comma-separated list of strings. Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter. Indicates WPS configuration methods enabled on the device.
// Outputs a common separated list of the enabled WPS config methods, 64 bytes max
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output)
{
	if (!output)
		return RETURN_ERR;
	snprintf(output, 128, "PushButton,PIN");
	return RETURN_OK;
}

// sets an enviornment variable that specifies the WPS configuration method(s).  methodString is a comma separated list of methods USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString)
{
	//apply instantly. No setting need to be stored.
	return RETURN_ERR;
}

// outputs the pin value, ulong_pin must be allocated by the caller
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong)
{
	if (!output_ulong)
		return RETURN_ERR;
	*output_ulong = 45276457;
	return RETURN_OK;
}

// set an enviornment variable for the WPS pin for the selected AP. Normally, Device PIN should not be changed.
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin)
{
	//set the pin to wifi config and hostpad config. wait for wifi reset or hostapd reset to apply
	return RETURN_ERR;
}

// Output string is either Not configured or Configured, max 32 characters
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string)
{
	char cmd[64] = {0};
	char buf[512] = {0};
	char *pos = NULL;

	snprintf(output_string, 64, "Not configured");

	sprintf(cmd, "hostapd_cli -i %s%d get_config", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	if ((pos = strstr(buf, "wps_state=")) != NULL) {
		if (strstr(pos, "configured") != NULL)
			snprintf(output_string, 64, "Configured");
	}
	return RETURN_OK;
}

// sets the WPS pin for this AP
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin)
{
	char cmd[64] = {0};
	char buf[256] = {0};
	BOOL enable;

	wifi_getApEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;

	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;

	snprintf(cmd, 64, "hostapd_cli -i%s%d wps_pin any %s", AP_PREFIX, apIndex, pin);
	_syscmd(cmd, buf, sizeof(buf));

	if ((strstr(buf, "OK")) != NULL)
		return RETURN_OK;
	else
		return RETURN_ERR;
}

// This function is called when the WPS push button has been pressed for this AP
INT wifi_setApWpsButtonPush(INT apIndex)
{
	char cmd[64] = {0};
	char buf[256] = {0};
	BOOL enable;

	wifi_getApEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;

	wifi_getApWpsEnable(apIndex, &enable);
	if (!enable)
		return RETURN_ERR;

	snprintf(cmd, 64, "hostapd_cli -i%s%d wps_cancel; hostapd_cli -i%s%d wps_pbc", AP_PREFIX, apIndex, AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	if ((strstr(buf, "OK")) != NULL)
		return RETURN_OK;
	else
		return RETURN_ERR;
}

// cancels WPS mode for this AP
INT wifi_cancelApWPS(INT apIndex)
{
	char cmd[64] = {0};
	char buf[256] = {0};

	snprintf(cmd, 64, "hostapd_cli -i%s%d wps_cancel", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	if ((strstr(buf, "OK")) != NULL)
		return RETURN_OK;
	else
		return RETURN_ERR;
}

//Get the ApManagementFramePowerControl
INT wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm)
{
	if (NULL == output_dBm)
		return RETURN_ERR;

	*output_dBm = 0;
	return RETURN_OK;
}
//Set the ApManagementFramePowerControl
INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
	return RETURN_ERR;
}
//Device.WiFi.AccessPoint.{i}.AssociatedDevice.*
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size)
{
	char cmd[256];
	char buf[2048];
	wifi_associated_dev_t *dev = NULL;
	unsigned int assoc_cnt = 0;
	char *pos;
	FILE *f;
	char *mac = NULL;
	char *aid = NULL;
	char *chan = NULL;
	char *txrate = NULL;
	char *rxrate = NULL;
	char *rssi = NULL;

	*output_array_size = 0;
	*associated_dev_array = NULL;

	if (apIndex < 0)
		return RETURN_ERR;

	sprintf(cmd,  "wlanconfig %s%d list sta  2>/dev/null | grep -v HTCAP >/tmp/ap_%d_cli.txt; cat /tmp/ap_%d_cli.txt | wc -l", AP_PREFIX, apIndex, apIndex, apIndex);
	_syscmd(cmd, buf, sizeof(buf));

	*output_array_size = atoi(buf);

	if (*output_array_size <= 0)
		return RETURN_OK;

	dev = (wifi_associated_dev_t *) calloc(*output_array_size, sizeof(wifi_associated_dev_t));
	*associated_dev_array = dev;

	sprintf(cmd, "cat /tmp/ap_%d_cli.txt", apIndex);
	if ((f = popen(cmd, "r")) == NULL) {
		printf("%s: popen %s error\n", __func__, cmd);
		return -1;
	}

	while (!feof(f)) {
		pos = buf;
		*pos = 0;
		fgets(pos, 200, f);

		if (strlen(pos) == 0)
			break;

		if (assoc_cnt >= *output_array_size)
			break;

		char *mac = strtok(pos, " ");
		char *aid = strtok('\0', " ");
		char *chan = strtok('\0', " ");
		char *txrate = strtok('\0', " ");
		char *rxrate = strtok('\0', " ");
		char *rssi = strtok('\0', " ");

		// Should be Mac Address line
		if (mac) {
			sscanf(mac, "%x:%x:%x:%x:%x:%x",
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[0],
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[1],
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[2],
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[3],
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[4],
				   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[5]);
		}

		memset(dev[assoc_cnt].cli_IPAddress, 0, 64);
		dev[assoc_cnt].cli_AuthenticationState = 1;

		dev[assoc_cnt].cli_AuthenticationState = (rssi != NULL) ? atoi(rssi) - 100 : 0;
		dev[assoc_cnt].cli_LastDataDownlinkRate = (txrate != NULL) ? atoi(strtok(txrate, "M")) : 0;
		dev[assoc_cnt].cli_LastDataUplinkRate = (rxrate != NULL) ? atoi(strtok(rxrate, "M")) : 0;

		//zqiu: TODO: fill up the following items
		dev[assoc_cnt].cli_SignalStrength = -100;
		dev[assoc_cnt].cli_Retransmissions = 0;
		dev[assoc_cnt].cli_Active = TRUE;
		strncpy(dev[assoc_cnt].cli_OperatingStandard, "", 64);
		strncpy(dev[assoc_cnt].cli_OperatingChannelBandwidth, "20MHz", 64);
		dev[assoc_cnt].cli_SNR = 20;
		strncpy(dev[assoc_cnt].cli_InterferenceSources, "", 64);
		dev[assoc_cnt].cli_DataFramesSentAck = 0;
		dev[assoc_cnt].cli_DataFramesSentNoAck = 0;
		dev[assoc_cnt].cli_BytesSent = 0;
		dev[assoc_cnt].cli_BytesReceived = 0;
		dev[assoc_cnt].cli_RSSI = 30;

		assoc_cnt++;

	}
	pclose(f);

	return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering object
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Capability bool r/o
//To get Band Steering Capability
INT wifi_getBandSteeringCapability(BOOL *support)
{
	*support = FALSE;
	return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable bool r/w
//To get Band Steering enable status
INT wifi_getBandSteeringEnable(BOOL *enable)
{
	*enable = FALSE;
	return RETURN_OK;
}

//To turn on/off Band steering
INT wifi_setBandSteeringEnable(BOOL enable)
{
	return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.APGroup string r/w
//To get Band Steering AP group
INT wifi_getBandSteeringApGroup(char *output_ApGroup)
{

	if (NULL == output_ApGroup)
		return RETURN_ERR;

	strcpy(output_ApGroup, "1,2");
	return RETURN_OK;
}

//To set Band Steering AP group
INT wifi_setBandSteeringApGroup(char *ApGroup)
{

	return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.UtilizationThreshold int r/w
//to set and read the band steering BandUtilizationThreshold parameters
INT wifi_getBandSteeringBandUtilizationThreshold(INT radioIndex, INT *pBuThreshold)
{

	return RETURN_ERR;
}

INT wifi_setBandSteeringBandUtilizationThreshold(INT radioIndex, INT buThreshold)
{

	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.RSSIThreshold int r/w
//to set and read the band steering RSSIThreshold parameters
INT wifi_getBandSteeringRSSIThreshold(INT radioIndex, INT *pRssiThreshold)
{

	return RETURN_ERR;
}

INT wifi_setBandSteeringRSSIThreshold(INT radioIndex, INT rssiThreshold)
{

	return RETURN_ERR;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.PhyRateThreshold int r/w
//to set and read the band steering physical modulation rate threshold parameters
INT wifi_getBandSteeringPhyRateThreshold(INT radioIndex, INT *pPrThreshold) //If chip is not support, return -1
{

	return RETURN_ERR;
}

INT wifi_setBandSteeringPhyRateThreshold(INT radioIndex, INT prThreshold) //If chip is not support, return -1
{

	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.OverloadInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under overload condition
INT wifi_getBandSteeringOverloadInactiveTime(INT radioIndex, INT *pPrThreshold)
{

	return RETURN_ERR;
}

INT wifi_setBandSteeringOverloadInactiveTime(INT radioIndex, INT prThreshold)
{

	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.IdleInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under Idle condition
INT wifi_getBandSteeringIdleInactiveTime(INT radioIndex, INT *pPrThreshold)
{

	return RETURN_ERR;
}

INT wifi_setBandSteeringIdleInactiveTime(INT radioIndex, INT prThreshold)
{

	return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.History string r/o
//pClientMAC[64]
//pSourceSSIDIndex[64]
//pDestSSIDIndex[64]
//pSteeringReason[256]
INT wifi_getBandSteeringLog(INT record_index, ULONG *pSteeringTime, CHAR *pClientMAC, INT *pSourceSSIDIndex, INT *pDestSSIDIndex, INT *pSteeringReason) //if no steering or redord_index is out of boundary, return -1. pSteeringTime returns the UTC time in seconds. pClientMAC is pre allocated as 64bytes. pSteeringReason returns the predefined steering trigger reason
{
	*pSteeringTime = 1454685924;
	strcpy(pClientMAC, "14:CF:E2:13:CD:AE");
	strcpy(pSourceSSIDIndex, "ath0");
	strcpy(pSourceSSIDIndex, "ath1");
	snprintf(pSteeringReason, 256, "RSSIThreshold=%d; RSSI=%d", 30, 35);
	return RETURN_OK;
}

INT wifi_ifConfigUp(INT apIndex)
{
	char cmd[128];
	char buf[1024];

	snprintf(cmd, sizeof(cmd), "ifconfig %s%d up 2>/dev/null", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));
	return 0;
}

//>> Deprecated. Replace with wifi_applyRadioSettings
INT wifi_pushBridgeInfo(INT apIndex)
{
	char ip[32];
	char subnet[32];
	char bridge[32];
	int vlanId;
	char cmd[128];
	char buf[1024];

	wifi_getApBridgeInfo(apIndex, bridge, ip, subnet);
	wifi_getApVlanID(apIndex, &vlanId);

	snprintf(cmd, sizeof(cmd), "cfgVlan %s%d %s %d %s ", AP_PREFIX, apIndex, bridge, vlanId, ip);
	_syscmd(cmd, buf, sizeof(buf));

	return 0;
}

INT wifi_pushChannel(INT radioIndex, UINT channel)
{
	char cmd[128];
	char buf[1024];
	int apIndex;

	apIndex = (radioIndex == 0) ? 0 : 1;
	snprintf(cmd, sizeof(cmd), "iwconfig %s%d freq %d", AP_PREFIX, apIndex, channel);
	_syscmd(cmd, buf, sizeof(buf));

	return 0;
}

INT wifi_pushChannelMode(INT radioIndex)
{
	//Apply Channel mode, pure mode, etc that been set by wifi_setRadioChannelMode() instantly
	return RETURN_ERR;
}

INT wifi_pushDefaultValues(INT radioIndex)
{
	//Apply Comcast specified default radio settings instantly
	//AMPDU=1
	//AMPDUFrames=32
	//AMPDULim=50000
	//txqueuelen=1000

	return RETURN_ERR;
}

INT wifi_pushTxChainMask(INT radioIndex)
{
	//Apply default TxChainMask instantly
	return RETURN_ERR;
}

INT wifi_pushRxChainMask(INT radioIndex)
{
	//Apply default RxChainMask instantly
	return RETURN_ERR;
}

INT wifi_pushSSID(INT apIndex, CHAR *ssid)
{
	wifi_setSSIDName(apIndex, ssid);
	wifi_setApEnable(apIndex, FALSE);
	wifi_setApEnable(apIndex, TRUE);

	return RETURN_OK;
}

INT wifi_pushSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
	//Apply default Ssid Advertisement instantly

	return RETURN_ERR;
}

INT wifi_getRadioUpTime(INT radioIndex, ULONG *output)
{
	INT status = RETURN_ERR;
	*output = 0;
	return RETURN_ERR;
}

#ifdef _WIFI_HAL_TEST_
int main(int argc, char **argv)
{
	int index;
	INT ret = 0;

	if (argc <= 1) {
		printf("help\n");
		//fprintf(stderr,"%s", commands_help);

		exit(-1);
	}

	if (strstr(argv[1], "init") != NULL) {
		return wifi_init();
	else if (strstr(argv[1], "reset") != NULL)
		return wifi_reset();

	index = atoi(argv[2]);
	if (strstr(argv[1], "getApEnable") != NULL) {
		BOOL enable;

		ret = wifi_getApEnable(index, &enable);
		printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
	} else if (strstr(argv[1], "setApEnable") != NULL) {
		BOOL enable = atoi(argv[3]);

		ret = wifi_setApEnable(index, enable);
		printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
	} else if (strstr(argv[1], "getApStatus") != NULL) {
		char status[64];

		ret = wifi_getApStatus(index, status);
		printf("%s %d: %s, returns %d\n", argv[1], index, status, ret);
	} else if (strstr(argv[1], "getSSIDTrafficStats2") != NULL) {
		wifi_ssidTrafficStats2_t stats = {0};

		ret = wifi_getSSIDTrafficStats2(index, &stats); //Tr181
		printf("%s %d: returns %d\n", argv[1], index, ret);
		printf("     ssid_BytesSent             =%lu\n", stats.ssid_BytesSent);
		printf("     ssid_BytesReceived         =%lu\n", stats.ssid_BytesReceived);
		printf("     ssid_PacketsSent           =%lu\n", stats.ssid_PacketsSent);
		printf("     ssid_PacketsReceived       =%lu\n", stats.ssid_PacketsReceived);
		printf("     ssid_RetransCount          =%lu\n", stats.ssid_RetransCount);
		printf("     ssid_FailedRetransCount    =%lu\n", stats.ssid_FailedRetransCount);
		printf("     ssid_RetryCount            =%lu\n", stats.ssid_RetryCount);
		printf("     ssid_MultipleRetryCount    =%lu\n", stats.ssid_MultipleRetryCount);
		printf("     ssid_ACKFailureCount       =%lu\n", stats.ssid_ACKFailureCount);
		printf("     ssid_AggregatedPacketCount =%lu\n", stats.ssid_AggregatedPacketCount);
		printf("     ssid_ErrorsSent            =%lu\n", stats.ssid_ErrorsSent);
		printf("     ssid_ErrorsReceived        =%lu\n", stats.ssid_ErrorsReceived);
		printf("     ssid_UnicastPacketsSent    =%lu\n", stats.ssid_UnicastPacketsSent);
		printf("     ssid_UnicastPacketsReceived    =%lu\n", stats.ssid_UnicastPacketsReceived);
		printf("     ssid_DiscardedPacketsSent      =%lu\n", stats.ssid_DiscardedPacketsSent);
		printf("     ssid_DiscardedPacketsReceived  =%lu\n", stats.ssid_DiscardedPacketsReceived);
		printf("     ssid_MulticastPacketsSent      =%lu\n", stats.ssid_MulticastPacketsSent);
		printf("     ssid_MulticastPacketsReceived  =%lu\n", stats.ssid_MulticastPacketsReceived);
		printf("     ssid_BroadcastPacketsSent      =%lu\n", stats.ssid_BroadcastPacketsSent);
		printf("     ssid_BroadcastPacketsRecevied  =%lu\n", stats.ssid_BroadcastPacketsRecevied);
		printf("     ssid_UnknownPacketsReceived    =%lu\n", stats.ssid_UnknownPacketsReceived);
	} else if (strstr(argv[1], "getNeighboringWiFiDiagnosticResult2") != NULL) {
		wifi_neighbor_ap2_t *neighbor_ap_array = NULL, *pt = NULL;
		UINT array_size = 0;
		UINT i = 0;

		ret = wifi_getNeighboringWiFiDiagnosticResult2(index, &neighbor_ap_array, &array_size);
		printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
		for (i = 0, pt = neighbor_ap_array; i < array_size; i++, pt++) {
			printf("  neighbor %d:\n", i);
			printf("     ap_SSID                =%s\n", pt->ap_SSID);
			printf("     ap_BSSID               =%s\n", pt->ap_BSSID);
			printf("     ap_Mode                =%s\n", pt->ap_Mode);
			printf("     ap_Channel             =%d\n", pt->ap_Channel);
			printf("     ap_SignalStrength      =%d\n", pt->ap_SignalStrength);
			printf("     ap_SecurityModeEnabled =%s\n", pt->ap_SecurityModeEnabled);
			printf("     ap_EncryptionMode      =%s\n", pt->ap_EncryptionMode);
			printf("     ap_SupportedStandards  =%s\n", pt->ap_SupportedStandards);
			printf("     ap_OperatingStandards  =%s\n", pt->ap_OperatingStandards);
			printf("     ap_OperatingChannelBandwidth   =%s\n", pt->ap_OperatingChannelBandwidth);
			printf("     ap_SecurityModeEnabled         =%s\n", pt->ap_SecurityModeEnabled);
			printf("     ap_BeaconPeriod                =%d\n", pt->ap_BeaconPeriod);
			printf("     ap_Noise                       =%d\n", pt->ap_Noise);
			printf("     ap_BasicDataTransferRates      =%s\n", pt->ap_BasicDataTransferRates);
			printf("     ap_SupportedDataTransferRates  =%s\n", pt->ap_SupportedDataTransferRates);
			printf("     ap_DTIMPeriod                  =%d\n", pt->ap_DTIMPeriod);
			printf("     ap_ChannelUtilization          =%d\n", pt->ap_ChannelUtilization);
		}
		if (neighbor_ap_array)
			free(neighbor_ap_array); //make sure to free the list
	} else if (strstr(argv[1], "getApAssociatedDeviceDiagnosticResult") != NULL) {
		wifi_associated_dev_t *associated_dev_array = NULL, *pt = NULL;
		UINT array_size = 0;
		UINT i = 0;

		ret = wifi_getApAssociatedDeviceDiagnosticResult(index, &associated_dev_array, &array_size);
		printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
		for (i = 0, pt = associated_dev_array; i < array_size; i++, pt++) {
			printf("  associated_dev %d:\n", i);
			printf("     cli_OperatingStandard      =%s\n", pt->cli_OperatingStandard);
			printf("     cli_OperatingChannelBandwidth  =%s\n", pt->cli_OperatingChannelBandwidth);
			printf("     cli_SNR                    =%d\n", pt->cli_SNR);
			printf("     cli_InterferenceSources    =%s\n", pt->cli_InterferenceSources);
			printf("     cli_DataFramesSentAck      =%lu\n", pt->cli_DataFramesSentAck);
			printf("     cli_DataFramesSentNoAck    =%lu\n", pt->cli_DataFramesSentNoAck);
			printf("     cli_BytesSent              =%lu\n", pt->cli_BytesSent);
			printf("     cli_BytesReceived          =%lu\n", pt->cli_BytesReceived);
			printf("     cli_RSSI                   =%d\n", pt->cli_RSSI);
			printf("     cli_MinRSSI                =%d\n", pt->cli_MinRSSI);
			printf("     cli_MaxRSSI                =%d\n", pt->cli_MaxRSSI);
			printf("     cli_Disassociations        =%d\n", pt->cli_Disassociations);
			printf("     cli_AuthenticationFailures =%d\n", pt->cli_AuthenticationFailures);
		}
		if (associated_dev_array)
			free(associated_dev_array); //make sure to free the list
	}
	return 0;
}
#endif

INT wifi_setApCsaDeauth(INT apIndex, INT mode)
{
	// TODO Implement me!
	return RETURN_OK;
}

INT wifi_setApScanFilter(INT apIndex, INT mode, CHAR *essid)
{
	// TODO Implement me!
	return RETURN_OK;
}

INT wifi_pushRadioChannel(INT radioIndex, UINT channel)
{
	// TODO Implement me!
	return RETURN_ERR;
}

static INT chan_to_freq(int radioIndex, UINT channel, int *freq)
{
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int ret = 0;

	sprintf(cmd, "iwlist %s%d channel |grep %02d |awk '{print $4}'  | tr -d '.'", RADIO_PREFIX, radioIndex, channel);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if ((ret != 0) && (strlen(buf) == 0))
		return RETURN_ERR;
	sscanf(buf, "%d", freq);
	return RETURN_OK;

}

INT wifi_pushRadioChannel2(INT radioIndex, UINT channel, UINT channel_width_MHz, UINT csa_beacon_count)
{
	// hostapd_cli  -i wifi0 chan_switch 30 (wzorek chan do freq) sec_channel_offset=1 center_freq1=(freq+polowa bandwith zalezne od rozmiaru) bandwidth=40 (2.4 ht 5g vht)
	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int freq = 0;
	int ret = 0;
	//char vht[4] = (radioIndex == 0)? "vt":"vht";

	if (chan_to_freq(radioIndex, channel, &freq) == RETURN_ERR)
		return RETURN_ERR;
	//sprintf(cmd, "hostapd_cli  -i %s%d chan_switch %d %d sec_channel_offset=1 center_freq1=(freq+polowa bandwith zalezne od rozmiaru) bandwidth=%d %s", RADIO_PREFIX, radioIndex, csa_beacon_count, freq,channel_width_MHz, vht);
	sprintf(cmd, "hostapd_cli  -i %s%d chan_switch %d %d ", RADIO_PREFIX, radioIndex, csa_beacon_count, freq);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if ((ret != 0) && (strlen(buf) == 0))
		return RETURN_ERR;
	return RETURN_OK;
}

INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool)
{
	char config_file[MAX_BUF_SIZE] = {0};

	char cmd[MAX_CMD_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int ret = 0;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);

	WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

	sprintf(cmd, "cat %s | grep \"^channel=\" | cut -d \"=\"  -f 2 | head -n1", config_file);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if ((ret != 0) && (strlen(buf) == 0))
		return RETURN_ERR;
	*output_bool = (strncmp("0", buf, 1) == 0) ?  TRUE : FALSE;

	WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

	return RETURN_OK;
}

INT wifi_getSSIDNameStatus(INT apIndex, CHAR *output)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};

	if (NULL == output)
		return RETURN_ERR;

	snprintf(cmd, sizeof(cmd), "iw dev %s%d info |grep ssid | awk '{printf $2}'", AP_PREFIX, apIndex);
	_syscmd(cmd, buf, sizeof(buf));
	snprintf(output, 64, buf);

	return RETURN_OK;

}

INT wifi_getApMacAddressControlMode(INT apIndex, INT *output_filterMode)
{
	// TODO Implement me!
	char config_file[MAX_BUF_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};

	if (!output_filterMode)
		return RETURN_ERR;

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "macaddr_acl", buf, 64);

	*output_filterMode = atoi(buf);
	return RETURN_OK;
}

INT wifi_delApAclDevices(INT apIndex)
{
	char cmd[MAX_BUF_SIZE] = {0};
	char buf[MAX_BUF_SIZE] = {0};
	int ret = 0;

	sprintf(cmd, "hostapd_cli -i %s%d accept_acl CLEAR", AP_PREFIX, apIndex);
	ret = _syscmd(cmd, buf, sizeof(buf));
	if (ret != 0)
		return RETURN_ERR;

	return RETURN_OK;

}

INT wifi_getApAssociatedDeviceStats(INT apIndex, mac_address_t *clientMacAddress, wifi_associated_dev_stats_t *associated_dev_stats, ULLONG *handle)
{
	//TODO Implement me!
	return RETURN_OK;
}

INT wifi_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_rx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
	//TODO Implement me!
	return RETURN_OK;
}

INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
	//TODO Implement me!
	return RETURN_OK;
}

INT wifi_setRadioStatsEnable(INT radioIndex, BOOL enable)
{
	//TODO Implement me!
	return RETURN_OK;
}

INT wifi_getApAssociatedDeviceTidStatsResult(INT radioIndex,  mac_address_t *clientMacAddress, wifi_associated_dev_tid_stats_t *tid_stats,  ULLONG *handle)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_getApAssociatedDeviceDiagnosticResult2(INT apIndex, wifi_associated_dev2_t **associated_dev_array, UINT *output_array_size)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array, INT array_size)
{
	//TODO Implement me!
	return RETURN_OK;
}

INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
	//TODO Implement me!
	return RETURN_OK;
}

INT wifi_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientMeasure(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason)
{
	//TODO Implement me!
	return RETURN_ERR;
}

INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
	//TODO Implement me!
	return RETURN_ERR;
}
#define HOSTAPD_STA_PARAM_ENTRIES 29
INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
	//return wifi_getApAssociatedDeviceDiagnosticResult2(apIndex, (wifi_associated_dev2_t **)associated_dev_array, output_array_size);
	char cmd[256];
	char buf[2048];
	wifi_associated_dev_t *dev = NULL;
	unsigned int assoc_cnt = 0;
	char *pos;
	FILE *f;
	char *mac = NULL;
	char *aid = NULL;
	char *chan = NULL;
	char *txrate = NULL;
	char *rxrate = NULL;
	char *rssi = NULL;
	//struct hostapd_sta_param sta_parameters[29];
	//char *key, *value;
	*output_array_size = 0;
	*associated_dev_array = NULL;

	if (apIndex < 0)
		return RETURN_ERR;

	wifi_getApNumDevicesAssociated(apIndex, output_array_size);

	if (*output_array_size <= 0)
		return RETURN_OK;

	dev = (wifi_associated_dev3_t *) calloc(*output_array_size, sizeof(wifi_associated_dev3_t));
	*associated_dev_array = dev;

	sprintf(cmd, "hostapd_cli -i %s%d list_sta", AP_PREFIX, apIndex);
	if ((f = popen(cmd, "r")) == NULL) {
		printf("%s: popen %s error\n", __func__, cmd);
		return -1;
}

	for (int i = 0; i < *output_array_size; i++) {
		fscanf(f, "%x:%x:%x:%x:%x:%x",
			   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[0],
			   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[1],
			   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[2],
			   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[3],
			   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[4],
			   (unsigned int *)&dev[assoc_cnt].cli_MACAddress[5]);

/*		//fill all sta parameters from sta
		int k = 0;
		while(k < HOSTAPD_STA_PARAM_ENTRIES) {
			fgets(buf, 2048, f);
			key = strtok(line, "    \n");
			strncpy(sta_parameters[k].key,key,50);
			value = = strtok(NULL, "   \n");
			strncpy(sta_parameters[k].value,value,100);
			k++;
		}

//		char *aid = hostapd_sta_get_param(sta_parameters,"aid");
//		char *chan = hostapd_sta_get_param(sta_parameters,"aid");
//		char *txrate = hostapd_sta_get_param(sta_parameters,"tx_rate_info");
//		char *rxrate = hostapd_sta_get_param(sta_parameters,"rx_rate_info");
//		char *rssi = hostapd_sta_get_param(sta_parameters,"signal");



		memset(dev[assoc_cnt].cli_IPAddress, 0, 64);
		dev[assoc_cnt].cli_AuthenticationState = 1;

	/*	dev[assoc_cnt].cli_AuthenticationState =  (rssi != NULL) ? atoi(rssi) - 100 : 0;
		dev[assoc_cnt].cli_LastDataDownlinkRate =  (txrate != NULL) ? atoi(strtok(txrate,"M")) : 0;
		dev[assoc_cnt].cli_LastDataUplinkRate =  (rxrate != NULL) ? atoi(strtok(rxrate,"M")) : 0;

		//zqiu: TODO: fill up the following items
		dev[assoc_cnt].cli_SignalStrength=-100;
		dev[assoc_cnt].cli_Retransmissions=0;
		dev[assoc_cnt].cli_Active=TRUE;
		strncpy(dev[assoc_cnt].cli_OperatingStandard, "", 64);
		strncpy(dev[assoc_cnt].cli_OperatingChannelBandwidth, "20MHz", 64);
		dev[assoc_cnt].cli_SNR=20;
		strncpy(dev[assoc_cnt].cli_InterferenceSources, "", 64);
		dev[assoc_cnt].cli_DataFramesSentAck=0;
		dev[assoc_cnt].cli_DataFramesSentNoAck=0;
		dev[assoc_cnt].cli_BytesSent=0;
		dev[assoc_cnt].cli_BytesReceived=0;
		dev[assoc_cnt].cli_RSSI=30;
	*/

	}
	pclose(f);

	return RETURN_OK;

}

INT wifi_steering_eventUnregister(void)
{
	//TODO Implement me!
	return RETURN_ERR;
}
INT wifi_setBTMRequest(UINT apIndex, CHAR *peerMac, wifi_BTMRequest_t *request)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_setRMBeaconRequest(UINT apIndex, CHAR *peer, wifi_BeaconRequest_t *in_request, UCHAR *out_DialogToken)
{
	// TODO Implement me!
	return RETURN_ERR;
}

INT wifi_getRadioChannels(INT radioIndex, wifi_channelMap_t *outputMap, INT outputMapSize)
{
	// TODO Implement me!
	return RETURN_ERR;
}
INT wifi_setBSSTransitionActivation(UINT apIndex, BOOL activate)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;

	list.name = "bss_transition";
	list.value = activate?"1":"0";

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdWrite(config_file, &list, 1);
	return RETURN_OK;

}

INT wifi_chan_eventRegister(wifi_chan_eventCB_t eventCb)
{
	//TODO Implement me!
	return RETURN_OK;
}

INT wifi_getBSSTransitionActivation(UINT apIndex, BOOL *activate)
{
	//TODO Implement me!
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "bss_transition", buf, 64);
	*activate = (strncmp("1", buf, 1) == 0);

	return RETURN_OK;
}

INT wifi_setNeighborReportActivation(UINT apIndex, BOOL activate)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};
	struct params list;

	list.name = "rrm_neighbor_report";
	list.value = activate ? "1" : "0";

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdWrite(config_file, &list, 1);
	return RETURN_OK;

}

INT wifi_getNeighborReportActivation(UINT apIndex, BOOL *activate)
{
	char buf[MAX_BUF_SIZE] = {0};
	char cmd[MAX_CMD_SIZE] = {0};
	char config_file[MAX_BUF_SIZE] = {0};

	sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
	wifi_hostapdRead(config_file, "rrm_neighbor_report", buf, 64);
	*activate = (strncmp("1", buf, 1) == 0);

	return RETURN_OK;

}

/* Hostapd events */

#ifndef container_of
#define offsetof(st, m) ((size_t)&(((st *)0)->m))
#define container_of(ptr, type, member) \
		    ((type *)((char *)ptr - offsetof(type, member)))
#endif /* container_of */

struct ctrl {
	char sockpath[128];
	char sockdir[128];
	char bss[IFNAMSIZ];
	int ssid_index;
	void (*cb)(struct ctrl *ctrl, int level, const char *buf, size_t len);
	void (*overrun)(struct ctrl *ctrl);
	struct wpa_ctrl *wpa;
		unsigned int ovfl;
	int initialized;
	ev_timer retry;
	ev_stat stat;
	ev_io io;
};

static wifi_newApAssociatedDevice_callback clients_connect_cb;
static wifi_apDisassociatedDevice_callback clients_disconnect_cb;
static struct ctrl wpa_ctrl[MAX_SUPPORTED_IFACES];
static int initialized;
/* static void
ctrl_close(struct ctrl *ctrl)
{
	if (ctrl->io.cb)
		ev_io_stop(EV_DEFAULT_ &ctrl->io);
	if (ctrl->retry.cb)
		ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
	if (!ctrl->wpa)
		return;

	wpa_ctrl_detach(ctrl->wpa);
	wpa_ctrl_close(ctrl->wpa);
	ctrl->wpa = NULL;
	LOGI("%s: closed", ctrl->bss);

	if (ctrl->closed)
		ctrl->closed(ctrl);
} */

static unsigned int
ctrl_get_drops(struct ctrl *ctrl)
{
	char cbuf[256] = {};
	struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cmsg;
	unsigned int ovfl = ctrl->ovfl;
	unsigned int drop;

	recvmsg(ctrl->io.fd, &msg, MSG_DONTWAIT);
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL)
			ovfl = *(unsigned int *)CMSG_DATA(cmsg);

	drop = ovfl - ctrl->ovfl;
	ctrl->ovfl = ovfl;

	return drop;
}

static void
ctrl_ev_cb(EV_P_ struct ev_io *io, int events)
{
	struct ctrl *ctrl = container_of(io, struct ctrl, io);
	const char *str;
	size_t len;
	char buf[1024];
	int drops;
	int level;
	int err;

	memset(buf, 0, sizeof(buf));
	len = sizeof(buf) - 1;
	err = wpa_ctrl_recv(ctrl->wpa, buf, &len);
	if (err < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		goto err_close;
	}

    /* Example events:
     *
     * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19
     * <3>AP-STA-CONNECTED-PWD 60:b4:f7:f0:0a:19 passphrase
     * <3>AP-STA-DISCONNECTED 60:b4:f7:f0:0a:19
     * <3>CTRL-EVENT-CONNECTED - Connection to 00:1d:73:73:88:ea completed [id=0 id_str=]
     * <3>CTRL-EVENT-DISCONNECTED bssid=00:1d:73:73:88:ea reason=3 locally_generated=1
     */
	printf("Received (%d): %s\n", ctrl->ssid_index, buf);
	if (!(str = index(buf, '>')))
		return;
	if (sscanf(buf, "<%d>", &level) != 1)
		return;

	str++;

	printf("Calling callback\n");

	if (strncmp("AP-STA-CONNECTED ", str, 17) == 0) {
		if (!(str = index(buf, ' ')))
			return;

		wifi_associated_dev_t sta;

		memset(&sta, 0, sizeof(sta));

		sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &sta.cli_MACAddress[0], &sta.cli_MACAddress[1], &sta.cli_MACAddress[2],
		   &sta.cli_MACAddress[3], &sta.cli_MACAddress[4], &sta.cli_MACAddress[5]);

		(clients_connect_cb)(ctrl->ssid_index, &sta);
		goto handled;
	}
	if (strncmp("AP-STA-DISCONNECTED ", str, 20) == 0) {
		if (!(str = index(buf, ' ')))
			return;

		(clients_disconnect_cb)(ctrl->ssid_index, str, 0);
		goto handled;
	}

	printf("Event not supported!!\n");

handled:

	if ((drops = ctrl_get_drops(ctrl))) {
		printf("%s: dropped %d messages", ctrl->bss, drops);
		if (ctrl->overrun)
			ctrl->overrun(ctrl);
	}

	return;

err_close:
	ev_timer_again(EV_DEFAULT_ &ctrl->retry);
}

static int
ctrl_open(struct ctrl *ctrl)
{
	int fd;

	if (ctrl->wpa)
		return 0;

	ctrl->wpa = wpa_ctrl_open(ctrl->sockpath);
	if (!ctrl->wpa)
		goto err;

	if (wpa_ctrl_attach(ctrl->wpa) < 0)
		goto err_close;

	fd = wpa_ctrl_get_fd(ctrl->wpa);
	if (fd < 0)
		goto err_detach;

	if (setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, (int[]){1}, sizeof(int)) < 0)
		goto err_detach;

	ev_io_init(&ctrl->io, ctrl_ev_cb, fd, EV_READ);
	ev_io_start(EV_DEFAULT_ &ctrl->io);
	printf("%s: opened", ctrl->bss);

	return 0;

err_detach:
	wpa_ctrl_detach(ctrl->wpa);
err_close:
	wpa_ctrl_close(ctrl->wpa);
err:
	ctrl->wpa = NULL;
	return -1;
}

static void
ctrl_stat_cb(EV_P_ ev_stat *stat, int events)
{
	struct ctrl *ctrl = container_of(stat, struct ctrl, stat);

	printf("%s: file state changed", ctrl->bss);
	ctrl_open(ctrl);
}

static void
ctrl_retry_cb(EV_P_ ev_timer *timer, int events)
{
	struct ctrl *ctrl = container_of(timer, struct ctrl, retry);

	printf("%s: retrying", ctrl->bss);
	if (ctrl_open(ctrl) < 0)
		ev_timer_again(EV_DEFAULT_ &ctrl->retry);
}

int
ctrl_enable(struct ctrl *ctrl)
{
	if (ctrl->wpa)
		return 0;

	if (!ctrl->stat.cb) {
		ev_stat_init(&ctrl->stat, ctrl_stat_cb, ctrl->sockpath, 0.);
		ev_stat_start(EV_DEFAULT_ &ctrl->stat);
	}
	printf("enabling for %s\n", ctrl->sockpath);
	if (!ctrl->retry.cb)
		ev_timer_init(&ctrl->retry, ctrl_retry_cb, 0., 5.);

	return ctrl_open(ctrl);
}

static int init_wpa()
{
	int ret = 0;
	ULONG s, snum;
	char *sock_path;
	int i = 0;

	ret = wifi_getSSIDNumberOfEntries(&snum);
	if (ret != RETURN_OK) {
		printf("%s: failed to get SSID count", __func__);
		return RETURN_ERR;
	}
	printf("initializing sockets to hostapd\n");
	if (snum > MAX_SUPPORTED_IFACES) {
		printf("more ssid than supported! %d\n", snum);
		return RETURN_ERR;
	}

	for (s = 0; s < snum; s++) {
		sprintf(wpa_ctrl[s].sockpath, "%s%d", SOCK_PREFIX, s);
		wpa_ctrl[s].ssid_index = s;
		ctrl_open(&wpa_ctrl[s]);
		ctrl_enable(&wpa_ctrl[s]);
	}
	initialized = 1;
	return RETURN_OK;
}

void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc)
{
	clients_connect_cb = callback_proc;
	if (!initialized)
		init_wpa();
}

void wifi_apDisassociatedDevice_callback_register(wifi_apDisassociatedDevice_callback callback_proc)
{
	clients_disconnect_cb = callback_proc;
	if (!initialized)
		init_wpa();
}

//<<
