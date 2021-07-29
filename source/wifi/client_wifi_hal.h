#ifndef __CLIENT_WIFI_HAL_H__
#define __CLIENT_WIFI_HAL_H__
INT wifi_getSTANumberOfEntries(ULONG *output);
INT wifi_getSTAName(INT apIndex, CHAR *output_string);
INT wifi_getSTARadioIndex(INT ssidIndex, INT *radioIndex);
INT wifi_getSTAMAC(INT ssidIndex, CHAR *output_string);
INT wifi_getSTABSSID(INT ssidIndex, CHAR *output_string);
INT wifi_getSTASSID(INT ssidIndex, CHAR *output_string);
INT wifi_getSTACredentials(INT ssidIndex, CHAR *output_string);
INT wifi_getSTANetworks(INT apIndex, wifi_sta_network_t **out_staNetworks_array, INT out_array_size, BOOL *out_scan_cur_freq);
INT wifi_setSTANetworks(INT apIndex, wifi_sta_network_t **staNetworks_array, INT array_size, BOOL scan_cur_freq);
INT wifi_getSTAEnabled(INT ssidIndex, BOOL *enabled);
INT wifi_setSTAEnabled(INT ssidIndex, BOOL enable);
#endif
