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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "ccsp_hal_dhcpv4_emu_api.h"
#include "lm_api.h"

#if 0

********************************************************************************************************************
********************************************************************************************************************

					UDHCPD CONFIGURATION IMPLEMENTATION

*********************************************************************************************************************
*********************************************************************************************************************

/*Getting the dhcpv4 configuration (starting and ending)values */
INT CcspHalGetConfigValue(CHAR *key, CHAR *value, INT size)
{

        FILE *fp;
        CHAR line[FILE_SIZE], *ptr;
        INT result_found=0;

        fp =fopen(UDHCPD_CONF_FILE_PATH ,"r+");
	if(fp)
	{
        while(fgets(line,FILE_SIZE, fp) != NULL) {
                if((strstr(line, key)) != NULL) {
                       for(ptr = line; *ptr&&*ptr!=SPACE ;ptr++);
                        if(*ptr==SPACE)ptr++;
                       if(*ptr) result_found=1;
                       break;
                }
         }
	}
	else
		result_found=0;
	
        if(result_found == 0)
	{
                printf("\nSorry, couldn't find a match.\n");
		ptr = "0.0.0.0";
                snprintf(value, size, "%s", ptr);
	}
        else
                snprintf(value, size, "%s", ptr);
        close(fp);
        return 0;

}

/*Getting the dhcpv4 configuration(lease time)value */
INT CcspHalGetConfigLeaseValue(CHAR *key, CHAR *value, INT size)
{

        FILE *fp;
        CHAR line[FILE_SIZE], *ptr;
        INT result_found=0;

        fp =fopen(UDHCPD_CONF_FILE_PATH ,"r+");
	if(fp)
	{
        while(fgets(line,FILE_SIZE, fp) != NULL) {
                if((strstr(line, key)) != NULL) {
                       for(ptr = line; *ptr&&*ptr!=SPACE;ptr++);
                        if(*ptr==SPACE)ptr++;
                        for(*ptr;*ptr!=SPACE;ptr++);
                        if(*ptr==SPACE)ptr++;
		if(*ptr) result_found=1;
                       break;
                }
         }
	}
	else
		result_found=0;

        if(result_found == 0)
	{
                printf("\nSorry, couldn't find a match.\n");
		ptr = "0";
                snprintf(value, size, "%s", ptr);
	}
        else
                snprintf(value, size, "%s", ptr);
        close(fp);
        return 0;

}

/*passing the inputs to  dhcpv4 configuration file */
INT CcspHal_change_config_value(CHAR *field_name, CHAR *field_value, CHAR *buf, UINT *nbytes)
{
        INT found=0, old_value_length, adjustment_bytes, count=0;
        CHAR *p, *buf_base = buf, *value_start_pos;
        while(*buf)
        {
                for(;*buf&&(*buf=='\t'||*buf=='\n'||*buf==SPACE);buf++);
                p = field_name;
                for(;*buf&&*p&&!(*buf^*p); p++, buf++);
                if(!*p)
                {
                        printf("FOUND\n");
                        found = 1;
                        for(;*buf&&(*buf=='\t'||*buf=='\n'||*buf==SPACE);buf++);
                        printf("buf:%s\n", buf);
                        for(old_value_length=0;*buf&&*buf^NEW_LINE;buf++) old_value_length++;
                        break;
                }
                else
                {
                        printf("NOT FOUND\n");
                        for(;*buf&&*buf^NEW_LINE;buf++);
                        buf++;//going past \n
                }
        }

        if (!found)
        {
                printf("Invalid field name\n");
                return -1;
        }

        //KEEPING NOTE OF POSITION WHERE VALUE HAS TO BE CHANGED
        value_start_pos = buf-old_value_length;

        //FOR BUFFER ADJUSTMENTS
        adjustment_bytes = strlen(field_value)-old_value_length;// bytes to be adjusted either way
        *nbytes += adjustment_bytes;

        if(adjustment_bytes<0)
        {//shifting buffer content to left
                printf("NEGATIVE\n");
                for(;*buf;buf++)*(buf+adjustment_bytes) = *buf;
        }
        if(adjustment_bytes>0)
        {//shifting buffer content to right
                printf("POSITIVE\n");
                p = buf;
                for(;*buf;++buf);
		 buf--;//moving back to last character
         for(;buf>=p;buf--)*(buf+adjustment_bytes) = *buf;
        }
        while(*field_value) *value_start_pos++ = *field_value++; //replacing old value with new value.
        return 0;
}

/*Setting the inputs values to dhcpv4 configuration value  */
INT CcspHalSetDHCPConfigValues(UINT value_flag, ConfigValues *config_value)
{
        CHAR buf[FILE_SIZE] = "";//Must fill the buffer with zeroes
        INT fd, nbytes, ret;
        struct stat file_stat={};
        if((fd = open(UDHCPD_CONF_FILE_PATH, 0|O_RDWR))==-1)
        {
                //perror("open(/etc/udhcpd.conf) failed");
                printf("open(/etc/udhcpd.conf) failed: %m\n");
                return -1;
        }

        if(fstat(fd, &file_stat)==-1)
        {//called for getting file size
                printf("stat failed: %m\n");
                return -1;
        }
        if(file_stat.st_size+BUFFER_ADJUSTMENT> sizeof buf) //+128 bytes reserved for buffer adjustments
        {//checking whether buf size is sufficient or not
                printf("Insufficient buffer size\n");
                return -1;
        }

        if((nbytes = read(fd, buf, sizeof buf))==-1)
        {//reading contents of the file.
                printf("read(/etc/udhcpd.conf) failed: %m\n");
                return -1;
        }

        if(value_flag&GATEWAY)
                {
                ret = CcspHal_change_config_value("opt router ", config_value->gateway, buf, &nbytes);
                ret = CcspHal_change_config_value("option dns ", config_value->gateway, buf, &nbytes);
                }
        if(value_flag&SUBNET_MASK)
                ret = CcspHal_change_config_value("option subnet ",config_value->subnet, buf, &nbytes);
        if(value_flag&DHCP_STARTING_RANGE)
                ret = CcspHal_change_config_value("start ", config_value->start, buf, &nbytes);
        if(value_flag&DHCP_ENDING_RANGE)
                ret = CcspHal_change_config_value("end ", config_value->end, buf, &nbytes);
        if(value_flag&DHCP_LEASE_TIME)
                ret = CcspHal_change_config_value("option lease ", config_value->lease_time, buf, &nbytes);

        if(ret == -1)
	 {
             printf("change_config_value failed\n");
                return -1;
        }

        if(ftruncate(fd, 0)==-1)
        {
                printf("ftruncate failed: %m\n");
                return -1;
        }
        if(lseek(fd, 0, SEEK_SET)==-1)
        {
                printf("lseek failed: %m\n");
                return -1;
        }
        if(write(fd, buf, nbytes)==-1)
        {
                printf("write failed: %m\n");
                return -1;
        }
        close(fd);
        system("killall dnsmasq");
        system("/usr/bin/dnsmasq -N -a 127.0.0.1 -z");
        usleep(150);
        system("killall udhcpd");
        system("udhcpd /etc/udhcpd.conf");
        return 0;
}
#endif

/*********************************************************************************************************
**********************************************************************************************************

					DNSMASQ CONFIGURATION IMPLEMENTATION

***********************************************************************************************************
***********************************************************************************************************/
/*
 *  Procedure           : RestartDnsmasq
 *  Purpose             : Restart the dnsmasq with updated configuration
 *
 *  Parameters          : None
 *  Return_values       : None
 */

void RestartDnsmasq()
{
	system("killall dnsmasq");
	sleep(5);
	system("/usr/bin/dnsmasq &");
}
/*
 *  Procedure     : CcspHalGetConfigValues
 *  Purpose       : To Get current DHCPv4 parameter values from dnsmasq configuration file
 *
 *  Parameters    : 
 *     value_flag : To Get current value_flag status (subnet_mask,DHCP_starting & Ending Range,Lease Time)
 *     value      : Current DHCP parameter value should be stored 
 *     size       : size of value 
 *  Return_values : 
 *      value     : Current DHCP parameter value , to be returned
 *      size      : size of value, to be returned
 */

void CcspHalGetConfigValues(INT value_flag,CHAR *value, INT size)
{
	FILE *fp = NULL,*fd = NULL;
	CHAR path[512],lease_val[50],min_val[50],max_val[50];
	char *dhcp_range,output[50];
	int count = 0,min_result_found,max_result_found,lease_result_found,result_found;

	fd =fopen(DNSMASQ_CONF_FILE_PATH ,"r+");
	if(fd)
	{
		//Get Mininum Address
		fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f1 ", "r");
		if (fp == NULL)
		{
			printf("Failed to run command inside function %s\n",__FUNCTION__);
			min_result_found = 1;
		}
		else
		{
			fgets(path, sizeof(path)-1, fp);
			dhcp_range = strchr(path,'=');
			strcpy(output,dhcp_range+1);
			for(count=0;output[count]!='\n';count++)
				min_val[count]=output[count];
			min_val[count]='\0';
			min_result_found = 0;
			pclose(fp);
		}

		//Get Maximum Address

		fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f2 ", "r");
		if (fp == NULL)
		{
			printf("Failed to run command inside function %s\n",__FUNCTION__);
			max_result_found = 1;
		}
		else
		{
			fgets(path, sizeof(path)-1, fp);
			for(count=0;path[count]!='\n';count++)
				max_val[count]=path[count];
			max_val[count]='\0';
			max_result_found = 0;
			pclose(fp);
		}

		//Get Lease Time

		fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f4 ", "r");
		if (fp == NULL)
		{
			printf("Failed to run command inside function %s\n",__FUNCTION__);
			lease_result_found = 1;
		}
		else
		{
			fgets(path, sizeof(path)-1, fp);
			for(count=0;path[count]!='\n';count++)
				lease_val[count]=path[count];
			lease_val[count]='\0';
			lease_result_found = 0;
			pclose(fp);
		}

		fclose(fd); //end of dnsamsq file path
		result_found = 0;
	}
	else
		result_found = 1;
	if (result_found == 0)
	{
		if(value_flag&DHCP_STARTING_RANGE)
		{
			if (min_result_found == 0)
			{
				snprintf(value, size, "%s", min_val);
				if (strcmp(min_val,"") == 0)

				{
					printf("\n sorry,couldn't find a match \n");
					strcpy(max_val,"0.0.0.0");
					snprintf(value, size, "%s", max_val);
				}
			}

			else 
			{
				printf("\n sorry,couldn't find a match \n");
				strcpy(min_val,"0.0.0.0");
				snprintf(value, size, "%s", min_val);
			}
		}

		else if(value_flag&DHCP_ENDING_RANGE)
		{
			if (max_result_found == 0)
			{
				snprintf(value, size, "%s", max_val);
				if (strcmp(max_val,"") == 0)
				{		
					printf("\n sorry,couldn't find a match \n");
					strcpy(max_val,"0.0.0.0");
					snprintf(value, size, "%s", max_val);
				}
			}
			else
			{
				strcpy(max_val,"0.0.0.0");
				snprintf(value, size, "%s", max_val);
			}	
		}

		else if(value_flag&DHCP_LEASE_TIME)
		{
			if (lease_result_found == 0)
				snprintf(value, size, "%s", lease_val);
			else
			{
				printf("\n sorry,couldn't find a match \n");
				strcpy(lease_val,"0");
				snprintf(value, size, "%s", lease_val);
			}
		}
	}
	else
	{
		printf("\n sorry, couldn't find the dnsmasq.conf file \n");
		strcpy(min_val,"0.0.0.0");
		snprintf(value, size, "%s", min_val);
		strcpy(max_val,"0.0.0.0");
		snprintf(value, size, "%s", max_val);
		strcpy(lease_val,"0");
		snprintf(value, size, "%s", lease_val);

	}
}

/*
 *  Procedure     : CcspHalSetDHCPConfigValues
 *  Purpose       : To set current DHCPv4 parameter values to dnsmasq configuration file
 *
 *  Parameters    : 
 *     value_flag : To Get current value_flag status (subnet_mask,DHCP_starting & Ending Range,Lease Time)
 *     value      : Current DHCP parameter value should be stored 
 *  Return_values : The status of the operation
 *     @retval 0 , if successful
 *     @retval<0 , if any error is detected
 */

INT CcspHalSetDHCPConfigValues(INT value_flag,CHAR *value)
{
	FILE *fp;
	CHAR path[256],orig_val[100],min_val[50],max_val[50],subnet_val[50],lease_val[50];
	INT count;
	CHAR command[100],orig_dhcp_range[100],updated_dhcp_range[100];

	//Getting Orig DHCP Range
	fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range ", "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path)-1, fp);
	for(count=0;path[count]!='\n';count++)
		orig_val[count]=path[count];
	orig_val[count]='\0';
	sprintf(orig_dhcp_range,"%s",orig_val);

	//Getting Min Address
	fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f1 ", "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path)-1, fp);
	for(count=0;path[count]!='\n';count++)
		min_val[count]=path[count];
	min_val[count]='\0';

	//Getting Max Address
	fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f2 ", "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path)-1, fp);
	for(count=0;path[count]!='\n';count++)
		max_val[count]=path[count];
	max_val[count]='\0';

	//Getting SubnetMask
	fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f3 ", "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path)-1, fp);
	for(count=0;path[count]!='\n';count++)
		subnet_val[count]=path[count];
	subnet_val[count]='\0';

	//Getting LeaseTime
	fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f4 ", "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path)-1, fp);
	for(count=0;path[count]!='\n';count++)
		lease_val[count]=path[count];
	lease_val[count]='\0';

	if(value_flag&SUBNET_MASK)
		sprintf(updated_dhcp_range,"%s,%s,%s,%s",min_val,max_val,value,lease_val);
	if(value_flag&DHCP_STARTING_RANGE)
		sprintf(updated_dhcp_range,"%s%s,%s,%s,%s","dhcp-range=",value,max_val,subnet_val,lease_val);
	if(value_flag&DHCP_ENDING_RANGE)
		sprintf(updated_dhcp_range,"%s,%s,%s,%s",min_val,value,subnet_val,lease_val);
	if(value_flag&DHCP_LEASE_TIME)
		sprintf(updated_dhcp_range,"%s,%s,%s,%s",min_val,max_val,subnet_val,value);

	sprintf(command,"%s%s/%s%s%s","sed -i -e 's/",orig_dhcp_range,updated_dhcp_range,"/g' ","/etc/dnsmasq.conf");
	//Execute the command
	system(command);
	pclose(fp);
	system("rm /etc/dhcp_static_hosts");
	system("touch /etc/dhcp_static_hosts");
	//Restart the dnsmaq
	RestartDnsmasq();
}

/*
 *  Procedure     : CcspHalInterfacesetval
 *  Purpose       : To set current DHCPv4 Router value to Emulator(Gateway)
 *
 *  Parameters    : 
 *     name       : To Get Interface Name 
 *     str        : To Get New Gateway IP Address
 *  Return_values : The status of the operation
 *     @retval 0 , if successful
 *     @retval<0 , if any error is detected
 */

INT CcspHalInterfacesetval(CHAR *name,CHAR *str)
	{

	struct ifreq ifr;
	INT fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
    	inet_pton(AF_INET, str, ifr.ifr_addr.sa_data + 2);
    	ioctl(fd, SIOCSIFADDR, &ifr);
        return 0;

	}
/*
 *  Procedure     : CcspHalNetmasksetvalue
 *  Purpose       : To set current DHCPv4 Subnet value to Emulator
 *
 *  Parameters    : 
 *     name       : To Get Interface Name 
 *     str        : To Get New Subnet Mask Address
 *  Return_values : The status of the operation
 *     @retval 0 , if successful
 *     @retval<0 , if any error is detected
 */


INT CcspHalNetmasksetvalue(CHAR *name,CHAR *str)
	{
	
	struct ifreq ifr;
	INT fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
    	inet_pton(AF_INET, str, ifr.ifr_addr.sa_data + 2);
    	ioctl(fd, SIOCSIFNETMASK, &ifr);
        return 0;

	}
/*
 *  Procedure     : CcspHalGetPIDbyName
 *  Purpose       : To Get DHCPv4 server PID (to known ,it should be in Enable or Disable state)
 *
 *  Parameters    : 
 *     pidName    : To get DHPCv4 server Name
 *  Return_values : The status of the operation
 *     @retval 0 , if successful
 *     @retval<0 , if any error is detected
 */

INT CcspHalGetPIDbyName(CHAR* pidName)
	{

        FILE *fp;
        CHAR pidofCmd[FILE_SIZE]={0};
        INT pidValue=-1;
        if(pidName != 0) {
        strcpy(pidofCmd, DHCPv4_PID);
        strcat(pidofCmd, pidName);
        strcat(pidofCmd,  DHCP_PID);
        system(pidofCmd);
        fp = fopen(DHCP_PATH, "r");
        fscanf(fp, "%d", &pidValue);
        fclose(fp);
         }
       return pidValue;
	}


/*
 *  Procedure     : CcspHalNoofClientConnected
 *  Purpose       : To Get Total number of connected clients through Emulator(Gateway)
 *
 *  Parameters    : None
 *  Return_values : The status of the operation
 *     @retval 0 , if successful
 *     @retval<0 , if any error is detected
 */
ULONG CcspHalNoofClientConnected()
{
	FILE *fp = NULL;
	ULONG total_reachable_clients = 0;
	CHAR str[512];
	fp = popen("ip nei show | grep brlan0 | grep -e REACHABLE -e STALE -e DELAY | wc -l","r");
	if(fp == NULL)
	{
		printf("Failed to run command\n" );
		return;
	}
	fgets(str, sizeof(str)-1, fp); 
	total_reachable_clients = atoi(str);
	return total_reachable_clients;
}

/*
 *  Procedure     : checkLan
 *  Purpose       : To check the Lan status
 *
 *  Parameters    : None
 *  Return_values : The status of the operation
 *     @retval true , if successful
 *     @retval false , if any error is detected
 */
bool checkLan()
{
        FILE *fp = NULL;
        CHAR path[FILE_SIZE];
        INT count = 0;
        fp = popen ("ifconfig | grep eth1 | grep -v grep | wc -l","r");
        if(fp == NULL)
                return 0;
        fgets(path,FILE_SIZE,fp);
        count = atoi ( path );
        pclose(fp);
        if(count)
                return true;
        else
                return false;
}

/*
 *  Procedure     : CcspHalUpdateInterfaceval
 *  Purpose       : To set new Gateway IP address to Lighttpd WebServer
 *
 *  Parameters    : 
 *   newgatewayip : Having New Gateway IP Address
 *  Return_values : The status of the operation
 *     @retval 0 , if successful
 *     @retval<0 , if any error is detected
 */

INT CcspHalUpdateInterfaceval(CHAR *newgatewayip)
{
        CHAR path[1024],buf[500];
        FILE *fp = NULL;
        CHAR str[40],buf1[100],buf2[100];
        INT count;
        fp = popen("cat etc/lighttpd.conf | grep  server.bind |  cut -d '=' -f2","r");
        if(fp == NULL)
        {
                printf("\n function failed");
                return;
        }
        while(fgets(path,sizeof(path),fp)!=NULL);
        for(count=0;path[count]!='\n';count++)
                str[count]=path[count];
        str[count]='\0';
        sprintf(buf1,"%s%s","server.bind =",str);
        sprintf(buf2,"%s%c%s%c","server.bind = ",'"',newgatewayip,'"');
        sprintf(buf,"%s%s%s%s%s%s","sed -i -e 's/",buf1,"/",buf2,"/g'", " /etc/lighttpd.conf");
        system(buf);
        pclose(fp);
        return 0;
}

/********************************************************************************************
*********************************************************************************************

				RESERVED IP IMPLEMENTATION

*********************************************************************************************
*********************************************************************************************/

/*
 *  Procedure           : updateReservedIp
 *  Purpose             : It will edit the Existing Reserved IP in static Table Entry
 *
 *  Parameters          : 
 *   hostPtr            : Having connected clients details. 
 *   pDhcpStaticAddress : Having static table entry details.
 *  Return_values       : None
 */


void updateReservedIp(struct hostDetails *hostPtr,HALPCOSA_DML_DHCPS_SADDR pDhcpStaticAddress)
{
	char command[256],path[512],updated_reserved_Mac[512],staticMac[512],Updated_Reserved[512],str[512];
	int count = 0,dhcp = 0,tot_count = 0;
	FILE *fp;
	char staticIP_buf[100];
	struct in_addr ip_addr;
	ip_addr.s_addr = pDhcpStaticAddress->Yiaddr.Value;
	inet_ntop(AF_INET, &ip_addr, staticIP_buf, sizeof staticIP_buf);

	sprintf(staticMac,"%02x:%02x:%02x:%02x:%02x:%02x",pDhcpStaticAddress->Chaddr[0],pDhcpStaticAddress->Chaddr[1],pDhcpStaticAddress->Chaddr[2],pDhcpStaticAddress->Chaddr[3],pDhcpStaticAddress->Chaddr[4],pDhcpStaticAddress->Chaddr[5]);

	/* checking the file size whether it's empty or not */
	fp = popen("cat /etc/dhcp_static_hosts | cut -d ',' -f1","r");
	if(fp == NULL)
	{
		printf("Failure Function %s \n",__FUNCTION__);
		return;
	}
	while(fgets(path, sizeof(path)-1, fp) != NULL)
	{
		for(count = 0;path[count]!='\n';count++)
			updated_reserved_Mac[count] = path[count];
		updated_reserved_Mac[count] = '\0';
		if(strcmp(updated_reserved_Mac,staticMac) == 0)//Editing the Existing Reserved IP,RESERVED -> RESERVED
		{
			sprintf(command,"%s%s%s","cat /etc/dhcp_static_hosts | grep ",staticMac," > /tmp/Reserved_Mac.txt");
			system(command);
			fp = popen("cat /tmp/Reserved_Mac.txt | cut -d ',' -f2","r");
			if(fp == NULL)
			{
				printf("Failure Function %s \n",__FUNCTION__);
				return;
			}
			fgets(path, sizeof(path)-1, fp);
			for(count = 0;path[count]!='\n';count++)
				Updated_Reserved[count] = path[count];
			Updated_Reserved[count] = '\0';
			sprintf(command,"%s%s/%s%s","sed -i 's/",Updated_Reserved,staticIP_buf,"/' /etc/dhcp_static_hosts");
			system(command);//RESERVED IP -> RESERVED IP

		}

		else
		{
			dhcp = dhcp + 1;
		}
	}//end of while
	pclose(fp);
	sprintf(command,"%s","cat /etc/dhcp_static_hosts | wc -l > /tmp/tot.count.txt");
	system(command);
	fp = popen("cat /tmp/tot.count.txt","r");
	if(fp == NULL)
	{
		printf("Failure Function %s \n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path), fp);
	for(count = 0;path[count]!='\n';count++)
		str[count] = path[count];
	str[count] = '\0';
	tot_count = atoi(str);
	pclose(fp);
	if(tot_count == dhcp)//Adding the new Reserved IP in /etc/dhcp_static_hosts,DHCP -> RESERVED
	{
		sprintf(str,"%s%02x:%02x:%02x:%02x:%02x:%02x,%s,%s%s","echo ",pDhcpStaticAddress->Chaddr[0],pDhcpStaticAddress->Chaddr[1],pDhcpStaticAddress->Chaddr[2],pDhcpStaticAddress->Chaddr[3],pDhcpStaticAddress->Chaddr[4],pDhcpStaticAddress->Chaddr[5],staticIP_buf,pDhcpStaticAddress->DeviceName," >> /etc/dhcp_static_hosts");
		system(str);//DHCP-> RESERVED IP
	}
}

/*
 *  Procedure           : CcspHalDHCPv4ReservedClients
 *  Purpose             : To set Reserved IP in Static Entry Table 
 *
 *  Parameters          : 
 *   pDhcpStaticAddress : Having Static Table Entry.
 *  Return_values       : None
 */

void CcspHalDHCPv4ReservedClients(HALPCOSA_DML_DHCPS_SADDR pDhcpStaticAddress)
{
	int i,Total_Hosts_Count=0,Connected_Client_Counts = 0;
	struct hostDetails hostlist[MAX_NUM_HOST];
	LM_hosts_t host;
	int ret,count = 0,flag = 1;
	FILE *fp;
	char staticMac[100],str[256],path[512],updated_reserved_Mac[100];
	char staticIP_buf[100],command[512];
	struct in_addr ip_addr;
	ip_addr.s_addr = pDhcpStaticAddress->Yiaddr.Value;
	inet_ntop(AF_INET, &ip_addr, staticIP_buf, sizeof staticIP_buf);

	sprintf(staticMac,"%02x:%02x:%02x:%02x:%02x:%02x",pDhcpStaticAddress->Chaddr[0],pDhcpStaticAddress->Chaddr[1],pDhcpStaticAddress->Chaddr[2],pDhcpStaticAddress->Chaddr[3],pDhcpStaticAddress->Chaddr[4],pDhcpStaticAddress->Chaddr[5]);

	//checking the file size where it's empty or not
	sprintf(command,"%s","cat /etc/dhcp_static_hosts | wc -l > /tmp/count.txt");
	system(command);
	fp = popen("cat /tmp/count.txt","r");
	if(fp == NULL)
	{
		printf("Failure Function %s \n",__FUNCTION__);
		return;
	}
	fgets(path, sizeof(path), fp);
	for(count = 0;path[count]!='\n';count++)
		str[count] = path[count];
	str[count] = '\0';
	pclose(fp);
	if(strcmp(str,"0") == 0)
	{
		sprintf(str,"%s%02x:%02x:%02x:%02x:%02x:%02x,%s,%s%s","echo ",pDhcpStaticAddress->Chaddr[0],pDhcpStaticAddress->Chaddr[1],pDhcpStaticAddress->Chaddr[2],pDhcpStaticAddress->Chaddr[3],pDhcpStaticAddress->Chaddr[4],pDhcpStaticAddress->Chaddr[5],staticIP_buf,pDhcpStaticAddress->DeviceName," >> /etc/dhcp_static_hosts");
		system(str);
	}
	else
	{
		ret =  lm_get_all_hosts(&host);//Getting Connected Clients Lists
		if( ret == LM_RET_SUCCESS )
		{
			for(i = 0; i < host.count; i++)
			{
				sprintf(hostlist[i].hostName,"%02x:%02x:%02x:%02x:%02x:%02x", host.hosts[i].phyAddr[0], host.hosts[i].phyAddr[1], host.hosts[i].phyAddr[2], host.hosts[i].phyAddr[3], host.hosts[i].phyAddr[4], host.hosts[i].phyAddr[5]);
				if(strcmp(hostlist[i].hostName,staticMac) == 0)
					updateReservedIp(&hostlist[i],pDhcpStaticAddress);
				else
					Connected_Client_Counts = Connected_Client_Counts + 1;
			}
			Total_Hosts_Count = host.count;
		}

		if((Total_Hosts_Count == Connected_Client_Counts) || (Total_Hosts_Count == 0))//Not in Connected Client List,DHCP -> RESERVED
		{
			fp = popen("cat /etc/dhcp_static_hosts | cut -d ',' -f1","r");
			if(fp == NULL)
			{
				printf("Failure Function %s \n",__FUNCTION__);
				return;
			}
			while(fgets(path, sizeof(path)-1, fp) != NULL)
			{
				for(count = 0;path[count]!='\n';count++)
					updated_reserved_Mac[count] = path[count];
				updated_reserved_Mac[count] = '\0';

				//New Entry
				if((strcmp(updated_reserved_Mac,staticMac) != 0) && (flag == 1))
				{
					sprintf(str,"%s%02x:%02x:%02x:%02x:%02x:%02x,%s,%s%s","echo ",pDhcpStaticAddress->Chaddr[0],pDhcpStaticAddress->Chaddr[1],pDhcpStaticAddress->Chaddr[2],pDhcpStaticAddress->Chaddr[3],pDhcpStaticAddress->Chaddr[4],pDhcpStaticAddress->Chaddr[5],staticIP_buf,pDhcpStaticAddress->DeviceName," >> /etc/dhcp_static_hosts");
					system(str);
					flag = 2;//To avoid repeated iteration for same StaticMac
				}
			}//end of while
			flag = 1;
		}//end of not in connected client if
	}
	//Restart the dnsmasq
	RestartDnsmasq();
}

/*
 *  Procedure           : CcspHalDHCPv4DeleteReservedClients
 *  Purpose             : To delete Reserved IP in Static Entry Table 
 *
 *  Parameters          : 
 *   pDhcpStaticAddress : Having Static Table Entry.
 *  Return_values       : None
 */

void CcspHalDHCPv4DeleteReservedClients(HALPCOSA_DML_DHCPS_SADDR pDhcpStaticAddress)//RESERVED IP --> DHCP
{
	char command[256],staticMac[512];
	sprintf(staticMac,"%02x:%02x:%02x:%02x:%02x:%02x",pDhcpStaticAddress->Chaddr[0],pDhcpStaticAddress->Chaddr[1],pDhcpStaticAddress->Chaddr[2],pDhcpStaticAddress->Chaddr[3],pDhcpStaticAddress->Chaddr[4],pDhcpStaticAddress->Chaddr[5]);

	sprintf(command,"%s%s%s","sed -i.bak '/",staticMac,"/d' /etc/dhcp_static_hosts");
	system(command);
	//Restart the dnsmasq
	RestartDnsmasq();
}

/*
 *  Procedure           : GetInterfaceMacAddressValue
 *  Purpose             : To Get NULL MAC Address,If that interface is not there
 *
 *  Parameters          : 
 *   interface_details  : Having Mac Address Value is NULL
 *  Return_values       : None
 */

void GetInterfaceMacAddressValue(struct ethernet_port_details *interface_details)
{
	int bssidindex=0;
	int arr[6];
	char MacAddress[100] = {0};
	UCHAR Mac[250] = {0};
	// Store in One byte
	strcpy(MacAddress,"00:00:00:00:00:00");
	if( 6 == sscanf(MacAddress, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
	{
		for( bssidindex = 0; bssidindex < 6; ++bssidindex )
		{
			interface_details->Mac[bssidindex] = (unsigned char) arr[bssidindex];
		}
	}
}

/*
 *  Procedure           : CcspHalGetInterfaceDetails
 *  Purpose             : To Get all Interface Details(like Name,Mac Address).
 *
 *  Parameters          : 
 *   interface_details  : Having Interface Details of Static Information.
 *   ulIndex            : Instance Number of Interfaces
 *  Return_values       : None
 */
void CcspHalGetInterfaceDetails(ULONG ulIndex,struct ethernet_port_details *interface_details)
{
	UCHAR strMac[128] = {0};
	FILE *fp;
	char path[256] = {0},status[100] = {0};
	int count = 0;
	if(ulIndex == 1)
	{
		strcpy(interface_details->Name,"eth1");
		fp = popen("ifconfig | grep eth1 | grep -v grep | wc -l","r");
		if(fp == NULL)
		{
			printf("Failed to run command in Function %s\n",__FUNCTION__);
			return;
		}
		while(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
		if(strcmp(status,"1") == 0)
		{
			if ( -1 != _getMac(interface_details->Name, strMac) )
				AnscCopyMemory(interface_details->Mac,strMac,6);
		}
		else
			       GetInterfaceMacAddressValue(interface_details);
	pclose(fp);
	}
	else if(ulIndex == 2)
	{
		strcpy(interface_details->Name,"eth0");
		fp = popen("ifconfig | grep eth0 | grep -v grep | wc -l","r");
		if(fp == NULL)
		{
			printf("Failed to run command in Function %s\n",__FUNCTION__);
			return;
		}
		while(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
		if(strcmp(status,"1") == 0)
		{
			if ( -1 != _getMac(interface_details->Name,strMac) )
				AnscCopyMemory(interface_details->Mac,strMac,6);
		}
		else
			       GetInterfaceMacAddressValue(interface_details);
	pclose(fp);
	}
	else if(ulIndex == 3)
	{
		strcpy(interface_details->Name,"eth2");
		fp = popen("ifconfig | grep eth2 | grep -v grep | wc -l","r");
		if(fp == NULL)
		{
			printf("Failed to run command in Function %s\n",__FUNCTION__);
			return;
		}
		while(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
		if(strcmp(status,"1") == 0)
		{
			if ( -1 != _getMac(interface_details->Name,strMac) )
				AnscCopyMemory(interface_details->Mac,strMac,6);
		}
		else
			       GetInterfaceMacAddressValue(interface_details);
	pclose(fp);
	}
}
/*
 *  Procedure           : CcspHalGetInterfaceStatusDetails
 *  Purpose             : To Get all Interface Status Detail.
 *
 *  Parameters          : 
 *   pInfo              : Having Interface Status Detail.
 *   ulInstanceNumber   : Instance Number of Interfaces
 *  Return_values       : None
 */

void CcspHalGetInterfaceStatusDetails(ULONG ulInstanceNumber,HALPCOSA_DML_ETH_PORT_DINFO pInfo)
{
	FILE *fp;
	char path[256] = {0},status[100] = {0};
	int count = 0;
	if (ulInstanceNumber == 1)
	{
		fp = popen("ifconfig eth1 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		if(fp == NULL)
		{
			printf("Failed to run command in Function %s\n",__FUNCTION__);
			return;
		}
		while(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
		if(strcmp(status,"RUNNING") == 0)
			pInfo->Status = HALCOSA_DML_IF_STATUS_Up;
		else
			pInfo->Status = HALCOSA_DML_IF_STATUS_Down;
		pclose(fp);
	}
	else if (ulInstanceNumber == 2)
	{
		fp = popen("ifconfig eth0 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		if(fp == NULL)
		{
			printf("Failed to run command in Function %s\n",__FUNCTION__);
			return;
		}
		while(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
		if(strcmp(status,"RUNNING") == 0)
			pInfo->Status = HALCOSA_DML_IF_STATUS_Up;
		else
			pInfo->Status = HALCOSA_DML_IF_STATUS_Down;
		pclose(fp);
	}
	else if (ulInstanceNumber == 3)
	{
		fp = popen("ifconfig eth2 | grep RUNNING | tr -s ' ' | cut -d ' ' -f4","r");
		if(fp == NULL)
		{
			printf("Failed to run command in Function %s\n",__FUNCTION__);
			return;
		}
		while(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
		if(strcmp(status,"RUNNING") == 0)
			pInfo->Status = HALCOSA_DML_IF_STATUS_Up;
		else
			pInfo->Status = HALCOSA_DML_IF_STATUS_Down;
		pclose(fp);
	}
}
/*
 *  Procedure         : CcspHalSetInterfaceEnableDetails
 *  Purpose           : To check the LAN and WAN Enable Status in Emulator
 *
 *  Parameters        : 
 *     InstanceNumber : Having Instance Number of Interface
 *     enable         : Having current interface status
 *  Return_values     : The status of the operation
 *     @retval true , if successful
 *     @retval false , if any error is detected
 */

INT CcspHalSetInterfaceEnableDetails(INT index,bool enable)
{
	char interface_name[64] = {0};
	char buf[128] = {0};
	if(enable == false)
	{
	if(index == 1)
		strcpy(buf,"ifconfig eth1 down");
	else if(index == 2)
		strcpy(buf,"ifconfig eth0 down");
	else if(index == 3)
		strcpy(buf,"ifconfig eth2 down");
	}
	else
	{
	if(index == 1)
		strcpy(buf,"ifconfig eth1 up");
	else if(index == 2)
		strcpy(buf,"ifconfig eth0 up");
	else if(index == 3)
		strcpy(buf,"ifconfig eth2 up");
	}
	system(buf);
	return 0;
}
/*
 *  Procedure         : CcspHalGetInterfaceEnableDetails
 *  Purpose           : To check the LAN and WAN Enable Status in Emulator
 *
 *  Parameters        : 
 *     InstanceNumber : Having Instance Number of Interface
 *     enable         : Having current status of interface
 *  Return_values     : The status of the operation
 *     @retval true , if successful
 *     @retval false , if any error is detected
 */
INT CcspHalGetInterfaceEnableDetails(ULONG InstanceNumber,bool *enable)
{
        FILE *fp;
        char path[256] = {0},status[100] = {0};
        int count = 0;
        if (InstanceNumber == 1)
        {
                fp = popen("ifconfig | grep eth1 | grep -v grep | wc -l","r");
                if(fp == NULL)
                {
                        printf("Failed to run command in Function %s\n",__FUNCTION__);
                        return 0;
                }
                while(fgets(path, sizeof(path)-1, fp) != NULL)
                {
                        for(count=0;path[count]!='\n';count++)
                                status[count]=path[count];
                        status[count]='\0';
                }
                pclose(fp);
                if(strcmp(status,"1") == 0)
                        *enable = true;
                else
                        *enable =  false;
        }
        else if (InstanceNumber == 2)
        {
                fp = popen("ifconfig | grep eth0 | grep -v grep | wc -l","r");
                if(fp == NULL)
                {
                        printf("Failed to run command in Function %s\n",__FUNCTION__);
                        return 0;
                }
                while(fgets(path, sizeof(path)-1, fp) != NULL)
                {
                        for(count=0;path[count]!='\n';count++)
                                status[count]=path[count];
                        status[count]='\0';
                }
                pclose(fp);
                if(strcmp(status,"1") == 0)
                        *enable = true;
                else
                        *enable = false;
        }
	else if (InstanceNumber == 3)
        {
                fp = popen("ifconfig | grep eth2 | grep -v grep | wc -l","r");
                if(fp == NULL)
                {
                        printf("Failed to run command in Function %s\n",__FUNCTION__);
                        return 0;
                }
                while(fgets(path, sizeof(path)-1, fp) != NULL)
                {
                        for(count=0;path[count]!='\n';count++)
                                status[count]=path[count];
                        status[count]='\0';
                }
                pclose(fp);
                if(strcmp(status,"1") == 0)
                        *enable = true;
                else
                        *enable = false;
        }
}

/*
 *  Procedure            : CcspHalGetBridgePortNames
 *  Purpose              : To get Bridge Port Names
 *
 *  Parameters           : 
 *   ulBrgInstanceNumber : Having Instance number of Bridge
 *   ulIndex             : Having Instance number of port
 *   string              : Having Bridge_Port Names
 *  Return_values        : None
 */

void CcspHalGetBridgePortNames(ULONG ulBrgInstanceNumber,ULONG ulIndex,char *string)
{
        if( (ulIndex == 1) && ( ulBrgInstanceNumber == 1))
                strcpy(string,"brlan0");
        else if( (ulIndex == 2) && ( ulBrgInstanceNumber == 1))
                strcpy(string,"eth1");
        else if( (ulIndex == 3) && ( ulBrgInstanceNumber == 1))
                strcpy(string,"wlan0");
        else if( (ulIndex == 1) && ( ulBrgInstanceNumber == 2))
                strcpy(string,"brlan1");
        else if( (ulIndex == 2) && ( ulBrgInstanceNumber == 2))
                strcpy(string,"gretap0");
        else if( (ulIndex == 3) && ( ulBrgInstanceNumber == 2))
                strcpy(string,"wlan0_0");

}

/*
 *  Procedure         : GetBridgePortStatus
 *  Purpose           : To Get Bridge Port Current Status
 *
 *  Parameters        : 
 *     string         : Having Current Interface
 *  Return_values     : The status of the operation
 *     @retval up   , if successful
 *     @retval down , if any error is detected
 */

HALCOSA_DML_IF_STATUS GetBridgePortStatus(char *string)
{
        FILE *fp;
        char path[256] = {0},status[100] = {0} , command[100] = {0};
        int count = 0;
        sprintf(command,"%s%s%s","ifconfig ",string," | grep RUNNING | tr -s ' ' | cut -d ' ' -f4 > /tmp/BridgePort_Status");
        system(command);
        fp = popen("cat /tmp/BridgePort_Status","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return 0;
        }
        while(fgets(path, sizeof(path)-1, fp) != NULL)
        {
                for(count=0;path[count]!='\n';count++)
                        status[count]=path[count];
                status[count]='\0';
        }
        pclose(fp);
        if(strcmp(status,"RUNNING") == 0)
                return HALCOSA_DML_IF_STATUS_Up;
        else
                return HALCOSA_DML_IF_STATUS_Down;

}

/*
 *  Procedure              : CcspHalGetBridgePortStatus
 *  Purpose                : To Get Bridge Port Current Status
 *
 *  Parameters             : 
 *     ulBrgInstanceNumber : Having Instance Number of Bridge
 *     ulIndex             : Having Instance Number of Port
 *  Return_values          : The status of the operation
 *     @retval up    , if successful
 *     @retval down  , if any error is detected
 */

HALCOSA_DML_IF_STATUS CcspHalGetBridgePortStatus(ULONG ulBrgInstanceNumber,ULONG ulIndex)
{
        if( (ulIndex == 1) && ( ulBrgInstanceNumber == 1))
                return GetBridgePortStatus("brlan0");
        else if( (ulIndex == 2) && ( ulBrgInstanceNumber == 1))
                return GetBridgePortStatus("eth1");
        else if( (ulIndex == 3) && ( ulBrgInstanceNumber == 1))
                return GetBridgePortStatus("wlan0");
        else if( (ulIndex == 1) && ( ulBrgInstanceNumber == 2))
                return GetBridgePortStatus("brlan1");
        else if( (ulIndex == 2) && ( ulBrgInstanceNumber == 2))
                return GetBridgePortStatus("gretap0");
        else if( (ulIndex == 3) && ( ulBrgInstanceNumber == 2))
                return GetBridgePortStatus("wlan0_0");
}

/*
 *  Procedure         : GetBridgePortEnable
 *  Purpose           : To Get Bridge Port Enable Status
 *
 *  Parameters        : 
 *     string         : Having current Interface
 *  Return_values     : The status of the operation
 *     @retval true , if successful
 *     @retval false , if any error is detected
 */

bool GetBridgePortEnable(char *string)
{
        FILE *fp;
        char path[256] = {0},status[100] = {0} , command[100] = {0};
        int count = 0;
        if(strcmp(string,"wlan0") == 0)
        {
                system("ifconfig | grep wlan0 | grep -v wlan0_0 | grep -v mon.wlan0 | wc -l > /tmp/BridgePort_Enable");
        }
        else
        {
                sprintf(command,"%s%s%s","ifconfig | grep ",string," | wc -l  > /tmp/BridgePort_Enable");
                printf(" The command is %s \n",command);
                system(command);
        }
        fp = popen("cat /tmp/BridgePort_Enable","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return 0;
        }
        while(fgets(path, sizeof(path)-1, fp) != NULL)
        {
                for(count=0;path[count]!='\n';count++)
                        status[count]=path[count];
                status[count]='\0';
        }
        pclose(fp);
        if(strcmp(status,"1") == 0)
                return true;
        else
                return false;

}

/*
 *  Procedure              : CcspHalGetBridgePortEnable
 *  Purpose                : To Get Bridge Port Enable Status
 *
 *  Parameters             : 
 *     ulBrgInstanceNumber : Having Instance Number of Bridge
 *     ulIndex             : Having Instance Number of Port
 *  Return_values          : The status of the operation
 *     @retval true , if successful
 *     @retval false , if any error is detected
 */

bool CcspHalGetBridgePortEnable(ULONG ulIndex,ULONG ulBrgInstanceNumber)
{
        if( (ulIndex == 1) && ( ulBrgInstanceNumber == 1))
                return GetBridgePortEnable("brlan0");
        else if( (ulIndex == 2) && ( ulBrgInstanceNumber == 1))
                return GetBridgePortEnable("eth1");
        else if( (ulIndex == 3) && ( ulBrgInstanceNumber == 1))
                return GetBridgePortEnable("wlan0");
        else if( (ulIndex == 1) && ( ulBrgInstanceNumber == 2))
                return GetBridgePortEnable("brlan1");
        else if( (ulIndex == 2) && ( ulBrgInstanceNumber == 2))
                return GetBridgePortEnable("gretap0");
        else if( (ulIndex == 3) && ( ulBrgInstanceNumber == 2))
                return GetBridgePortEnable("wlan0_0");
}

/*
 *  Procedure           : CcspHalGetBridgePortStats
 *  Purpose             : To get Bridge Port Status Value is NULL
 *
 *  Parameters          : 
 *   pStats             : Having Bridge port stats details.
 *  Return_values       : None
 */

void CcspHalGetBridgePortStats(HALPCOSA_DML_ETH_STATS pStats)
{
        pStats->BroadcastPacketsReceived = 0;
        pStats->BroadcastPacketsSent = 0;
        pStats->BytesReceived = 0;
        pStats->BytesSent = 0;
        pStats->DiscardPacketsReceived = 0;
        pStats->DiscardPacketsSent = 0;
        pStats->ErrorsReceived = 0;
        pStats->ErrorsSent = 0;
        pStats->MulticastPacketsReceived = 0;
        pStats->MulticastPacketsSent = 0;
        pStats->PacketsReceived = 0;
        pStats->PacketsSent = 0;
        pStats->UnicastPacketsReceived = 0;
        pStats->UnicastPacketsSent = 0;
        pStats->UnknownProtoPacketsReceived = 0;
}

/*
 *  Procedure           : CcspHaldhcpv4cGetGw
 *  Purpose             : To get WAN Default Gateway Address 
 *
 *  Parameters          : 
 *   Gateway_Address    : Having WAN Default Gateway Address
 *  Return_values       : None
 */

void CcspHaldhcpv4cGetGw(char Gateway_Address[120])
{
	FILE *fp;
        char path[256] = {0},status[100] = {0};
        int count = 0;
        fp = popen("route -n | grep UG | tr -s ' ' | cut -d ' ' -f2","r");
        if(fp == NULL)
        {
                printf("Failed to run command in Function %s\n",__FUNCTION__);
                return;
        }
        if(fgets(path, sizeof(path)-1, fp) != NULL)
        {
        for(count=0;path[count]!='\n';count++)
                status[count]=path[count];
        status[count]='\0';
        }
        strcpy(Gateway_Address,status);
        pclose(fp);
}

/*
 *  Procedure           : CcspHalGetDNSServerValue
 *  Purpose             : To get primary and secondary DNSServer values
 *
 *  Parameters          : 
 *   InstanceNum        : Having Instance Number 
 *   DNSServer		: Having DNSServer Value
 *  Return_values       : None
 */

void CcspHalGetDNSServerValue(ULONG InstanceNum, char DNSServer[64])
{
	FILE *fp;
	char path[256] = {0},status[100] = {0};
	int count = 0;
	fp = popen("cat /etc/resolv.conf | grep nameserver | cut -d ' ' -f2","r");
	if(fp == NULL)
	{
		printf("Failed to run command in Function %s\n",__FUNCTION__);
		return;
	}
	if(InstanceNum == 1)
	{
		if(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
	}
	else if(InstanceNum == 2)
	{
		fgets(path, sizeof(path)-1, fp);
		if(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			for(count=0;path[count]!='\n';count++)
				status[count]=path[count];
			status[count]='\0';
		}
	}
	pclose(fp);
	strcpy(DNSServer,status);
}

/*
 *  Procedure           : CcspHalGetWanAddressMode
 *  Purpose             : Whether DHCP is enabled or disabled
 *
 *  Parameters          : None
 *  Return_values       : Status of the Operation
 *     @retval true , if successful
 *     @retval false , if any error is detected
 */

bool CcspHalGetWanAddressMode()
{
	FILE *fp = NULL;
	char path[512] = {0};
	unsigned long RX_packets = 0,RX_bytes = 0;
	int count = 0,c = 0,wlan0_0_count = 0;
	fp = popen ("ifconfig gretap0 | grep packets | grep RX | tr -s ' ' | cut -d ' ' -f3 | cut -d ':' -f2","r");
	if(fp == NULL)
		return 0;
	fgets(path,512,fp);
	RX_packets = atoi ( path );
	fp = popen ("ifconfig gretap0 | grep bytes | grep RX | tr -s ' ' | cut -d ' ' -f3 | cut -d ':' -f2","r");
	if(fp == NULL)
		return 0;
	fgets(path,512,fp);
	RX_bytes = atoi ( path );
	fp = popen ("ps -eaf | grep CcspHotspot | grep -v grep | wc -l","r");
	if(fp == NULL)
		return 0;
	fgets(path,512,fp);
	count = atoi ( path );
	fp = popen ("ifconfig | grep gretap0 | grep -v grep | wc -l","r");
        if(fp == NULL)
                return 0;
        while(fgets(path,512,fp) != NULL);
        c = atoi ( path );
	fp = popen ("iw dev wlan0_0 station dump | grep wlan0_0 | wc -l","r");
        if(fp == NULL)
                return 0;
        fgets(path,512,fp);
        wlan0_0_count = atoi ( path );
	pclose(fp);
	if((RX_bytes > 0) && (RX_packets > 0) && (count == 1) && (c == 1) && (wlan0_0_count > 0))
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*
 *  Procedure           : CcspHalDhcpcGetInfo
 *  Purpose             : To get LeaseTimeRemaining information for connected clients
 *
 *  Parameters          : None
 *  Return_values       : LeaseTimeRemaining value
 */

int CcspHalDhcpcGetInfo()
{
	FILE *fp;
	char path[256] = {0},lease_val[100] = {0};
	int count = 0,LeaseTimeRemaining = 0;
	fp = popen("cat /etc/dnsmasq.conf | grep -w dhcp-range | cut -d ',' -f4 ", "r");
	if (fp == NULL)
	{
		printf("Failed to run command inside function %s\n",__FUNCTION__);
	}
	else
	{
		fgets(path, sizeof(path)-1, fp);
		for(count=0;path[count]!='\n';count++)
			lease_val[count]=path[count];
		lease_val[count]='\0';
	}
	pclose(fp);
	LeaseTimeRemaining = atoi(lease_val);
	return LeaseTimeRemaining;
}
