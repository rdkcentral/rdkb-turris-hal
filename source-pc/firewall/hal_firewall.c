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
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#define __USE_GNU
#include <string.h>   // strcasestr needs __USE_GNU
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "ccsp/ansc_platform.h"
#include "hal_firewall.h"
#include <netinet/in.h>
#ifdef _ANSC_LINUX
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#endif

#define MAX_QUERY 256

#define UPLINK_IF_NAME "eth0"
#define UPLINKBR_IF_NAME "brlan0"

/*
 * For timed internet access rules we use cron 
 */
#define crontab_dir  "/var/spool/cron/crontabs/"
#define crontab_filename  "firewall"
#define cron_everyminute_dir "/etc/cron/cron.everyminute"
#define SYS_LOG_FILE	"/var/syslog_level"	
#define DEFAULT_LOGLEVEL_DEBUG	8

/* DSCP val for gre*/
extern ANSC_HANDLE bus_handle;//lnt
extern char g_Subsystem[32];//lnt

 
static int  lock_fd = -1;
static int isHttpBlocked=0;
static int isHttpsBlocked=0;
static int isP2pBlocked=0;                        // Block incoming P2P traffic
static int isPingBlocked=0;
static int isIdentBlocked=0;
static int isMulticastBlocked=0;
static int isFirewallEnabled;
static int isCronRestartNeeded;
static int ppFlushNeeded = 0;
static int isLogEnabled;
static int isLogSecurityEnabled;
static int isLogIncomingEnabled;
static int isLogOutgoingEnabled;
static char log_level[5];         // if logging is enabled then this is the log level
static int  log_leveli;           // an integer version of the above
static int  syslog_level; 

static char default_wan_ifname[50]; // name of the regular wan interface
static char current_wan_ifname[50]; // name of the ppp interface or the regular wan interface if no ppp
static char current_wan_ipaddr; // ipv4 address of the wan interface, whether ppp or regular
static char wan6_ifname[20];
static char wan_service_status[20];       // wan_service-status

static char *firewall_service_name = "firewall";
const char* const firewall_component_id = "ccsp.firewall";

static char default_wan_ifname[50];
static char lan_ifname[50];       // name of the lan interface
static char lan_3_octets[17];     // first 3 octets of the lan ipv4 address
static char firewall_level[20];   // None, Low, Medium, High, or Custom
char str[MAX_QUERY];

static bool InitialRuleSet = true;  //Initial Rule set to add iptables in DMZ
static bool InitialRule = true;     //Initial Rule Set to add iptables in Remote Management
int Portforwarding=0; //Disable portforwarding
int Porttriggering=0; //Disable porttriggering
int ParentalControlSite=0; //Disable   ParentalControl
int ParentalControlService=0; //Disable   ParentalControl
int ParentalControlDevice=0; //Disable   ParentalControl


/*
 *  Procedure     : to_syslog_level
 *  Purpose       : convert syscfg log_level to syslog level
 */
static int to_syslog_level (int log_leveli)
{
   switch (log_leveli) {
   case 2:
      return LOG_ALERT;
   case 3:
      return LOG_CRIT;
   case 4:
      return LOG_ERR;
   case 5:
      return LOG_WARNING;
   case 6:
      return LOG_NOTICE;
   case 7:
      return LOG_INFO;
   case 8:
      return LOG_DEBUG;
   case 1:
   default:	
      return LOG_EMERG;
   }
}

int get_syslog_level()
{
	FILE *fp;
	int level=0;
#if 1
	fp = fopen(SYS_LOG_FILE,"w"); //write mode
		if( fp == NULL )
		{
			perror("Error while Writing the file.\n");
			return ;
		}
	fprintf(fp, "%d", DEFAULT_LOGLEVEL_DEBUG);
	fclose(fp);

#endif
	fp = fopen(SYS_LOG_FILE,"r"); // read mode

	if( fp == NULL )
	{
		perror("Error while opening the file.\n");
		exit(EXIT_FAILURE);
	}

	printf("The contents of %s file are :\n", SYS_LOG_FILE);
	if(fscanf (fp, "%d", &level) == EOF)
		level = DEFAULT_LOGLEVEL_DEBUG;

	fclose(fp);
	return level;
}

int prepare_globals_from_configuration(struct custom_option *option)
{
      isPingBlocked = option->isPingBlocked;
      isMulticastBlocked = option->isMulticastBlocked;
      isHttpBlocked = option->isHttpBlocked;
      isHttpsBlocked = option->isHttpsBlocked;
      isIdentBlocked = option->isIdentBlocked;
      isFirewallEnabled =option->isFirewallEnabled;
      isP2pBlocked=option->isP2pBlocked; // Block incoming P2P traffic
      
      log_leveli = get_syslog_level();
      syslog_level = to_syslog_level (log_leveli);
      printf("ssyslog_level   %d \n",syslog_level);
      isLogEnabled      = (log_leveli > 1) ? 1 : 0;
      isLogSecurityEnabled = (isLogEnabled && log_leveli > 1) ? 1 : 0;
      isLogIncomingEnabled = (isLogEnabled && log_leveli > 1) ? 1 : 0;
      isLogOutgoingEnabled = (isLogEnabled && log_leveli > 1) ? 1 : 0;

}

/**********************************************************************
		PARENTAL CONTROL FUNCTION DEFINITIONS
***********************************************************************/

int do_parentalControl_Addrule_Sites()
{
        char cmd[1024];
	if(!ParentalControlSite)
	{
		sprintf(cmd,"iptables -N  ParentalControl_Sites  ");
		system(cmd);
		sprintf(cmd,"iptables -I FORWARD -j ParentalControl_Sites  ");
		system(cmd);
		ParentalControlSite = 1;
	}
}


int do_parentalControl_Addrule_Services()
{
        char cmd[1024];
	if(!ParentalControlService)
	{
		sprintf(cmd,"iptables -N  ParentalControl_Services  ");
		system(cmd);
		sprintf(cmd,"iptables -I FORWARD -j ParentalControl_Services  ");
		system(cmd);
		ParentalControlService = 1;
	}
}
int do_parentalControl_Addrule_Devices()
{
        char cmd[1024];
	if(!ParentalControlDevice)
	{
		sprintf(cmd,"iptables -t nat -N  ParentalControl_Devices  ");
		system(cmd);
		sprintf(cmd,"iptables -t nat -A PREROUTING  -j ParentalControl_Devices  ");
		system(cmd);
		ParentalControlDevice = 1;
	}
}

int do_parentalControl_Delrule_Sites()
{
        char cmd[1024];
	if( ParentalControlSite )
	{
		sprintf(cmd,"iptables -F  ParentalControl_Sites  ");
		system(cmd);
		sprintf(cmd,"iptables -D FORWARD -j ParentalControl_Sites  ");
		system(cmd);
		sprintf(cmd,"iptables -X  ParentalControl_Sites  ");
		system(cmd);
		ParentalControlSite = 0;
	}
}

int do_parentalControl_Delrule_Services()
{
        char cmd[1024];
	if(ParentalControlService)
	{
		sprintf(cmd,"iptables -F  ParentalControl_Services  ");
		system(cmd);
		sprintf(cmd,"iptables -D FORWARD -j ParentalControl_Services  ");
		system(cmd);
		sprintf(cmd,"iptables -X  ParentalControl_Services  ");
		system(cmd);
		ParentalControlService = 0;
	}
}
int do_parentalControl_Delrule_Devices()
{
        char cmd[1024];
	if(ParentalControlDevice)
	{
		sprintf(cmd,"iptables -t nat -F  ParentalControl_Devices  ");
		system(cmd);
		sprintf(cmd,"iptables -t nat -D PREROUTING -j ParentalControl_Devices  ");
		system(cmd);
		sprintf(cmd,"iptables -t nat -X  ParentalControl_Devices  ");
		system(cmd);
		ParentalControlDevice = 0;
	}
}

int do_parentalControl_Sites(int OPERATION,COSA_DML_BLOCKEDURL *i_BlockedURLs)
{
	  int len;
          char newvar[1024];
          char cmd[1024]= {'\0'};
          char url[1024];
          const char s[] = "://";
          char *token;
          char strWord[1024];     
          switch(OPERATION)
          {
                  case ADD:
			  strcpy(newvar,"iptables  -A ParentalControl_Sites  ");
			  break;
                  case DELETE:
			  strcpy(newvar,"iptables  -D ParentalControl_Sites  ");
			  break;
	  }

	  if(i_BlockedURLs->BlockMethod == BLOCK_METHOD_URL)
          {
                  token = strtok(i_BlockedURLs->Site,s);
                  len = strlen(token);
                  strcpy(strWord,i_BlockedURLs->Site+len+3);
          }
          else if(i_BlockedURLs->BlockMethod == BLOCK_METHOD_KEYWORD)
          {
                  strcpy(strWord,i_BlockedURLs->Site);
          }

         if(!i_BlockedURLs->AlwaysBlock )
          {
               snprintf(cmd,sizeof(cmd),"%s  -m string --algo bm --string %s -m time --timestart %s --timestop %s --weekdays %s -j DROP",newvar,strWord,i_BlockedURLs->StartTime,i_BlockedURLs->EndTime,i_BlockedURLs->BlockDays);                 
	  }
         else
          {
               snprintf(cmd,sizeof(cmd),"%s  -m string --algo bm --string %s -j DROP",newvar,strWord);
          }
          system(cmd);
}

int do_parentalControl_Services(int OPERATION,COSA_DML_MS_SERV *i_MSServs)
{
          char newvar[1024];
          char action[10];
          ULONG startport;
          char cmd[1024]= {'\0'};
          char protocol[10];
          char protocol1[10];

          switch(OPERATION)
          {
                  case ADD:
          		strcpy(newvar,"iptables  -A  ParentalControl_Services  ");
			break;
                  case DELETE:
          		strcpy(newvar,"iptables  -D  ParentalControl_Services ");
			break;
	 }
	  switch(i_MSServs->Protocol)
          {
                  case PROTO_TCP:
                          strcpy(protocol,"tcp");
                          break;
                  case PROTO_UDP:
                          strcpy(protocol,"udp");
                          break;
                  case PROTO_BOTH:
                          strcpy(protocol,"tcp");
                          strcpy(protocol1,"udp");
                          break;
          }
	  if(i_MSServs->StartPort == i_MSServs->EndPort)
          {
                if(!i_MSServs->AlwaysBlock)
                {
                       if(i_MSServs->Protocol != PROTO_BOTH)
                       {
                             snprintf(cmd,sizeof(cmd),"%s -p %s  --destination-port %ld -m time --timestart %s --timestop %s --weekdays %s -j DROP",newvar,protocol,i_MSServs->StartPort,i_MSServs->StartTime,i_MSServs->EndTime,i_MSServs->BlockDays);
                              system(cmd);
                       }
                       else
                       {
                            snprintf(cmd,sizeof(cmd),"%s -p %s --destination-port %ld -m time --timestart %s --timestop %s --weekdays %s -j DROP",newvar,protocol,i_MSServs->StartPort,i_MSServs->StartTime,i_MSServs->EndTime,i_MSServs->BlockDays);
                            system(cmd);
                            snprintf(cmd,sizeof(cmd),"%s -p %s --destination-port %ld -m time --timestart %s --timestop %s --weekdays %s-j DROP",newvar,protocol1,i_MSServs->StartPort,i_MSServs->StartTime,i_MSServs->EndTime,i_MSServs->BlockDays);
                            system(cmd);

                       }
                }
                else
                {
                      if(i_MSServs->Protocol != PROTO_BOTH)
                       {
                             snprintf(cmd,sizeof(cmd),"%s -p %s  --destination-port %ld  -j DROP",newvar,protocol,i_MSServs->StartPort);
                             system(cmd);
                        }
                        else
                       {
                             snprintf(cmd,sizeof(cmd),"%s -p %s --destination-port %ld  -j DROP",newvar,protocol,i_MSServs->StartPort);
                             system(cmd);
                             snprintf(cmd,sizeof(cmd),"%s -p %s  --destination-port %ld  -j DROP",newvar,protocol1,i_MSServs->StartPort);
                             system(cmd);
                       }
                 }
         }
         else
         {
              if(!i_MSServs->AlwaysBlock)
              {
                     if(i_MSServs->Protocol != PROTO_BOTH)
                     {
                          snprintf(cmd,sizeof(cmd),"%s -p %s -m multiport --dports %ld:%ld -m time --timestart %s --timestop %s --weekdays %s -j DROP",newvar,protocol,i_MSServs->StartPort,i_MSServs->EndPort,i_MSServs->StartTime,i_MSServs->EndTime,i_MSServs->BlockDays);
                           system(cmd);
                     }
                     else
                     {
                          snprintf(cmd,sizeof(cmd),"%s -p %s -m multiport --dports %ld:%ld -m time --timestart %s  --timestop %s --weekdays %s -j DROP",newvar,protocol,i_MSServs->StartPort,i_MSServs->EndPort,i_MSServs->StartTime,i_MSServs->EndTime,i_MSServs->BlockDays);
                          system(cmd);
   
                          snprintf(cmd,sizeof(cmd),"%s -p %s -m multiport --dports %ld:%ld -m time --timestart %s  --timestop %s --weekdays %s -j DROP",newvar,protocol1,i_MSServs->StartPort,i_MSServs->EndPort,i_MSServs->StartTime,i_MSServs->EndTime,i_MSServs->BlockDays);
                          system(cmd);
                     }
             }
             else
             {
                     if(i_MSServs->Protocol != PROTO_BOTH)
                     {
                            snprintf(cmd,sizeof(cmd),"%s -p %s -m multiport --dports %ld:%ld  -j DROP",newvar,protocol,i_MSServs->StartPort,i_MSServs->EndPort);
                            system(cmd);
                     }
                     else
                     {
                              snprintf(cmd,sizeof(cmd),"%s -p %s -m multiport --dports %ld:%ld  -j DROP",newvar,protocol,i_MSServs->StartPort,i_MSServs->EndPort);
                              system(cmd);
                              snprintf(cmd,sizeof(cmd),"%s -p %s -m multiport --dports %ld:%ld  -j DROP",newvar,protocol1,i_MSServs->StartPort,i_MSServs->EndPort);
                              system(cmd);
  
                      }
              }
  
       }
}

int do_parentalControl_Devices(int OPERATION,COSA_DML_MD_DEV *i_MDDevs)
{
	  int i;
          char newvar[1024] = {'\0'};
	  char exec_cmd[512] = {'\0'};
          char cmd[1024]= {'\0'},exe_cmd[1024]={'\0'};
          char protocol1[10];
          char action[100] = {0};
	  switch(OPERATION)
          {
                  case ADD:
                        strcpy(newvar,"iptables -t nat  -I  ParentalControl_Devices");
			strcpy(exec_cmd,"iptables -I FORWARD");
                          break;
                  case DELETE:
                        strcpy(newvar,"iptables -t nat -D  ParentalControl_Devices");
			strcpy(exec_cmd,"iptables -D FORWARD");
                          break;
          }


          if( !i_MDDevs->AlwaysBlock )
          {
                if(i_MDDevs->Type == MD_TYPE_BLOCK)
                {
	                sprintf(action,"prerouting_redirect");
			snprintf(cmd,sizeof(cmd),"%s -p tcp -m mac --mac-source %s -m time --timestart %s --timestop %s --weekdays %s -j %s",newvar,i_MDDevs->MACAddress,i_MDDevs->StartTime,i_MDDevs->EndTime,i_MDDevs->BlockDays,action);
			snprintf(exe_cmd,sizeof(exe_cmd),"%s -p udp ! --dport 67 -m mac --mac-source %s -m time --timestart %s --timestop %s --weekdays %s -j %s",newvar,i_MDDevs->MACAddress,i_MDDevs->StartTime,i_MDDevs->EndTime,i_MDDevs->BlockDays,action);
			system(exe_cmd);
			sprintf(exe_cmd,"iptables -D FORWARD -p icmp -m mac --mac-source %s -j DROP",i_MDDevs->MACAddress);
			system(exe_cmd);
			snprintf(exe_cmd,sizeof(exe_cmd),"%s -p icmp -m mac --mac-source %s -j DROP",exec_cmd,i_MDDevs->MACAddress);
			system(exe_cmd);
                }
                else if(i_MDDevs->Type == MD_TYPE_ALLOW)
                {
		       sprintf(action,"ACCEPT");
                       snprintf(cmd,sizeof(cmd),"%s -p tcp -m mac --mac-source %s -m time --timestart %s --timestop %s --weekdays %s -j %s",newvar,i_MDDevs->MACAddress,i_MDDevs->StartTime,i_MDDevs->EndTime,i_MDDevs->BlockDays,action);
                }
	 }
	 else
         {
               if(i_MDDevs->Type == MD_TYPE_BLOCK)
               {
	                sprintf(action,"prerouting_redirect");
                        snprintf(cmd,sizeof(cmd),"%s -p tcp -m mac --mac-source %s -j %s",newvar,i_MDDevs->MACAddress,action);
                        snprintf(exe_cmd,sizeof(exe_cmd),"%s -p udp ! --dport 67 -m mac --mac-source %s -j %s",newvar,i_MDDevs->MACAddress,action);
			system(exe_cmd);
			sprintf(exe_cmd,"iptables -D FORWARD -p icmp -m mac --mac-source %s -j DROP",i_MDDevs->MACAddress);
			system(exe_cmd);
			snprintf(exe_cmd,sizeof(exe_cmd),"%s -p icmp -m mac --mac-source %s -j DROP",exec_cmd,i_MDDevs->MACAddress);
			system(exe_cmd);
               }
               else if(i_MDDevs->Type == MD_TYPE_ALLOW)
               {
		        sprintf(action,"ACCEPT");
                        snprintf(cmd,sizeof(cmd),"%s -p tcp -m mac --mac-source %s -j %s",newvar,i_MDDevs->MACAddress,action);
               }
          }
          system(cmd);
}
 
void CosaDmlTrustedUser_Accept(int block_type,char  ipAddress[64],int operation)
{
        char cmd[1024];
        LONG ruleNumber;
        switch(block_type)
        {
                case TRUSTEDSITE_TYPE:
                        if(operation == ADD)
                         {
                             sprintf(cmd,"iptables -I ParentalControl_Sites  -s %s -j ACCEPT",ipAddress);
                         }
                         else
                         {
                             sprintf(cmd,"iptables -D ParentalControl_Sites  -s %s -j ACCEPT",ipAddress);
                         }
                        break;
               case TRUSTEDSERVICE_TYPE:
                       if(operation == ADD)
                       {
                            sprintf(cmd,"iptables -I ParentalControl_Services  -s %s -j ACCEPT",ipAddress);
                       }
                       else
                       {
                            sprintf(cmd,"iptables -D ParentalControl_Services  -s %s -j ACCEPT",ipAddress);
                       }
                       break;
        }
        system(cmd);

}

/*************************************************************************************
				FIREWALL FUNCTION DEFINITIONS
**************************************************************************************/
int do_nonat(FILE *filter_fp,struct NetworkDetails *netDetails)
{

	char lan_netmask[16]="";
	char lan_ipaddr[16]="";
	char wan_netmask[16]="";
	char wan_ipaddr[16]="";
	char netmaskfull[16]="255.255.255.255\0";

	sprintf(lan_ipaddr, "%d.%d.%d.%d\0", (netDetails->LanIPAddress).Dot[0],\
              (netDetails->LanIPAddress).Dot[1], (netDetails->LanIPAddress).Dot[2],\
	      (netDetails->LanIPAddress).Dot[3] );
	sprintf(lan_netmask, "%d.%d.%d.%d\0", (netDetails->LanSubnetMask).Dot[0],\
	      (netDetails->LanSubnetMask).Dot[1],(netDetails->LanSubnetMask).Dot[2],\
              (netDetails->LanSubnetMask).Dot[3]);
	sprintf(wan_ipaddr, "%d.%d.%d.%d\0", (netDetails->WanIPAddress).Dot[0],\
              (netDetails->WanIPAddress).Dot[1], (netDetails->WanIPAddress).Dot[2],\
              (netDetails->WanIPAddress).Dot[3] );
	sprintf(wan_netmask, "%d.%d.%d.%d\0", (netDetails->WanSubnetMask).Dot[0],\
              (netDetails->WanSubnetMask).Dot[1], (netDetails->WanSubnetMask).Dot[2],\
              (netDetails->WanSubnetMask).Dot[3] );

	if (strncasecmp(firewall_level, "High", strlen("High")) == 0)
	{
		fprintf(filter_fp, "-A INPUT  -i %s -j firewall_wan2self \n",\
							netDetails->UpLink_IF);
		fprintf(filter_fp, "-A OUTPUT -d %s/%s -j firewall_lan2self\n",\
							 lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A OUTPUT -s %s/%s  -j firewall_lan2wan\n",\
							 lan_ipaddr,lan_netmask);
		fprintf(filter_fp, "-A OUTPUT -d %s/%s  -j firewall_lan2self\n",\
							 lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A FORWARD -i %s -o %s -j firewall_wan2lan\n", netDetails->UpLink_IF, netDetails->UpLinkBr_IF);
		fprintf(filter_fp, "-A FORWARD -i %s -o %s -j firewall_lan2wan\n", netDetails->UpLinkBr_IF, netDetails->UpLink_IF);
		fprintf(filter_fp, "-A FORWARD -s %s/%s  -d %s/%s  \
		     -j firewall_lan2lan\n",lan_ipaddr,lan_netmask,lan_ipaddr,lan_netmask);

		fprintf(filter_fp, "-A firewall_wan2self -p tcp -m tcp  -m multiport  \
			--dports 80,443,53,119,123,25,110,143,465,587,993,995,3689,1723\
			-j firewall_wan2self_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2self -p udp  -m udp  -m multiport \ 
			--dports 53,500,1194,1196   -j firewall_wan2self_accept_log\n");	
		fprintf(filter_fp, "-A firewall_wan2self  -p gre \
						    -j firewall_wan2self_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2self -p tcp --dport 8000:8999 \
						    -j firewall_wan2self_accept_log\n");	
		fprintf(filter_fp, "-A firewall_wan2self  -p tcp --dport 42000:42999 \
                                                    -j firewall_wan2self_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2self -m state --state RELATED,ESTABLISHED \
                                                    -j firewall_wan2self_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2self -p tcp -m tcp  -m multiport \
                 ! --dports 80,443,53,119,123,25,110,143,465,587,993,995,3689,1723\
						      -j firewall_wan2self_drop_log\n");
		fprintf(filter_fp, "-A firewall_wan2self -p udp  -m udp  -m multiport\
	         ! --dports 53,500,1194,1196   -j firewall_wan2self_drop_log\n");
		fprintf(filter_fp, "-A firewall_wan2self    -j firewall_wan2self_drop_log\n");

		fprintf(filter_fp, "-A firewall_lan2lan -s %s/%s -d %s/%s \
		-j firewall_lan2lan_accept_log\n",lan_ipaddr,lan_netmask,lan_ipaddr,lan_netmask);
		fprintf(filter_fp, "-A firewall_lan2wan -p gre -j firewall_lan2wan_accept_log\n");
		fprintf(filter_fp, "-A firewall_lan2wan -p udp  -m udp  -m multiport  \
		--dports 53,67,68,500,1194,1196  -j firewall_lan2wan_accept_log\n");
		fprintf(filter_fp, "-A firewall_lan2wan -p tcp -m tcp  -m multiport \
		--dports 80,443,53,119,123,25,110,143,465,587,993,995,3689,1723 \
		-j firewall_lan2wan_accept_log\n");
		fprintf(filter_fp, "-A firewall_lan2wan -p tcp --dport 8000:8999 \
						-j firewall_lan2wan_accept_log\n");	
		fprintf(filter_fp, "-A firewall_lan2wan -p tcp --dport 42000:42999\ 
						-j firewall_lan2wan_accept_log\n");
		fprintf(filter_fp, "-A firewall_lan2wan -m state --state RELATED,ESTABLISHED \
						-j firewall_lan2wan_accept_log\n");
		fprintf(filter_fp, "-A firewall_lan2wan -p tcp -m tcp  -m multiport\
		 ! --dports 80,443,53,119,123,25,110,143,465,587,993,995,3689,1723 \
						  -j firewall_lan2wan_drop_log\n");
		fprintf(filter_fp, "-A firewall_lan2wan -p udp  -m udp  -m multiport \
		! --dports 53,67,68,500,1194,1196  -j firewall_lan2wan_drop_log\n");
		fprintf(filter_fp, "-A firewall_lan2wan -j firewall_lan2wan_drop_log\n");

		fprintf(filter_fp, "-A firewall_wan2lan -p gre -j firewall_wan2lan_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan -p tcp --dport 8000:8999 \
							-j firewall_wan2lan_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan -p tcp --dport 42000:42999\ 
							-j firewall_wan2lan_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan -p udp -m udp -m multiport \ 
			       --dports 53,500,1194,1196 -j firewall_wan2lan_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan -p tcp -m tcp -m multiport  \
				--dports 80,443,53,119,123,25,110,143,465,587,993,995,3689,1723\
							-j firewall_wan2lan_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan -m state --state ESTABLISHED,RELATED \
							  -j firewall_wan2lan_accept_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan -p udp -m udp -m multiport \
				! --dports 53,500,1194,1196 -j firewall_wan2lan_drop_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan -p tcp -m tcp -m multiport \
		! --dports 80,443,53,119,123,25,110,143,465,587,993,995,3689,1723 \
		-j firewall_wan2lan_drop_log\n");
		fprintf(filter_fp, "-A firewall_wan2lan  -j firewall_wan2lan_drop_log\n");
		fprintf(filter_fp, "-A firewall_lan2self -p gre  -j firewall_lan2self_accept_log\n",\
			lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A firewall_lan2self -p udp -m udp -m multiport\  
		--dports 53,500,1194,1196  -j firewall_lan2self_accept_log\n",lan_ipaddr,netmaskfull);	
		fprintf(filter_fp, "-A firewall_lan2self -p tcp -m tcp -m multiport \ 
		--dports 80,443,53,119,123,25,110,143,465,587,993,995,1723,3689 \
		-j firewall_lan2self_accept_log  \n",lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A firewall_lan2self -p tcp  --dport 42000:42999 \
		-j firewall_lan2self_accept_log  \n",lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A firewall_lan2self  -p tcp  --dport 8000:8999 \
		-j firewall_lan2self_accept_log  \n",lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A firewall_lan2self -m state --state RELATED,ESTABLISHED \
		-j firewall_lan2self_accept_log\n");	
		fprintf(filter_fp, "-A firewall_lan2self -p udp -m udp -m multiport \
		! --dports 53,500,1194,1196  -j firewall_lan2self_drop_log\n",lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A firewall_lan2self -p tcp -m tcp -m multiport \
		! --dports 80,443,53,119,123,25,110,143,465,587,993,995,1723,3689 \
		-j firewall_lan2self_drop_log\n",lan_ipaddr,netmaskfull);	
		fprintf(filter_fp, "\n");
     } 
     else if (strncasecmp(firewall_level, "Medium", strlen("Medium")) == 0)
     {
          // ALLOW ALL

         fprintf(filter_fp, "-A INPUT -s 0/0 -d %s/%s -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
         fprintf(filter_fp, "-A OUTPUT -s %s/%s -d 0/0 -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
         fprintf(filter_fp, "-A FORWARD -s %s/%s -d 0/0 -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);

                // IDENT
         fprintf(filter_fp, "-A INPUT -p tcp --dport 113 -j firewall_reject_log\n"); // IDENT

     // ICMP
        fprintf(filter_fp,"-A INPUT -i %s  -p icmp --icmp-type 8\ 
                    -s 0/0 -d %s/%s  -m state --state NEW,ESTABLISHED,RELATED \
                        -j firewall_wan2lan_drop_log\n",netDetails->UpLink_IF,wan_ipaddr,wan_netmask);
 //Vuze
            fprintf(filter_fp, "-A INPUT -p tcp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-A INPUT -p udp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-A FORWARD -p tcp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-A FORWARD -p udp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-A OUTPUT -p tcp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-A OUTPUT -p udp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);

// GLUTELLA
            fprintf(filter_fp,"-A INPUT -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A INPUT -p TCP -m string --string \"urn:sha1:\" --algo bm -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A INPUT -p TCP -m string --string \"GET /get/\" --algo bm  -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A INPUT -p TCP -m string --string \"GET /uri-res/\" --algo bm -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A INPUT -p tcp --dport 6346 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A INPUT -p udp --dport 6346 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-A OUTPUT -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A OUTPUT -p TCP -m string --string \"urn:sha1:\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A OUTPUT -p TCP -m string --string \"GET /get/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A OUTPUT -p TCP -m string --string \"GET /uri-res/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A OUTPUT -p tcp --dport 6346  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A OUTPUT -p udp --dport 6346 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"urn:sha1:\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"GET /get/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"GET /uri-res/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A FORWARD -p tcp --dport 6346  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A FORWARD -p udp --dport 6346 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

                //KAAZA
            fprintf(filter_fp,"-A INPUT -p TCP -m string --string \"X-Kazaa-\" --algo bm  -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A INPUT -p UDP -m string --string \"KaZaA\" --algo bm -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A INPUT -p UDP -m string --string \"fileshare\" --algo bm  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-A OUTPUT -p TCP -m string --string \"X-Kazaa-\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A OUTPUT -p UDP -m string --string \"KaZaA\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A OUTPUT -p UDP -m string --string \"fileshare\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A OUTPUT -p tcp --dport 1214  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A OUTPUT -p udp --dport 1214 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"X-Kazaa-\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A FORWARD -p UDP -m string --string \"KaZaA\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-A FORWARD -p UDP -m string --string \"fileshare\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

                //BITTORRENT

            fprintf(filter_fp, "-A INPUT  -p tcp --dport 6881:6999 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A INPUT -m string --string \"BitTorrent\" --algo bm --to 65535 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A INPUT -m string --string \"BitTorrent protocol\" --algo bm --to 65535  -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A INPUT -p TCP -m string --string \"BitTorrent protocol\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp, "-A OUTPUT  -p tcp --dport 6881:6999 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A OUTPUT -m string --string \"BitTorrent\" --algo bm --to 65535 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A OUTPUT -m string --string \"BitTorrent protocol\" --algo bm --to 65535 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A OUTPUT -p TCP -m string --string \"BitTorrent protocol\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);


            fprintf(filter_fp, "-A FORWARD  -p tcp --dport 6881:6999 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A FORWARD -m string --string \"BitTorrent\" --algo bm --to 65535 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A FORWARD -m string --string \"BitTorrent protocol\" --algo bm --to 65535  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-A FORWARD -p TCP -m string --string \"BitTorrent protocol\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);

 /// GLUTELLA
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm  -j firewall_reject_log   \n");
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"urn:sha1:\" --algo bm  -j firewall_reject_log   \n");
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"GET /get/\" --algo bm -j firewall_reject_log   \n");
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"GET /uri-res/\" --algo bm -j firewall_reject_log   \n");
            fprintf(filter_fp, "-A FORWARD -p tcp --dport 6346 -j firewall_wan2lan_drop_log\n"); // Gnutella
            fprintf(filter_fp, "-A FORWARD -p udp --dport 6346 -j firewall_wan2lan_drop_log\n"); // Gnutella

                //KAAZA
            fprintf(filter_fp,"-A FORWARD -p TCP -m string --string \"X-Kazaa-\" --algo bm  -j firewall_reject_log  \n");
            fprintf(filter_fp,"-A FORWARD -p UDP -m string --string \"KaZaA\" --algo bm  -j firewall_wan2lan_drop_log\n");
            fprintf(filter_fp,"-A FORWARD -p UDP -m string --string \"fileshare\" --algo bm  -j  firewall_wan2lan_drop_log\n");
            fprintf(filter_fp, "-A FORWARD -p tcp --dport 1214 -j firewall_wan2lan_drop_log\n"); // Kazaa
            fprintf(filter_fp, "-A FORWARD -p udp --dport 1214 -j firewall_wan2lan_drop_log\n"); // Kazaa


                //BITTORRENT
            fprintf(filter_fp, "-A FORWARD  -p tcp --dport 6881:6999 -j firewall_wan2lan_drop_log\n"); // Bittorrent
            fprintf(filter_fp, "-A FORWARD -m string --string \"BitTorrent\" --algo bm --to 65535 -j firewall_wan2lan_drop_log\n");
            fprintf(filter_fp, "-A FORWARD -m string --string \"BitTorrent protocol\" --algo bm --to 65535 -j firewall_wan2lan_drop_log\n");
            fprintf(filter_fp, "-A FORWARD -p TCP -m string --string \"BitTorrent protocol\" --algo bm -j firewall_reject_log  \n");

             snprintf(str, sizeof(str), "-A INPUT   -s 0/0 -d %s/%s -j firewall_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
             fprintf(filter_fp, "%s\n", str);
             snprintf(str, sizeof(str), "-A OUTPUT -s %s/%s -d 0/0 -j firewall_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
             fprintf(filter_fp, "%s\n", str);
             snprintf(str, sizeof(str), "-A FORWARD -s %s/%s -d 0/0  -j firewall_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
             fprintf(filter_fp, "%s\n", str);
             printf("%s\n",str);
  
	        
      }
      else if (strncasecmp(firewall_level, "Low", strlen("Low")) == 0)
      {
	 fprintf(filter_fp, "-A INPUT -s 0/0 -d %s/%s -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
         fprintf(filter_fp, "-A OUTPUT -s %s/%s -d 0/0 -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
         fprintf(filter_fp, "-A FORWARD -s %s/%s -d 0/0 -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);

                // IDENT
         fprintf(filter_fp, "-A INPUT -p tcp --dport 113 -j firewall_reject_log\n"); // IDENT

         snprintf(str, sizeof(str), "-A INPUT   -s 0/0 -d %s/%s -j firewall_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
         fprintf(filter_fp, "%s\n", str);
         snprintf(str, sizeof(str), "-A OUTPUT -s %s/%s -d 0/0 -j firewall_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
         fprintf(filter_fp, "%s\n", str);
         snprintf(str, sizeof(str), "-A FORWARD -s %s/%s -d 0/0  -j firewall_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
         fprintf(filter_fp, "%s\n", str);
         printf("%s\n",str);

	
      }
      else if (strncasecmp(firewall_level, "Custom", strlen("Custom")) == 0)
      {
  // ALLOW ALL

         fprintf(filter_fp, "-A INPUT -s 0/0 -d %s/%s -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
         fprintf(filter_fp, "-A OUTPUT -s %s/%s -d 0/0 -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
         fprintf(filter_fp, "-A FORWARD -s %s/%s -d 0/0 -j firewall_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);


		fprintf(filter_fp, "-A INPUT  -i %s -j firewall_wan2lan \n",\
							netDetails->UpLink_IF);
		fprintf(filter_fp, "-A OUTPUT -d %s/%s -j firewall_lan2self\n",\
							 lan_ipaddr,netmaskfull);
		fprintf(filter_fp, "-A OUTPUT -s %s/%s  -j firewall_lan2wan\n",\
							 lan_ipaddr,lan_netmask);
		fprintf(filter_fp, "-A FORWARD -i %s -o %s -j firewall_wan2lan\n", netDetails->UpLink_IF, netDetails->UpLinkBr_IF);
		fprintf(filter_fp, "-A FORWARD -i %s -o %s -j firewall_lan2wan\n", netDetails->UpLinkBr_IF, netDetails->UpLink_IF);
		fprintf(filter_fp, "-A FORWARD -s %s/%s  -d %s/%s  \
		     -j firewall_lan2lan\n",lan_ipaddr,lan_netmask,lan_ipaddr,lan_netmask);
		
		fprintf(filter_fp, "-A firewall_lan2wan -j firewall_lan2wan_accept_log\n");
		fprintf(filter_fp, "-A firewall_lan2lan -j firewall_lan2wan_accept_log\n");

		if(isHttpBlocked && isHttpsBlocked)
	        {
			fprintf(filter_fp, "-A firewall_wan2lan  -p tcp -m tcp   -m multiport --sports 80,443  -s 0/0 -d %s/%s \
			-j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
			fprintf(filter_fp, "-A firewall_wan2lan \ 
			-p udp -m udp   -m multiport --sports 80,443  -s 0/0 -d %s/%s \
			-j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
	        }
	        if (isIdentBlocked)
	        {
                // IDENT
         fprintf(filter_fp, "-I INPUT -p tcp --dport 113 -j firewall_reject_log\n"); // IDENT


	        }
       		if (isPingBlocked)
	        {
			// ICMP
			fprintf(filter_fp,"-A firewall_wan2lan -p icmp --icmp-type 8\ 
			-s 0/0 -d %s/%s  -m state --state NEW,ESTABLISHED,RELATED \
			-j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
	        }
        
		if (isP2pBlocked)
	        {
            fprintf(filter_fp, "-I INPUT -p tcp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-I INPUT -p udp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-I FORWARD -p tcp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-I FORWARD -p udp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-I OUTPUT -p tcp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);
            fprintf(filter_fp, "-I OUTPUT -p udp --dport 49152:65534 -s %s/%s -d 0/0 -j firewall_wan2lan_drop_log\n",lan_ipaddr,lan_netmask);

   /// GLUTELLA
            fprintf(filter_fp,"-I INPUT -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I INPUT -p TCP -m string --string \"urn:sha1:\" --algo bm -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I INPUT -p TCP -m string --string \"GET /get/\" --algo bm  -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I INPUT -p TCP -m string --string \"GET /uri-res/\" --algo bm -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I INPUT -p tcp --dport 6346 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I INPUT -p udp --dport 6346 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-I OUTPUT -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I OUTPUT -p TCP -m string --string \"urn:sha1:\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I OUTPUT -p TCP -m string --string \"GET /get/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I OUTPUT -p TCP -m string --string \"GET /uri-res/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I OUTPUT -p tcp --dport 6346  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I OUTPUT -p udp --dport 6346 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"urn:sha1:\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"GET /get/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"GET /uri-res/\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I FORWARD -p tcp --dport 6346  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I FORWARD -p udp --dport 6346 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

              //KAAZA
            fprintf(filter_fp,"-I INPUT -p TCP -m string --string \"X-Kazaa-\" --algo bm  -s 0/0 -d %s/%s -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I INPUT -p UDP -m string --string \"KaZaA\" --algo bm -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I INPUT -p UDP -m string --string \"fileshare\" --algo bm  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-I OUTPUT -p TCP -m string --string \"X-Kazaa-\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I OUTPUT -p UDP -m string --string \"KaZaA\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I OUTPUT -p UDP -m string --string \"fileshare\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I OUTPUT -p tcp --dport 1214  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I OUTPUT -p udp --dport 1214 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"X-Kazaa-\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I FORWARD -p UDP -m string --string \"KaZaA\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp,"-I FORWARD -p UDP -m string --string \"fileshare\" --algo bm  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I FORWARD -p tcp --dport 1214  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I FORWARD -p udp --dport 1214  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
              //BITTORRENT

            fprintf(filter_fp, "-I INPUT  -p tcp --dport 6881:6999 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I INPUT -m string --string \"BitTorrent\" --algo bm --to 65535 -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I INPUT -m string --string \"BitTorrent protocol\" --algo bm --to 65535  -s 0/0 -d %s/%s -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I INPUT -p TCP -m string --string \"BitTorrent protocol\" --algo bm -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);

            fprintf(filter_fp, "-I OUTPUT  -p tcp --dport 6881:6999 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I OUTPUT -m string --string \"BitTorrent\" --algo bm --to 65535 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I OUTPUT -m string --string \"BitTorrent protocol\" --algo bm --to 65535 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I OUTPUT -p TCP -m string --string \"BitTorrent protocol\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);


            fprintf(filter_fp, "-I FORWARD  -p tcp --dport 6881:6999 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I FORWARD -m string --string \"BitTorrent\" --algo bm --to 65535 -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I FORWARD -m string --string \"BitTorrent protocol\" --algo bm --to 65535  -s  %s/%s -d 0/0  -j firewall_wan2lan_drop_log\n",wan_ipaddr,wan_netmask);
            fprintf(filter_fp, "-I FORWARD -p TCP -m string --string \"BitTorrent protocol\" --algo bm  -s  %s/%s -d 0/0 -j firewall_reject_log  \n",wan_ipaddr,wan_netmask);

 /// GLUTELLA
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"GNUTELLA CONNECT\" --algo bm  -j firewall_reject_log   \n");
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"urn:sha1:\" --algo bm  -j firewall_reject_log   \n");
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"GET /get/\" --algo bm -j firewall_reject_log   \n");
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"GET /uri-res/\" --algo bm -j firewall_reject_log   \n");
            fprintf(filter_fp, "-I FORWARD -p tcp --dport 6346 -j firewall_wan2lan_drop_log\n"); // Gnutella
            fprintf(filter_fp, "-I FORWARD -p udp --dport 6346 -j firewall_wan2lan_drop_log\n"); // Gnutella

         //KAAZA
            fprintf(filter_fp,"-I FORWARD -p TCP -m string --string \"X-Kazaa-\" --algo bm  -j firewall_reject_log  \n");
            fprintf(filter_fp,"-I FORWARD -p UDP -m string --string \"KaZaA\" --algo bm  -j firewall_wan2lan_drop_log\n");
            fprintf(filter_fp,"-I FORWARD -p UDP -m string --string \"fileshare\" --algo bm  -j  firewall_wan2lan_drop_log\n");
            fprintf(filter_fp, "-I FORWARD -p tcp --dport 1214 -j firewall_wan2lan_drop_log\n"); // Kazaa
            fprintf(filter_fp, "-I FORWARD -p udp --dport 1214 -j firewall_wan2lan_drop_log\n"); // Kazaa


                //BITTORRENT
            fprintf(filter_fp, "-I FORWARD  -p tcp --dport 6881:6999 -j firewall_wan2lan_drop_log\n"); // Bittorrent
            fprintf(filter_fp, "-I FORWARD -m string --string \"BitTorrent\" --algo bm --to 65535 -j firewall_wan2lan_drop_log\n");
            fprintf(filter_fp, "-I FORWARD -m string --string \"BitTorrent protocol\" --algo bm --to 65535 -j firewall_wan2lan_drop_log\n");
            fprintf(filter_fp, "-I FORWARD -p TCP -m string --string \"BitTorrent protocol\" --algo bm -j firewall_reject_log  \n");



		}

	         if(isMulticastBlocked) 
		{
			fprintf(filter_fp, "-I firewall_wan2lan -p 2 \
							-j firewall_wan2lan_drop_log\n"); // IGMP
			fprintf(filter_fp, "-I firewall_wan2lan -m iprange \
			--dst-range 224.0.0.0-239.255.255.255  -j firewall_wan2lan_drop_log\n");

		}

	        fprintf(filter_fp, "-A firewall_wan2lan  -j firewall_wan2lan_accept_log\n"); // ACCEPT ALL 
	        fprintf(filter_fp, "-A firewall_lan2self  -j firewall_lan2self_accept_log\n"); // ACCEPT ALL 
	        fprintf(filter_fp, "-A firewall_wan2self  -j firewall_wan2self_accept_log\n"); // ACCEPT ALL 
	        
      }
   return(0);
}


/*
 =================================================================
             Logging
 =================================================================
 */

/*
 *  Procedure     : do_logs
 *  Purpose       : prepare the iptables-restore statements with statements for logging
 *  Parameters    :
 *     filter_fp              : An open file that will be used for iptables-restore
 *                  protocol.
 *  Return Values :
 *     0               : done
 */

 int do_logs(FILE *filter_fp)
{
   char str[MAX_QUERY];

   /*
    * Aside from the general idea that logging is enabled,
    * we can turn on/off certain logs according to whether
    * they are security related, incoming, or outgoing
    */
   if (isLogEnabled) {
      if (isLogOutgoingEnabled) {
#ifdef LAN2WAN_LOG
            snprintf(str, sizeof(str),
            "-A firewall_lan2wan_accept_log  -j LOG --log-prefix \"RDKB-EMULATOR: FW.LAN2WAN ACCEPT \"\
	    --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit \
	    --limit 1/minute --limit-burst 1", syslog_level);
            fprintf(filter_fp, "%s\n", str);
            snprintf(str, sizeof(str),
            "-A firewall_lan2wan_drop_log  -j LOG --log-prefix \"RDKB-EMULATOR: FW.LAN2WAN DROP \" \
             --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit \
             --limit 1/minute --limit-burst 1", syslog_level);
            fprintf(filter_fp, "%s\n", str);
#endif
      }

      }

      if (isLogIncomingEnabled) {
         snprintf(str, sizeof(str),
         "-A firewall_wan2lan_accept_log  -j LOG --log-prefix \"RDKB-EMULATOR: FW.WAN2LAN ACCEPT \"\
         --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute\
         --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);

         snprintf(str, sizeof(str),
         "-A firewall_wan2self_accept_log -j LOG --log-prefix \"RDKB-EMULATOR: FW.WAN2LAN ACCEPT \"\
          --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute\
          --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);

         snprintf(str, sizeof(str),
         "-A firewall_wan2lan_drop_log  -j LOG --log-prefix \"RDKB-EMULATOR: FW.WAN2LAN DROP \" \
	 --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute\
	 --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);

         snprintf(str, sizeof(str),
         "-A firewall_wan2self_drop_log  -j LOG --log-prefix \"RDKB-EMULATOR: FW.WAN2LAN DROP \" \
	 --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute\
	 --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);
	 snprintf(str, sizeof(str),
         "-A firewall_drop_log  -j LOG --log-prefix \"RDKB-EMULATOR: FW.DROP \" --log-level %d \
	--log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute \
        --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);

         snprintf(str, sizeof(str),
         "-A firewall_reject_log -j LOG --log-prefix \"RDKB-EMULATOR: FW.REJECT \" --log-level %d \
         --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute\
         --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);
      }
      if (isLogSecurityEnabled) {

#ifdef LAN2WAN_LOG
         snprintf(str, sizeof(str),
         "-A firewall_lan2self_drop_log -m state --state NEW -j LOG --log-prefix \"RDKB-EMULATOR: FW.LAN2SELF DROP \"\
	  --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute \
          --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);

         snprintf(str, sizeof(str),
         "-A firewall_lan2wan_drop_log -j LOG --log-prefix \"RDKB-EMULATOR: FW.LAN2WAN DROP \" \
	 --log-level %d --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/minute\
	 --limit-burst 1", syslog_level);
         fprintf(filter_fp, "%s\n", str);
#endif
      }

   snprintf(str, sizeof(str), "-A firewall_lan2wan_accept_log -j ACCEPT");
   fprintf(filter_fp, "%s\n", str);

   snprintf(str, sizeof(str), "-A firewall_wan2lan_accept_log -j ACCEPT");
   fprintf(filter_fp, "%s\n", str);

   snprintf(str, sizeof(str), "-A firewall_lan2wan_drop_log -j DROP");
   fprintf(filter_fp, "%s\n", str);
   
   snprintf(str, sizeof(str), "-A firewall_wan2lan_drop_log -j DROP");
   fprintf(filter_fp, "%s\n", str);
 
   snprintf(str, sizeof(str), "-A firewall_lan2lan_accept_log -j ACCEPT");
   fprintf(filter_fp, "%s\n", str);

   snprintf(str, sizeof(str), "-A firewall_lan2lan_drop_log -j DROP");
   fprintf(filter_fp, "%s\n", str);


   snprintf(str, sizeof(str), "-A firewall_wan2self_accept_log -j ACCEPT");
   fprintf(filter_fp, "%s\n", str);
   
   snprintf(str, sizeof(str), "-A firewall_wan2self_drop_log -j DROP");
   fprintf(filter_fp, "%s\n", str);
  
   snprintf(str, sizeof(str), "-A firewall_lan2self_accept_log -j ACCEPT");
   fprintf(filter_fp, "%s\n", str);

   snprintf(str, sizeof(str), "-A firewall_lan2self_drop_log -j DROP");
   fprintf(filter_fp, "%s\n", str);

   snprintf(str, sizeof(str), "-A firewall_drop_log -j DROP");
   fprintf(filter_fp, "%s\n", str);

   snprintf(str, sizeof(str),"-A firewall_reject_log -p tcp -m tcp -j REJECT --reject-with tcp-reset ");
   fprintf(filter_fp, "%s\n", str);
   
   snprintf(str, sizeof(str), "-A firewall_reject_log -j DROP");
   fprintf(filter_fp, "%s\n", str);

   return(0);
}
/*
 ==========================================================================
                          XFINITY_WIFI(HotSpot)
 ==========================================================================
 */

/*
 *  Procedure     : Getting_Gre_DSCP_Val
 *  Purpose       : To read the DSCP(Differentiated service code point)value from PSM
 *     
 *  Parameters    : None
 *  Return_values : Integer Dscp value
 *  
 */


int Getting_Gre_DSCP_Val()
{
	char *param_value;
	int greDscp;
	char param_name[] = "dmsb.hotspot.tunnel.1.DSCPMarkPolicy";
	PSM_Get_Record_Value2(bus_handle,g_Subsystem, param_name, NULL, &param_value);
	greDscp = atoi(param_value);
	return greDscp;
}

/*
 *  Procedure     : xfinitywifi_InitialBootuprules_setup
 *  Purpose       : Mangle table Initial Boot up rules for xfinity-wifi,DSCP(Differentiated service code point) will decide the IP packets priority.
 *
 *  Parameters    : None
 *  Return_values : None
 *  Required Kernel Modules are xt_dscp.ko,xt_DSCP.ko,xt_connmark.ko,xt_tcpmss.ko,xt_TCPMSS.ko.
 */

void xfinitywifi_InitialBootuprules_setup()
{
        char str[512];
        int greDscp;
        greDscp = Getting_Gre_DSCP_Val();
	/* mangle */
        system("iptables -t mangle -A FORWARD -m state --state NEW -j DSCP --set-dscp-class af22");
        system("iptables -t mangle -A FORWARD -m state ! --state NEW -j DSCP  --set-dscp 0x0");
        system("iptables -t mangle -A OUTPUT -o eth0 -j DSCP --set-dscp-class af22");
        sprintf(str,"%s %d","iptables -t mangle -A POSTROUTING -o eth0 -p gre -j DSCP --set-dscp",greDscp);
        system(str);
        system("iptables -t mangle -I PREROUTING -i eth0 -m dscp --dscp-class af32 -j CONNMARK --set-mark 0xA");
        system("iptables -t mangle -I PREROUTING -i eth0 -m dscp --dscp-class cs1 -j CONNMARK --set-mark 0xB");
        system("iptables -t mangle -I PREROUTING -i eth0 -m dscp --dscp-class cs5 -j CONNMARK --set-mark 0xC");
        system("iptables -t mangle -I PREROUTING -i eth0 -m dscp --dscp-class af22 -j CONNMARK --set-mark 0xD");
        system("iptables -t mangle -A POSTROUTING -o eth0 -m connmark --mark 0xA  -j DSCP --set-dscp-class af32");
        system("iptables -t mangle -A POSTROUTING -o eth0 -m connmark --mark 0xB -j DSCP --set-dscp-class cs1");
        system("iptables -t mangle -A POSTROUTING -o eth0 -m connmark --mark 0xC -j DSCP --set-dscp-class cs5");
        system("iptables -t mangle -A POSTROUTING -o eth0 -m connmark --mark 0xD -j DSCP --set-dscp-class af22");
        system("iptables -t mangle -A POSTROUTING -o eth0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400");
        system("iptables -t mangle -A POSTROUTING -o eth0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400");
}

/*
==========================================================================
		CaptivePortal Redirection Rules
=========================================================================
*/
/*
 *  Procedure     : captiveportal_redirectionrules
 *  Purpose       : On fresh boot-up,captiveportal page should be bring up while browsing a any url in connected clients
 *
 *  Parameters    : None
 *  Return_values : None
 */

void captiveportal_redirectionrules()
{
        char *wifi = NULL, *captiveportal = NULL;
        PSM_Get_Record_Value2(bus_handle,g_Subsystem,"Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi", NULL, &wifi);
        PSM_Get_Record_Value2(bus_handle,g_Subsystem,"Device.DeviceInfo.X_RDKCENTRAL-COM_CaptivePortalEnable", NULL, &captiveportal);
        if((strcmp(wifi,"true") == 0 ) && (strcmp(captiveportal,"true") == 0))
        {
                if( access("/nvram/captivemode_enabled", F_OK ) != -1 )
                {
                        printf("CaptivePortal Mode was enabled \n");
                        if ( access("/nvram/updated_captiveportal_redirectionrules", F_OK ) != -1 )
                        {
                                printf(" Already updated the required rules for CaptivePortal Redirection \n");
                        }
                        else
                        {
                                system("iptables -t nat -I PREROUTING -i brlan0 -p udp --dport 53 -j DNAT --to 10.0.0.1");
                                system("iptables -t nat -I PREROUTING -i brlan0 -p tcp --dport 53 -j DNAT --to 10.0.0.1");
                                system("touch /nvram/updated_captiveportal_redirectionrules");
                        }
                }
                else
                {
                        printf("CaptivePortal Mode was disabled \n");
                        system("iptables -t nat -D PREROUTING -i brlan0 -p udp --dport 53 -j DNAT --to 10.0.0.1");
                        system("iptables -t nat -D PREROUTING -i brlan0 -p tcp --dport 53 -j DNAT --to 10.0.0.1");
                }
        }
}

/*
 ==========================================================================
              IPv4 Firewall 
 ==========================================================================
 */

/*
 *  Procedure     : prepare_subtables
 *  Purpose       : prepare the iptables-restore file that establishes all
 *                  ipv4 firewall rules with the table/subtable structure
 *  Parameters    :
 *    raw_filter_fp         : An open file for raw subtables
 *    mangle_filter_fp      : An open file for mangle subtables
 *    nat_filter_fp         : An open file for nat subtables
 *    filter_fp      : An open file for filter subtables
 * Return Values  :
 *    0              : Success
 */
static int prepare_subtables( FILE *filter_fp)
{
   int i; 
   /*
    * filter
    */
	fprintf(filter_fp, "*filter\n");
	fprintf(filter_fp, ":INPUT ACCEPT [0:0]\n");
	fprintf(filter_fp, ":FORWARD ACCEPT [0:0]\n");
	fprintf(filter_fp, ":OUTPUT ACCEPT [0:0]\n");
	fprintf(filter_fp, ":firewall_lan2lan - [0:0]\n");
	fprintf(filter_fp, ":firewall_lan2wan - [0:0]\n");
	fprintf(filter_fp, ":firewall_wan2lan - [0:0]\n");	
	fprintf(filter_fp,":firewall_wan2self - [0:0]\n");
	fprintf(filter_fp,":firewall_lan2self - [0:0]\n");
	fprintf(filter_fp,":firewall_drop     - [0:0]\n");
	fprintf(filter_fp,":firewall_lan2self_accept_log - [0:0]\n");   
	fprintf(filter_fp, ":firewall_lan2lan_accept_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_lan2lan_drop_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_lan2wan_accept_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_lan2wan_drop_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_wan2lan_accept_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_wan2lan_drop_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_wan2self_accept_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_wan2self_drop_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_lan2self_drop_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_drop_log - [0:0]\n");
	fprintf(filter_fp, ":firewall_reject_log - [0:0]\n");
	fprintf(filter_fp, ":lan2wan_triggers - [0:0]\n");
	fprintf(filter_fp, ":wan2lan_trigger - [0:0]\n");
	fprintf(filter_fp, ":xlog_accept_lan2wan_triggers - [0:0]\n");
	fprintf(filter_fp, ":xlog_accept_wan2lan_triggers - [0:0]\n");
	fprintf(filter_fp, ":RemoteManagement - [0:0]\n");
	fprintf(filter_fp, ":remote_accept_wan2self - [0:0]\n");
	fprintf(filter_fp, ":remote_wan2lan_accept_log - [0:0]\n");
	fprintf(filter_fp, ":remote_wan2lan_drop_log - [0:0]\n");
	fprintf(filter_fp, ":general_forward - [0:0]\n");
        fprintf(filter_fp, ":general_output - [0:0]\n");
	xfinitywifi_InitialBootuprules_setup();
   return(0);
}

/*
 *  Procedure     : prepare_enabled_ipv4
 *  Purpose       : prepare ipv4 firewall
 *  Parameters    :
 *   raw_filter_fp         : An open file for raw subtables
 *   mangle_filter_fp      : an open file for writing mangle statements
 *   nat_filter_fp         : an open file for writing nat statements
 *   filter_fp      : an open file for writing filter statements
 */
int prepare_enabled_ipv4( FILE *filter_fp,struct NetworkDetails *netDetails)
{
   /*
    * Add all of the tables and subtables that are required for the firewall
    */
   prepare_subtables(filter_fp);
   do_nonat(filter_fp,netDetails);
   do_logs(filter_fp);
   return(0);
}

#if  1
int prepare_ipv4(const char *fw_file,struct NetworkDetails *netDetails)
{

   /*
    * fw_file is the name of the file that we write firewall statement to.
    * This file is used by iptables-restore to provision the firewall.
    */

   if (NULL == fw_file) {
      return(-1);
   }

  FILE *fp = fopen(fw_file, "w");
   if (NULL == fp) {
      return(-2);
   }


  /*
   * We use 4 files to store the intermediary firewall statements.
   * One file is for raw, another is for mangle, another is for 
   * nat tables statements, and the other is for filter statements.
   */
  
   pid_t ourpid = getpid();
   char  fname[50];
   char  mname[50];
   char  command[100];

   snprintf(fname, sizeof(fname), "/tmp/filter_%x", ourpid);
   FILE *filter_fp = fopen(fname, "w+");
   if (NULL == filter_fp) {
      return(-2);
   }
  
   if (isFirewallEnabled ) {
      prepare_enabled_ipv4(filter_fp,netDetails);
   } else {
      prepare_disabled_ipv4(filter_fp);
   }
   //printf("======================= Rewindinf Filter_filter_fp\n");
   
   rewind(filter_fp);
   char string[MAX_QUERY];
   char *strp;
   while (NULL != (strp = fgets(string, MAX_QUERY, filter_fp)) ) {
      printf("%s\n",string);	
      fprintf(fp, "%s", string);
   }
   fclose(filter_fp);
   unlink(fname);

   snprintf(command,sizeof(command),"iptables-save -t filter > /tmp/filter\n");
   system(command);
   snprintf(mname, sizeof(mname), "/tmp/temp");
   system("sed -n '/0:0/!p' /tmp/filter > /tmp/temp");
   system("sed -n '/accept_log/!p' /tmp/temp > /tmp/temp1");
   system("sed -n '/firewall/!p' /tmp/temp1 > /tmp/temp2");
   system("sed -n '/filter/!p' /tmp/temp2 > /tmp/temp");
   system("sed -n '/:INPUT ACCEPT /!p' /tmp/temp > /tmp/temp1");
   system("sed -n '/:OUTPUT ACCEPT /!p' /tmp/temp1 > /tmp/temp2");
   system("sed -n '/:FORWARD ACCEPT /!p' /tmp/temp2 > /tmp/temp");
   filter_fp = fopen(mname, "r+");
   while (NULL != (strp = fgets(string, MAX_QUERY, filter_fp)) ) {
      printf("%s\n",string);	
      fprintf(fp, "%s", string);
   }
   fclose(filter_fp);
   unlink(mname);
   system("rm /tmp/filter");
   system("rm /tmp/temp1");
   system("rm /tmp/temp2");
   system("rm /tmp/temp");
//   fprintf(fp, "%s\n", "COMMIT");
   fclose(fp);
   return(0);
}
#endif
int i=0;
/*
 *  Procedure     : prepare_disable_ipv4
 *  Purpose       : prepare ipv4 firewall to stop all services (firewall, nat, qos) 
 *                  irrespective of their configuration
 *  Parameters    :
 *   file_filter_fp         : an open file for writing iptables statements
 */
int prepare_disabled_ipv4()
{

   /*
    * filter
    */
   char command[100];

   system("iptables-save -t filter  > /tmp/.ipt_filter");
   system("sed -n '/firewall/!p' /tmp/.ipt_filter > /tmp/.ipt_firewall_disable");
   system("sed -n '/accept_log/!p' /tmp/.ipt_firewall_disable > /tmp/.ipt_filter");
   system("iptables-restore  < /tmp/.ipt_filter");
   system("rm /tmp/.ipt_filter");
   system("iptables -N accept_log");
   system("iptables -I FORWARD -i brlan0 -o eth0  -m state --state RELATED,ESTABLISHED  -j accept_log");
   system("iptables -I FORWARD -i eth0 -o brlan0  -j accept_log");
   system("iptables -I accept_log -j ACCEPT");
   system("iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE");
   system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE");
}

/*
 * Name           :  firewall_service_init
 * Purpose        :  Initialize resources & retrieve configurations
 *                   required for firewall service
 * Parameters     :
 *    argc        :  Count of arguments (excludes event-name)
 *    argv        :  Array of arguments 
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
int firewall_service_init (struct custom_option *option)
{
   int rc = 0;
   int ret = 0;

   //printf("%s service initializing", firewall_service_name);

   isCronRestartNeeded     = 0;


   int too_much = 10;
   prepare_globals_from_configuration(option);
ret_err:
   return rc;
}

/*
 * Name           :  firewall_service_close
 * Purpose        :  Close resources initialized for firewall service
 * Parameters     :
 *    None        :
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
int firewall_service_close ()
{
   if (0 <= lock_fd) {
       close(lock_fd);
       unlink("/tmp/firewall_lock");
      //printf( "firewall closing firewall_lock");
   }
   //printf("firewall operation completed");

   return 0;
}

/*
 * Name           :  firewall_service_start
 * Purpose        :  Start firewall service (including nat & qos)
 * Parameters     :
 *    None        :
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
int firewall_service_start (char *level,struct NetworkDetails *netDetails)
{
   char *filename1 = "/tmp/.ipt";
   isFirewallEnabled =1;  
   strcpy(firewall_level,level);
   //printf("------------------  Firewall Level %s	%s\n",firewall_level,level); 

   /*  ipv4 */
   prepare_ipv4(filename1,netDetails);
   system("iptables-restore   < /tmp/.ipt");

#if 0
   if (!isCronRestartNeeded) {
      unlink(cron_file);
   }

   if(ppFlushNeeded == 1) {
       system("echo flush_all_sessions > /proc/net/ti_pp");
   }
#endif
   printf("started %s service", firewall_service_name);
   system("rm /tmp/.ipt");
   return 0;
}

/*
 * Name           :  firewall_service_stop
 * Purpose        :  Stop firewall service (including nat & qos)
 * Parameters     :  None
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
int firewall_service_stop (char *level)
{
   //printf( "stopping %s service", firewall_service_name);
   prepare_disabled_ipv4();
   //printf("stopped %s service", firewall_service_name);
   return 0;
}

/*
 * Name           :  firewall_service_restart
 * Purpose        :  Restart the firewall service
 * Parameters     :  None
 * Return Values  :
 *    0              : Success
 *    < 0            : Error code
 */
int firewall_service_restart (char *firewall_level,struct NetworkDetails *netDetails)
{
	return firewall_service_start(firewall_level,netDetails);
}

/***************************************************************************************************************
				ADVANCED CONFIGURATION FEATURES IMPLEMENTATION
*****************************************************************************************************************/
/**************************** REMOTE MANAGEMENT IMPLEMENTATION *****************************/

/**************************************************************
Getting Httpport and Httpsport value from lighttpd webserver
***************************************************************/

int GetHttpPortValue(ULONG value)
{
        char path[1024];
        FILE *fp = NULL;
        fp = popen("cat /etc/lighttpd.conf | grep  SERVER | cut -d ':' -f2","r");
        if(fp == NULL)
        {
                printf("\n function failed");
                return;
        }
        fgets(path,sizeof(path),fp);
        fgets(path,sizeof(path),fp);
        value = (unsigned long)atol(path);
        pclose(fp);
        return value;

}
int GetHttpsPortValue(ULONG value)
{
        char httpsportvalue[50];
        char *httpsport;
        char path[1024];
        FILE *fp = NULL;
        fp = popen("cat /etc/lighttpd.conf | grep -E SERVER ", "r");
        if (fp == NULL) {
                printf("Failed to run command in function %s\n",__FUNCTION__);
                return;
        }
        fgets(path, sizeof(path)-1, fp);
        httpsport = strchr(path,':');
        strcpy(httpsportvalue,httpsport+1);
        value = (unsigned long)atol(httpsportvalue);
        pclose(fp);
        return value;
}

/****************************************************************
Logging set up for Remote Management
******************************************************************/
int Wan2lan_log_deletion_setup(struct NetworkDetails *netDetails)
{
	char wan_netmask[16]="";
        char wan_ipaddr[16]="";
        char str[300];
        sprintf(wan_ipaddr, "%d.%d.%d.%d\0", (netDetails->WanIPAddress).Dot[0],\
              (netDetails->WanIPAddress).Dot[1], (netDetails->WanIPAddress).Dot[2],\
              (netDetails->WanIPAddress).Dot[3] );
        sprintf(wan_netmask, "%d.%d.%d.%d\0", (netDetails->WanSubnetMask).Dot[0],\
              (netDetails->WanSubnetMask).Dot[1], (netDetails->WanSubnetMask).Dot[2],\
              (netDetails->WanSubnetMask).Dot[3] );
        snprintf(str, sizeof(str), "iptables -D INPUT   -s 0/0 -d %s/%s -j remote_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
        system(str);
        snprintf(str, sizeof(str), "iptables -D FORWARD  -s %s/%s -d 0/0 -j remote_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
        system(str);
        snprintf(str, sizeof(str), "iptables -D OUTPUT   -s %s/%s -d 0/0 -j remote_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
        system(str);
	return 0;
}

int Wan2lan_log_insertion_setup(struct NetworkDetails *netDetails)
{
	char wan_netmask[16]="";
        char wan_ipaddr[16]="";
	char str[300];	
	sprintf(wan_ipaddr, "%d.%d.%d.%d\0", (netDetails->WanIPAddress).Dot[0],\
              (netDetails->WanIPAddress).Dot[1], (netDetails->WanIPAddress).Dot[2],\
              (netDetails->WanIPAddress).Dot[3] );
        sprintf(wan_netmask, "%d.%d.%d.%d\0", (netDetails->WanSubnetMask).Dot[0],\
              (netDetails->WanSubnetMask).Dot[1], (netDetails->WanSubnetMask).Dot[2],\
              (netDetails->WanSubnetMask).Dot[3] );
	snprintf(str, sizeof(str), "iptables -A INPUT   -s 0/0 -d %s/%s -j remote_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
        system(str);
	snprintf(str, sizeof(str), "iptables -A FORWARD  -s %s/%s -d 0/0 -j remote_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
        system(str);
	snprintf(str, sizeof(str), "iptables -A OUTPUT   -s %s/%s -d 0/0 -j remote_wan2lan_accept_log\n",wan_ipaddr,wan_netmask);
        system(str);
	
	return 0;
}

int GettingWanIP_remotemgmt_deletion_logsetup()
{
	struct NetworkDetails netDetails;
        uint32_t ip_integer;
        uint32_t  netmask;
	ip_integer = CosaUtilGetIfAddr(UPLINK_IF_NAME);
        netmask=CosaUtilIoctlXXX(UPLINK_IF_NAME,"netmask",NULL);
        *(uint32_t *)(netDetails.WanIPAddress).Dot =ip_integer;
        *(uint32_t *)(netDetails.WanSubnetMask).Dot =netmask;
	Wan2lan_log_deletion_setup(&netDetails);
	return 0;
}
int GettingWanIP_remotemgmt_insertion_logsetup()
{
	struct NetworkDetails netDetails;
        uint32_t ip_integer;
        uint32_t  netmask;
        ip_integer = CosaUtilGetIfAddr(UPLINK_IF_NAME);
        netmask=CosaUtilIoctlXXX(UPLINK_IF_NAME,"netmask",NULL);
        *(uint32_t *)(netDetails.WanIPAddress).Dot =ip_integer;
        *(uint32_t *)(netDetails.WanSubnetMask).Dot =netmask;
        Wan2lan_log_insertion_setup(&netDetails);
	return 0;
}
/**************************************************************
Creation and Deletion of Remote Management Iptables Rule Mapping
****************************************************************/
int DeleteRemoteManagementIptablesRules()
{
        system("iptables -F RemoteManagement");
        system("iptables -F remote_accept_wan2self");
	system("iptables -F remote_wan2lan_accept_log");
	system("iptables -F remote_wan2lan_drop_log");
        system("iptables -D INPUT -j RemoteManagement");
        system("iptables -D OUTPUT -j RemoteManagement");
        system("iptables -D FORWARD -j RemoteManagement");
	GettingWanIP_remotemgmt_deletion_logsetup();
        system("iptables -X RemoteManagement");
        system("iptables -X remote_accept_wan2self");
	system("iptables -X remote_wan2lan_accept_log");
	system("iptables -X remote_wan2lan_drop_log");
	InitialRule = true;
        return 0;
}
int AddRemoteManagementIptablesRules()
{
        system("iptables -N RemoteManagement");
        system("iptables -N remote_accept_wan2self");
	system("iptables -N remote_wan2lan_accept_log");
	system("iptables -N remote_wan2lan_drop_log");
	system("iptables -I INPUT -j RemoteManagement");
	system("iptables -I OUTPUT -j RemoteManagement");
	system("iptables -I FORWARD -j RemoteManagement");
        system("iptables -A remote_accept_wan2self -j ACCEPT");
	system("iptables  -A remote_wan2lan_accept_log  -j LOG --log-prefix \"RDKB-EMULATOR: RM.WAN2LAN ACCEPT\" \
         --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/s --limit-burst 3");
	system("iptables -A remote_wan2lan_accept_log -j ACCEPT");
	system("iptables -A remote_wan2lan_drop_log  -j LOG --log-prefix \"RDKB-EMULATOR: RM.WAN2LAN DROP\" --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/s --limit-burst 3");
	system("iptables -A remote_wan2lan_drop_log -j DROP");
	GettingWanIP_remotemgmt_insertion_logsetup();
        return 0;
}
/****************************************************************
Enabling and Disabling of Http and Https Port in lighttpd webserver
******************************************************************/
int DisablingHttps()
{
        char buf[200],str[100];
        unsigned long value,httpsport;
        httpsport = GetHttpsPortValue(value);
        sprintf(str,"%s%lu","0.0.0.0:",httpsport);
        sprintf(buf,"%s%c%c%s%s%s%c %s","sed -i ",'"','/',str,"/ s/^/","#/",'"',"/etc/lighttpd.conf");
        system(buf);
        sprintf(str,"%s","ssl.engine");
        sprintf(buf,"%s%c%c%s%s%s%c %s","sed -i ",'"','/',str,"/ s/^/","#/",'"',"/etc/lighttpd.conf");
        system(buf);
        sprintf(str,"%s","ssl.pemfile");
        sprintf(buf,"%s%c%c%s%s%s%c %s","sed -i ",'"','/',str,"/ s/^/","#/",'"',"/etc/lighttpd.conf");
        system(buf);
        return 0;
}
int EnablingHttps()
{
        char buf[200],str[100];
        unsigned long value,httpsport;
        httpsport = GetHttpsPortValue(value);
        sprintf(str,"%s%lu","0.0.0.0:",httpsport);
        sprintf(buf,"%s%c%c%s%s%c %s","sed -i ",'"','/',str,"/ s/^#*//",'"',"/etc/lighttpd.conf");
        system(buf);
        sprintf(str,"%s","ssl.engine");
        sprintf(buf,"%s%c%c%s%s%c %s","sed -i ",'"','/',str,"/ s/^#*//",'"',"/etc/lighttpd.conf");
        system(buf);
        sprintf(str,"%s","ssl.pemfile");
        sprintf(buf,"%s%c%c%s%s%c %s","sed -i ",'"','/',str,"/ s/^#*//",'"',"/etc/lighttpd.conf");
        system(buf);
        return 0;
}

int EnablingHttp()
{
        char buf[200],str[100];
        unsigned long hport,hports;
        hport = GetHttpPortValue(hports);
        sprintf(str,"%c%c%lu%c",'"',':',hport,'"');
        sprintf(buf,"%s%c%c%s%s%c %s","sed -i ",'"','/',str,"/ s/^#*//",'"',"/etc/lighttpd.conf");
        system(buf);
        return 0;
}
int DisablingHttp()
{
        char buf[200],str[100];
        unsigned long hport,hports;
        hport = GetHttpPortValue(hports);
        sprintf(str,"%c%c%lu%c",'"',':',hport,'"');
        sprintf(buf,"%s%c%c%s%s%s%c %s","sed -i ",'"','/',str,"/ s/^/","#/",'"',"/etc/lighttpd.conf");
        system(buf);
        return 0;
}
/**********************************************************
Setting new Http and Https port values to lighttpd Webserver
************************************************************/
int SetHttpPort(unsigned long htttpport)
{
        char str[250],str1[250],buf[250];
        char path[1024];
        char httpportvalue[50];
        FILE *fp = NULL;
        unsigned long httpport;
        fp = popen("cat /etc/lighttpd.conf | grep  SERVER | cut -d ':' -f2","r");
        if(fp == NULL)
        {
                printf("\n function failed");
                return;
        }
        fgets(path,sizeof(path),fp);
        fgets(path,sizeof(path),fp);
        httpport = atol(path);
        sprintf(str,"%c%c%lu%c",'"',':',httpport,'"');
        sprintf(str1,"%c%c%lu%c",'"',':',htttpport,'"');
        sprintf(buf,"%s%s%s%s%s%s","sed -i -e 's/",str,"/",str1,"/g'", " /etc/lighttpd.conf");
        system(buf);
        pclose(fp);
        return 0;
}

int SetHttpsPort(unsigned long httpssport)
{

        char str[250],str1[250],buf[250];
        unsigned long hport;
        char path[1024];
        char httpsportvalue[50];
        FILE *fp = NULL;
        char *httpsport;
        fp = popen("cat /etc/lighttpd.conf | grep -E SERVER ", "r");
        if (fp == NULL) {
                printf("Failed to run command in function %s\n",__FUNCTION__);
                return;
        }
        fgets(path, sizeof(path)-1, fp);
        httpsport = strchr(path,':');
        strcpy(httpsportvalue,httpsport+1);
        hport = (unsigned long)atol(httpsportvalue);
        sprintf(str,"%s%lu","0.0.0.0:",hport);
        sprintf(str1,"%s%lu","0.0.0.0:",httpssport);
        sprintf(buf,"%s%s%s%s%s%s","sed -i -e 's/",str,"/",str1,"/g'", " /etc/lighttpd.conf");
        system(buf);
        pclose(fp);
        return 0;
}
/*********************************************************************
Remote Management Operation
**********************************************************************/

int RemoteManagementiptableRulessetoperation(PCOSA_DML_RA_CFG pCfg)
{
        char buf[1024];
	ULONG value;
        if(GetHttpPortValue(value) != pCfg->HttpPort)
	SetHttpPort(pCfg->HttpPort);
	if(GetHttpsPortValue(value) != pCfg->HttpsPort)
	SetHttpsPort(pCfg->HttpsPort);	
	if(InitialRule == true)
        {
        AddRemoteManagementIptablesRules();
        InitialRule = false;
        }
        else
        system("iptables -F RemoteManagement");
        if(pCfg->bFromAnyIp == true)//select any computer
        {
        	  system("iptables -F RemoteManagement");
        if((pCfg->HttpEnable == true) && (pCfg->HttpsEnable == false))
        {
        DisablingHttps();
        EnablingHttp();
        sprintf(buf,"%s %lu %s","iptables -A RemoteManagement -p tcp --dport",pCfg->HttpPort,"-j remote_accept_wan2self");
        system(buf);
        }
        else if((pCfg->HttpEnable == false) && (pCfg->HttpsEnable == true))
        {
        EnablingHttps();
        DisablingHttp();
        sprintf(buf,"%s %lu %s","iptables -A RemoteManagement -p tcp --dport",pCfg->HttpsPort,"-j remote_accept_wan2self");
        system(buf);
        }
        else if((pCfg->HttpEnable == true) && (pCfg->HttpsEnable == true))
        {
        EnablingHttp();
        EnablingHttps();
        sprintf(buf,"%s %lu,%lu %s","iptables -A RemoteManagement -p tcp -m multiport --dport",pCfg->HttpPort,pCfg->HttpsPort,"-j remote_accept_wan2self");
        system(buf);
        }
        else if((pCfg->HttpEnable == false) && (pCfg->HttpsEnable == false))
	{
        DisablingHttp();
        DisablingHttps();
        DeleteRemoteManagementIptablesRules();
	}
        }
	else
        {
        if((pCfg->HttpEnable == true) && (pCfg->HttpsEnable == false))
        {
        DisablingHttps();
        EnablingHttp();
        if(pCfg->StartIp.Value == pCfg->EndIp.Value)//select single IP address
        {
        struct in_addr ip_addr;
        ip_addr.s_addr = pCfg->StartIp.Value;
	sprintf(buf,"%s %lu %s %s %s","iptables -I RemoteManagement -p tcp --dport",pCfg->HttpPort,"! -s",inet_ntoa(ip_addr),"-j remote_wan2lan_drop_log");
	system(buf);
        }
        else
        {
        char start_buf[100];
        char dest_buf[100];
        struct in_addr start_addr;
        struct in_addr end_addr;
        start_addr.s_addr = pCfg->StartIp.Value;
        end_addr.s_addr = pCfg->EndIp.Value;
        inet_ntop(AF_INET, &start_addr, start_buf, sizeof start_buf);
        inet_ntop(AF_INET, &end_addr, dest_buf, sizeof dest_buf);
        sprintf(buf,"%s %lu %s %s%s%s %s","iptables -A  RemoteManagement -p tcp --dport",pCfg->HttpPort, "-m iprange ! --src-range",start_buf,"-",dest_buf,"-j remote_wan2lan_drop_log");
        system(buf);
        }
        }
        else if((pCfg->HttpEnable == false) && (pCfg->HttpsEnable == true))
        {
        EnablingHttps();
        DisablingHttp();
        if(pCfg->StartIp.Value == pCfg->EndIp.Value)
        {
        struct in_addr ip_addr;
        ip_addr.s_addr = pCfg->StartIp.Value;
        sprintf(buf,"%s %lu %s %s %s","iptables -A  RemoteManagement -p tcp --dport",pCfg->HttpsPort," ! -s",inet_ntoa(ip_addr),"-j remote_wan2lan_drop_log");
	system(buf);
        }
        else
        {
        char start_buf[100];
        char dest_buf[100];
        struct in_addr start_addr;
        struct in_addr end_addr;
        start_addr.s_addr = pCfg->StartIp.Value;
        end_addr.s_addr = pCfg->EndIp.Value;
        inet_ntop(AF_INET, &start_addr, start_buf, sizeof start_buf);
        inet_ntop(AF_INET, &end_addr, dest_buf, sizeof dest_buf);
        sprintf(buf,"%s %lu %s %s%s%s %s","iptables -A  RemoteManagement -p tcp --dport",pCfg->HttpsPort, "-m iprange ! --src-range",start_buf,"-",dest_buf,"-j remote_wan2lan_drop_log");
        system(buf);
        }
        }
        else if((pCfg->HttpEnable == true) && (pCfg->HttpsEnable == true))
        {
        EnablingHttps();
        EnablingHttp();
        if(pCfg->StartIp.Value == pCfg->EndIp.Value)
        {
        struct in_addr ip_addr;
        ip_addr.s_addr = pCfg->StartIp.Value;
        sprintf(buf,"%s %lu,%lu %s %s %s","iptables -A  RemoteManagement -p tcp -m multiport --dport",pCfg->HttpPort,pCfg->HttpsPort,"! -s",inet_ntoa(ip_addr),"-j remote_wan2lan_drop_log");
	system(buf);
        }
        else
        {
        char start_buf[100];
        char dest_buf[100];
        struct in_addr start_addr;
        struct in_addr end_addr;
        start_addr.s_addr = pCfg->StartIp.Value;
        end_addr.s_addr = pCfg->EndIp.Value;
        inet_ntop(AF_INET, &start_addr, start_buf, sizeof start_buf);
        inet_ntop(AF_INET, &end_addr, dest_buf, sizeof dest_buf);
sprintf(buf,"%s %lu,%lu %s %s%s%s %s","iptables -A  RemoteManagement -p tcp -m multiport --dport",pCfg->HttpPort,pCfg->HttpsPort, "-m iprange ! --src-range",start_buf,"-",dest_buf,"-j remote_wan2lan_drop_log");
        system(buf);
        }
        }
        else if((pCfg->HttpEnable == false) && (pCfg->HttpsEnable == false))
        {
        DisablingHttps();
        DisablingHttp();
        DeleteRemoteManagementIptablesRules();
        }
        }
        return 0;
}

/********************** ROUTING CONNECTION WAN2LAN SET UP *****************/
int BasicRouting_Wan2Lan_SetupConnection()
{
	char str[1024] = {0};
	char lan_netmask[16]="";
        char lan_ipaddr[16]="";
	char wan_netmask[16]="";
        char wan_ipaddr[16]="";
	struct NetworkDetails netDetails;
        uint32_t wanip;
        uint32_t  lanip;
        uint32_t  netmask,w_netmask;
        lanip = CosaUtilGetIfAddr(UPLINKBR_IF_NAME);
        netmask=CosaUtilIoctlXXX(UPLINKBR_IF_NAME,"netmask",NULL);
        *(uint32_t *)(netDetails.LanIPAddress).Dot = lanip;
        *(uint32_t *)(netDetails.LanSubnetMask).Dot = netmask;
	sprintf(lan_ipaddr, "%d.%d.%d.%d\0", (netDetails.LanIPAddress).Dot[0],\
              (netDetails.LanIPAddress).Dot[1], (netDetails.LanIPAddress).Dot[2],\
              (netDetails.LanIPAddress).Dot[3] );
        sprintf(lan_netmask, "%d.%d.%d.%d\0", (netDetails.LanSubnetMask).Dot[0],\
              (netDetails.LanSubnetMask).Dot[1],(netDetails.LanSubnetMask).Dot[2],\
              (netDetails.LanSubnetMask).Dot[3]);

        wanip = CosaUtilGetIfAddr(UPLINK_IF_NAME);
        w_netmask = CosaUtilIoctlXXX(UPLINK_IF_NAME,"netmask",NULL);
	*(uint32_t *)(netDetails.WanIPAddress).Dot = wanip;
        *(uint32_t *)(netDetails.WanSubnetMask).Dot = w_netmask;
	sprintf(wan_ipaddr, "%d.%d.%d.%d\0", (netDetails.WanIPAddress).Dot[0],\
              (netDetails.WanIPAddress).Dot[1], (netDetails.WanIPAddress).Dot[2],\
              (netDetails.WanIPAddress).Dot[3] );
        sprintf(wan_netmask, "%d.%d.%d.%d\0", (netDetails.WanSubnetMask).Dot[0],\
              (netDetails.WanSubnetMask).Dot[1], (netDetails.WanSubnetMask).Dot[2],\
              (netDetails.WanSubnetMask).Dot[3] );

        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE");
        system("iptables -A FORWARD -i eth0 -o brlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
        system("iptables -A FORWARD -i brlan0 -o eth0 -j ACCEPT");
	system("iptables -t nat -N prerouting_redirect");
	system("iptables -t nat -A prerouting_redirect -p tcp --dport 80 -j DNAT --to-destination 0.0.0.0:21515");
	system("iptables -t nat -A prerouting_redirect -p tcp --dport 443 -j DNAT --to-destination 0.0.0.0:21515");
	system("iptables -t nat -A prerouting_redirect -p tcp  -j DNAT --to-destination 0.0.0.0:21515");
	system("iptables -t nat -A prerouting_redirect -p udp ! --dport 53 -j DNAT --to-destination 0.0.0.0:21515");
	captiveportal_redirectionrules();
	system("iptables -t nat -N prerouting_mgmt_override");
	system("iptables -t nat -I PREROUTING 1 -j prerouting_mgmt_override");
	system("iptables -t nat -F prerouting_mgmt_override");
	sprintf(str,"%s%s%s%s%s%s%s","iptables -t nat -I prerouting_mgmt_override -s ",lan_ipaddr,"/",lan_netmask," -d ",lan_ipaddr," -p tcp --dport 80 -j ACCEPT");
	system(str);
	sprintf(str,"%s%s%s%s%s%s%s","iptables -t nat -A prerouting_mgmt_override -s ",wan_ipaddr,"/",wan_netmask," -d ",wan_ipaddr," -j ACCEPT");
	system(str);
        return 0;
}

/***********************************  DMZ IMPLEMENTATION **********************/

/**************************************************************
Logging set up for DMZ Iptables Rule Mapping
***************************************************************/
         
int Lan2Wan_insertion_logsetup(struct NetworkDetails *netDetails)
{
	char lan_netmask[16]="";
        char lan_ipaddr[16]="";
	char str[500];
	 sprintf(lan_ipaddr, "%d.%d.%d.%d\0", (netDetails->LanIPAddress).Dot[0],\
              (netDetails->LanIPAddress).Dot[1], (netDetails->LanIPAddress).Dot[2],\
              (netDetails->LanIPAddress).Dot[3] );
        sprintf(lan_netmask, "%d.%d.%d.%d\0", (netDetails->LanSubnetMask).Dot[0],\
              (netDetails->LanSubnetMask).Dot[1],(netDetails->LanSubnetMask).Dot[2],\
              (netDetails->LanSubnetMask).Dot[3]);
	snprintf(str, sizeof(str), "iptables -t nat -A PREROUTING -s 0/0 -d %s/%s -j dmz_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
	system(str);
	snprintf(str, sizeof(str), "iptables -t nat -A INPUT -s %s/%s -d 0/0 -j dmz_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
	system(str);
	snprintf(str, sizeof(str), "iptables -t nat -A OUTPUT -s %s/%s -d 0/0 -j dmz_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
	system(str);
	return 0;
}

int Lan2Wan_Deletion_logsetup(struct NetworkDetails *netDetails)
{
	char lan_netmask[16]="";
        char lan_ipaddr[16]="";
	char str[500];
	 sprintf(lan_ipaddr, "%d.%d.%d.%d\0", (netDetails->LanIPAddress).Dot[0],\
              (netDetails->LanIPAddress).Dot[1], (netDetails->LanIPAddress).Dot[2],\
              (netDetails->LanIPAddress).Dot[3] );
        sprintf(lan_netmask, "%d.%d.%d.%d\0", (netDetails->LanSubnetMask).Dot[0],\
              (netDetails->LanSubnetMask).Dot[1],(netDetails->LanSubnetMask).Dot[2],\
              (netDetails->LanSubnetMask).Dot[3]);
	snprintf(str, sizeof(str), "iptables -t nat -D PREROUTING -s 0/0 -d %s/%s -j dmz_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
	system(str);
	snprintf(str, sizeof(str), "iptables -t nat -D INPUT -s %s/%s -d 0/0 -j dmz_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
	system(str);
	snprintf(str, sizeof(str), "iptables -t nat -D OUTPUT -s %s/%s -d 0/0 -j dmz_lan2wan_accept_log\n",lan_ipaddr,lan_netmask);
	system(str);
	return 0;
}

int GettingLanIP_Insertion_logsetup()
{
	struct NetworkDetails netDetails;
    	uint32_t ip_integer;
    	uint32_t  netmask;
	ip_integer = CosaUtilGetIfAddr(UPLINKBR_IF_NAME);
    	netmask=CosaUtilIoctlXXX(UPLINKBR_IF_NAME,"netmask",NULL);
    	*(uint32_t *)(netDetails.LanIPAddress).Dot = ip_integer;
    	*(uint32_t *)(netDetails.LanSubnetMask).Dot = netmask;
	Lan2Wan_insertion_logsetup(&netDetails);
	return 0;
}
int GettingLanIP_Deletion_logsetup()
{
	struct NetworkDetails netDetails;
        uint32_t ip_integer;
        uint32_t  netmask;
        ip_integer = CosaUtilGetIfAddr(UPLINKBR_IF_NAME);
        netmask=CosaUtilIoctlXXX(UPLINKBR_IF_NAME,"netmask",NULL);
        *(uint32_t *)(netDetails.LanIPAddress).Dot = ip_integer;
        *(uint32_t *)(netDetails.LanSubnetMask).Dot = netmask;
        Lan2Wan_Deletion_logsetup(&netDetails);
	return 0;
}
/******************************************************************
Creation and Deletion of DMZ Iptables Rule Mapping
*******************************************************************/
int DeleteDMZIptableRules(){
        system("iptables -t nat -F prerouting_fromwan_todmz");
	system("iptables -t nat -D PREROUTING -j prerouting_fromwan_todmz");
	system("iptables -t nat -F dmz_lan2wan_accept_log");
	GettingLanIP_Deletion_logsetup();
	system("iptables -t nat -X prerouting_fromwan_todmz");
	system("iptables -t nat -X dmz_lan2wan_accept_log");
	InitialRuleSet = true;
        return 0;
}

int  AddDMZIptableRules() {
	system("iptables -t nat -N prerouting_fromwan_todmz");
        system("iptables -t nat -I PREROUTING -j prerouting_fromwan_todmz");
	system("iptables -t nat -N dmz_lan2wan_accept_log");
	system("iptables -t nat -A dmz_lan2wan_accept_log -j LOG --log-prefix \"RDKB-EMULATOR: DMZ.LAN2WAN ACCEPT\" --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 1/s --limit-burst 2");
	system("iptables -t nat -A dmz_lan2wan_accept_log -j ACCEPT");
	GettingLanIP_Insertion_logsetup();
	return 0;
}

/******************************************************************
		DMZ Operation
*******************************************************************/

int DMZIptableRulesOperation(char dmzclientip[40])
{
        char buf[500];
        uint32_t ip_integer;
        char str[INET_ADDRSTRLEN];
	if(InitialRuleSet == true)
        {
        AddDMZIptableRules();
        InitialRuleSet = false;
        }
        else
        system("iptables -t nat -F prerouting_fromwan_todmz");
        ip_integer=CosaUtilGetIfAddr(UPLINK_IF_NAME);
        inet_ntop(AF_INET, &(ip_integer), str, INET_ADDRSTRLEN);
        sprintf(buf,"%s %s %s %s","iptables -t nat -A prerouting_fromwan_todmz -p tcp --dst", str,"-j DNAT --to-destination",dmzclientip);
        system(buf);
        sprintf(buf,"%s %s %s %s","iptables -t nat -A prerouting_fromwan_todmz -p udp --dst", str,"-j DNAT --to-destination",dmzclientip);
        system(buf);

        return 0;
}

	/***********************************  PORTFORWARDING IMPLEMENTATION **********************/

int port_forwarding_add_rule(UCHAR InternalClient[IPV4_ADDRESS_SIZE],char *prot,USHORT ExternalPort,USHORT ExternalPortEndRange)
{
        char cmd[1024]= {'\0'};
        /*Create iptable Rule Chain For PortForwarding*/
        if(!Portforwarding){
                system("iptables -t nat -X prerouting_fromwan");
                system("iptables -t nat -N prerouting_fromwan");
                system("iptables -t nat -A PREROUTING -i eth0 -j prerouting_fromwan");
                Portforwarding=1;
        }
        /*Add iptable Rule For PortForwarding protocol TCP,UDP,TCP/UDP */
        if((strcmp(prot,"both") == 0)||(strcmp(prot,"tcp")==0)){
                snprintf(cmd,sizeof cmd,
                "iptables -t nat -A prerouting_fromwan -p tcp -m tcp --dport %u -j DNAT --to-destination %u.%u.%u.%u:%u\n",
                ExternalPort,InternalClient[0],InternalClient[1],InternalClient[2],InternalClient[3],ExternalPortEndRange);
                system(cmd);
        }
        if((strcmp(prot,"both") == 0)||(strcmp(prot,"udp")==0)){
                snprintf(cmd,sizeof cmd,
                "iptables -t nat -A prerouting_fromwan -p udp -m udp --dport %u -j DNAT --to-destination %u.%u.%u.%u:%u\n",
                ExternalPort,InternalClient[0],InternalClient[1],InternalClient[2],InternalClient[3],ExternalPortEndRange);
                system(cmd);
        }
}

int port_forwarding_delete_rule(UCHAR InternalClient[IPV4_ADDRESS_SIZE],char *prot,USHORT ExternalPort,USHORT ExternalPortEndRange)
{
        char cmd[1024]= {'\0'};
        /*Delete iptable Rule For PortForwarding protocol TCP,UDP,TCP/UDP */
        if((strcmp(prot,"both") == 0)||(strcmp(prot,"tcp")==0)){
                snprintf(cmd,sizeof cmd,
                "iptables -t nat -D prerouting_fromwan -p tcp -m tcp --dport %u -j DNAT --to-destination %u.%u.%u.%u:%u\n",
                ExternalPort,InternalClient[0],InternalClient[1],InternalClient[2],InternalClient[3],ExternalPortEndRange);
                system(cmd);
        }
        if((strcmp(prot,"both") == 0)||(strcmp(prot,"udp")==0)){
                snprintf(cmd,sizeof cmd,
                "iptables -t nat -D prerouting_fromwan -p udp -m udp --dport %u -j DNAT --to-destination %u.%u.%u.%u:%u\n",
                ExternalPort,InternalClient[0],InternalClient[1],InternalClient[2],InternalClient[3],ExternalPortEndRange);
                system(cmd);
        }
}

int port_forwarding_disable()
{
        /*Delete PortForwarding iptable Rules*/
        system("iptables -t nat -F prerouting_fromwan");
        system("iptables -t nat -D PREROUTING -i eth0 -j prerouting_fromwan");
        Portforwarding=0;
}
	
	 /***********************************  PORTTRIGGERING IMPLEMENTATION **********************/

int port_triggering_add_rule(USHORT TriggerPortStart,USHORT TriggerPortEnd,char *prot,USHORT ForwardPortStart,USHORT ForwardPortEnd)
{
        char cmd[1024]= {'\0'};
        if(!Porttriggering){
                /*Create iptable Rule Chain For PortTriggering*/
                snprintf(cmd,sizeof(cmd),
                                "iptables -t filter -X lan2wan_triggers && iptables -t filter -X wan2lan_trigger \
                                && iptables -t nat -X prerouting_fromlan_trigger && iptables -t nat -X prerouting_fromwan_trigger");
                system(cmd);
                snprintf(cmd,sizeof(cmd),
                                "iptables -t filter -X xlog_accept_lan2wan_triggers && iptables -t filter -X \
                                xlog_accept_wan2lan_triggers && iptables -t nat -X plog_accept_wan2lan_triggers \
                                && iptables -t nat -X plog_accept_lan2wan_triggers");
                system(cmd);
                snprintf(cmd,sizeof(cmd),
                                "iptables -t filter -N lan2wan_triggers && iptables -t filter -N wan2lan_trigger \
                                && iptables -t nat -N prerouting_fromlan_trigger && iptables -t nat -N prerouting_fromwan_trigger");
                system(cmd);
                snprintf(cmd,sizeof(cmd),
                                "iptables -t filter -N xlog_accept_lan2wan_triggers && iptables -t filter -N \
                                xlog_accept_wan2lan_triggers && iptables -t nat -N plog_accept_wan2lan_triggers \
                                && iptables -t nat -N plog_accept_lan2wan_triggers");
                system(cmd);
                system("iptables -t filter  -I FORWARD -i eth0 -o brlan0 -j wan2lan_trigger");
                system("iptables -t filter  -I FORWARD -i brlan0 -o eth0 -j lan2wan_triggers");
                system("iptables -t nat -A PREROUTING -i brlan0 -j prerouting_fromlan_trigger");
                system("iptables -t nat -A PREROUTING -i eth0 -j prerouting_fromwan_trigger");
                system("iptables -A xlog_accept_lan2wan_triggers -m state --state NEW -j LOG --log-prefix \"TRIGGERING: FW.LAN2WAN ACCEPT \" \  --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-options");
                system("iptables -A xlog_accept_wan2lan_triggers -m state --state NEW -j LOG --log-prefix \"TRIGGERING: FW.WAN2LAN ACCEPT \" \  --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-option");
                system("iptables -A xlog_accept_lan2wan_triggers -j ACCEPT");
                system("iptables -t nat -A plog_accept_wan2lan_triggers -m state --state NEW -j LOG --log-prefix \"TRIGGERING_NAT: FW.WAN2LAN ACCEPT \" \  --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-option");
                system("iptables -t nat -A plog_accept_lan2wan_triggers -m state --state NEW -j LOG --log-prefix \"TRIGGERING_NAT: FW.LAN2WAN ACCEPT \" \  --log-level 7 --log-tcp-sequence --log-tcp-options --log-ip-options");
                Porttriggering=1;
        }
        /*Add iptable Rule For PortTriggering protocol TCP,UDP,TCP/UDP */
        if((strcmp(prot,"both") == 0)||(strcmp(prot,"tcp")==0)){
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A prerouting_fromwan_trigger -p tcp --dport %d:%d -j plog_accept_wan2lan_triggers"
                                ,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A plog_accept_wan2lan_triggers -j TRIGGER --trigger-type dnat --trigger-proto tcp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A prerouting_fromlan_trigger -p tcp -m tcp --dport %d:%d -j plog_accept_lan2wan_triggers",TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A plog_accept_lan2wan_triggers -j TRIGGER --trigger-type out --trigger-proto tcp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);

                snprintf(cmd,sizeof cmd,
                                "iptables -A wan2lan_trigger -p tcp -m tcp --dport %d:%d  -j xlog_accept_wan2lan_triggers",
                                ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -A xlog_accept_wan2lan_triggers -j TRIGGER --trigger-type in --trigger-proto tcp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -A lan2wan_triggers -p tcp -m tcp --dport %d:%d -j xlog_accept_lan2wan_triggers",                                 TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -A lan2wan_triggers -p tcp -m tcp --sport %d:%d -j xlog_accept_lan2wan_triggers",                                 ForwardPortStart,ForwardPortEnd);
                system(cmd);
                }

        if((strcmp(prot,"both") == 0)||(strcmp(prot,"udp")==0)){
                 snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A prerouting_fromwan_trigger -p udp --dport %d:%d -j plog_accept_wan2lan_triggers"
                                ,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A plog_accept_wan2lan_triggers -j TRIGGER --trigger-type dnat --trigger-proto udp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A prerouting_fromlan_trigger -p udp -m udp --dport %d:%d -j plog_accept_lan2wan_triggers",TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -A plog_accept_lan2wan_triggers -j TRIGGER --trigger-type out --trigger-proto udp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);

                snprintf(cmd,sizeof cmd,
                                "iptables -A wan2lan_trigger -p udp -m udp --dport %d:%d  -j xlog_accept_wan2lan_triggers",
                                ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -A xlog_accept_wan2lan_triggers -j TRIGGER --trigger-type in --trigger-proto udp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -A lan2wan_triggers -p udp -m udp --dport %d:%d -j xlog_accept_lan2wan_triggers",                                 TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -A lan2wan_triggers -p udp -m udp --sport %d:%d -j xlog_accept_lan2wan_triggers",                                 ForwardPortStart,ForwardPortEnd);
                system(cmd);

                }
        }

int port_triggering_delete_rule(USHORT TriggerPortStart,USHORT TriggerPortEnd,char *prot,USHORT ForwardPortStart,USHORT ForwardPortEnd)
{
        char cmd[1024]= {'\0'};
        /*Delete iptable Rule For PortTriggering protocol TCP,UDP,TCP/UDP */
        if((strcmp(prot,"both") == 0)||(strcmp(prot,"tcp")==0)){
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D prerouting_fromwan_trigger -p tcp --dport %d:%d -j plog_accept_wan2lan_triggers"
                                ,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D plog_accept_wan2lan_triggers -j TRIGGER --trigger-type dnat --trigger-proto tcp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D prerouting_fromlan_trigger -p tcp -m tcp --dport %d:%d -j plog_accept_lan2wan_triggers",TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D plog_accept_lan2wan_triggers -j TRIGGER --trigger-type out --trigger-proto tcp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);

                snprintf(cmd,sizeof cmd,
                                "iptables -D wan2lan_trigger -p tcp -m tcp --dport %d:%d  -j xlog_accept_wan2lan_triggers",
                                ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -D xlog_accept_wan2lan_triggers -j TRIGGER --trigger-type in --trigger-proto tcp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -D lan2wan_triggers -p tcp -m tcp --dport %d:%d -j xlog_accept_lan2wan_triggers",                                 TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -D lan2wan_triggers -p tcp -m tcp --sport %d:%d -j xlog_accept_lan2wan_triggers",                                 ForwardPortStart,ForwardPortEnd);
                system(cmd);
                }

    if((strcmp(prot,"both") == 0)||(strcmp(prot,"udp")==0)){
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D prerouting_fromwan_trigger -p udp --dport %d:%d -j plog_accept_wan2lan_triggers"
                                ,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D plog_accept_wan2lan_triggers -j TRIGGER --trigger-type dnat --trigger-proto udp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D prerouting_fromlan_trigger -p udp -m udp --dport %d:%d -j plog_accept_lan2wan_triggers",TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t nat -D plog_accept_lan2wan_triggers -j TRIGGER --trigger-type out --trigger-proto udp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);

                snprintf(cmd,sizeof cmd,
                                "iptables -D wan2lan_trigger -p udp -m udp --dport %d:%d  -j xlog_accept_wan2lan_triggers",
                                ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -D xlog_accept_wan2lan_triggers -j TRIGGER --trigger-type in --trigger-proto udp --trigger-match %d:%d  --trigger-relate %d:%d\n",ForwardPortStart,ForwardPortEnd,ForwardPortStart,ForwardPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -D lan2wan_triggers -p udp -m udp --dport %d:%d -j xlog_accept_lan2wan_triggers",                                 TriggerPortStart,TriggerPortEnd);
                system(cmd);
                snprintf(cmd,sizeof cmd,
                                "iptables -t filter -D lan2wan_triggers -p udp -m udp --sport %d:%d -j xlog_accept_lan2wan_triggers",                                 ForwardPortStart,ForwardPortEnd);
                system(cmd);
        }
}

int port_triggering_disable()
{
                /*Delete PortTriggering iptable Rules*/
                system("iptables -F wan2lan_trigger");
                system("iptables -F lan2wan_triggers");
                system("iptables  -t nat -F prerouting_fromlan_trigger");
                system("iptables -t nat -F prerouting_fromwan_trigger");
                system("iptables -t filter  -D FORWARD -i eth0 -o brlan0 -j wan2lan_trigger");
                system("iptables -t filter  -D FORWARD -i brlan0 -o eth0 -j lan2wan_triggers");
                system("iptables -t nat -D PREROUTING -i brlan0 -j prerouting_fromlan_trigger");
                system("iptables -t nat -D PREROUTING -i eth0 -j prerouting_fromwan_trigger");
                /*Delete log entry*/
                system("iptables -F xlog_accept_lan2wan_triggers");
                system("iptables -F xlog_accept_wan2lan_triggers");
                system("iptables -t nat -F plog_accept_lan2wan_triggers");
                system("iptables -t nat -F plog_accept_wan2lan_triggers");
                Porttriggering=0;
}
