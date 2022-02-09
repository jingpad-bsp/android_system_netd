/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "ExtDataController"
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <string.h>
#include <mutex>
#include <unordered_set>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <logwrap/logwrap.h>
#include <netdutils/StatusOr.h>

#include <netdutils/Misc.h>
#include <netdutils/Syscalls.h>
#include <processgroup/processgroup.h>
#include "TrafficController.h"
#include "bpf/BpfMap.h"
#include <netutils/ifc.h>

#include "FirewallController.h"
#include "InterfaceController.h"
#include "NetlinkListener.h"
#include "netdutils/DumpWriter.h"
#include "qtaguid/qtaguid.h"
#include "ExtDataController.h"
#include "Controllers.h"
#include "SockDiag.h"

#include <cutils/properties.h>

#include <logwrap/logwrap.h>
#include "PppController.h"

using namespace android::bpf;  // NOLINT(google-build-using-namespace): grandfathered

using android::net::gCtls;

namespace android {
namespace net {

using base::StringPrintf;
using base::unique_fd;
using netdutils::DumpWriter;
using netdutils::extract;
using netdutils::ScopedIndent;
using netdutils::Slice;
using netdutils::sSyscalls;
using netdutils::Status;
using netdutils::statusFromErrno;
using netdutils::StatusOr;
using netdutils::status::ok;

static char s_localip[INET_ADDRSTRLEN];
static char s_pcv4ip[INET_ADDRSTRLEN];

static bool isNeedCreateChain = true;


const char* usb_name[] = {
     "rndis0",
     "usb0",
};

/*
 *to check usb device name in different kernel.
 *be compatible with usb name in k3.10 and k4.4.
 */
static int check_usb_name(void)
{
    int i = 0;
    int usb_ifidx = 0;
    int ret = 0;
    int devnum = 0;

    ifc_init();
    devnum = (int)sizeof(usb_name)/sizeof(char*);
    for (i = 0; i < devnum; i++) {
        ret = ifc_get_ifindex(usb_name[i],&usb_ifidx);
        if (ret == 0) {
            ALOGD("auto test usb name =%s.\n", usb_name[i] );
            break;
        }
    }
    ifc_close();
    if (i == sizeof(usb_name)/sizeof(char*))
        i = 0;

    return i;
}

static int get_ipv4_ifaddr(const char *ifname, in_addr_t *addr) {
    ifc_init();
    if (ifc_get_addr(ifname, addr)) {
        ALOGE("Can't get the %s's ipv4 address: %s\n", ifname,
              strerror(errno));
        ifc_close();
        return -1;
    }
    ifc_close();

    return 0;
}

static int get_ipv4_pcaddr(in_addr_t *addr) {
    char arpstr[128];
    FILE *fp = NULL;


    fp = fopen("/proc/net/arp", "r");
    if (fp == NULL) {
        ALOGE("Fail to open /proc/net/arp: %s\n", strerror(errno));
        return -1;
    }
    memset(arpstr,0,sizeof(arpstr));
    while (fgets(arpstr, sizeof(arpstr), fp) != NULL) {
        char *p, *q, *w;
        p = strstr(arpstr,"usb");
        if (p) {
                w = arpstr;
                ALOGE("Get Usb arp {%s}\n", w);
                q = strtok(w," ");
                ALOGE("Get usb pc ip {%s}\n", w);
                if (inet_pton(AF_INET, w, addr) != 1) {
                        ALOGE("Can't convert %s to addr format\n", p);
                        fclose(fp);
                        return -1;
                }
                fclose(fp);
                return 0;
        }
        memset(arpstr,0,sizeof(arpstr));
    }
    fclose(fp);
    return -1;
}

static int get_ipv6_globaladdr(const char *ifname,char *ipv6addr) {
    char addrstr[48];
    char name[64];
    FILE *f;

    f = fopen("/proc/net/if_inet6", "r");
    if (f == NULL) {
        ALOGE("Fail to open /proc/net/if_inet6: %s\n", strerror(errno));
        return 0;
    }

    /* Format:
     * 20010db8000a0001fc446aa4b5b347ed 03 40 00 01    wlan0
     */
    while (fscanf(f, "%32s %*02x %*02x %*02x %*02x %63s\n",
        addrstr, name) == 2) {
        if (strcmp(name, ifname))
            continue;

        if (strncmp(addrstr, "fe80", sizeof("fe80")-1) != 0) {
            ALOGD("Get %s's ipv6 global address: %s\n", ifname, addrstr);
            sprintf(ipv6addr,"%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c",
                     addrstr[0],addrstr[1],addrstr[2],addrstr[3],
                     addrstr[4],addrstr[5],addrstr[6],addrstr[7],
                     addrstr[8],addrstr[9],addrstr[10],addrstr[11],
                     addrstr[12],addrstr[13],addrstr[14],addrstr[15],
                     addrstr[16],addrstr[17],addrstr[18],addrstr[19],
                     addrstr[20],addrstr[21],addrstr[22],addrstr[23],
                     addrstr[24],addrstr[25],addrstr[26],addrstr[27],
                     addrstr[28],addrstr[29],addrstr[30],addrstr[31]);
           fclose(f);
           return 0;
        }
    }
    fclose(f);
    return 1;
}

static int has_ipv6_globaladdr(const char *ifname) {
    char addrstr[INET6_ADDRSTRLEN];
    char name[64];
    FILE *f;

    f = fopen("/proc/net/if_inet6", "r");
    if (f == NULL) {
        ALOGE("Fail to open /proc/net/if_inet6: %s\n", strerror(errno));
        return 0;
    }

    /* Format:
     * 20010db8000a0001fc446aa4b5b347ed 03 40 00 01    wlan0
     */
    while (fscanf(f, "%32s %*02x %*02x %*02x %*02x %63s\n",
        addrstr, name) == 2) {
        if (strcmp(name, ifname))
            continue;

        if (strncmp(addrstr, "fe80", SSLEN("fe80")) != 0) {
            ALOGD("Get %s's ipv6 global address: %s\n", ifname, addrstr);
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}


static int cmd2type(char **cmd) {
    if (!strncasecmp(*cmd, "<preifup>", SSLEN("<preifup>"))) {
        *cmd += SSLEN("<preifup>");
        return CMD_TYPE_PREIFUP;
    } else if (!strncasecmp(*cmd, "<ifup>", SSLEN("<ifup>"))) {
        *cmd += SSLEN("<ifup>");
        return CMD_TYPE_IFUP;
    } else if (!strncasecmp(*cmd, "<ifdown>", SSLEN("<ifdown>"))) {
        *cmd += SSLEN("<ifdown>");
        return CMD_TYPE_IFDOWN;
    } else if(!strncasecmp(*cmd, "<dataOffDisable>", SSLEN("<dataOffDisable>"))) {
        *cmd += SSLEN("<dataOffDisable>");
        return CMD_TYPE_DATAOFF_DISABLE;
    } else if(!strncasecmp(*cmd, "<dataOffEnable>", SSLEN("<dataOffEnable>"))) {
        *cmd += SSLEN("<dataOffEnable>");
        return CMD_TYPE_DATAOFF_ENABLE;
    } else if (!strncasecmp(*cmd, "<pppup>", SSLEN("<pppup>"))) {
        *cmd += SSLEN("<pppup>");
        return CMD_TYPE_PPPUP;
    } else if (!strncasecmp(*cmd, "<startpppd>", SSLEN("<startpppd>"))) {
        *cmd += SSLEN("<startpppd>");
        return CMD_TYPE_PPPD_START;
    } else if (!strncasecmp(*cmd, "<stoppppd>", SSLEN("<stoppppd>"))) {
        *cmd += SSLEN("<stoppppd>");
        return CMD_TYPE_PPPD_STOP;
    }

    return -1;
}

int parse_cmd(char *cmd, struct command *c) {
    char *ifname, *v4v6, *autotest, *ipv4addr;
    char *saveptr = NULL;
    int type;
    char *slotIndex, *sPort;

    char * ttyName, *local, *remote, *dns1, *dns2;

    if (!strstr(cmd, "ext_data")) {
        ALOGE("wrong cmd: %s\n", cmd);
        return -1;
    }
    cmd += SSLEN("ext_data");

    if ((type=cmd2type(&cmd)) < 0) {
        ALOGE("Parse the cmdtype fail: %s\n", cmd);
        return -1;
    }
    c->cmdtype = type;

    if(CMD_TYPE_DATAOFF_ENABLE == type || CMD_TYPE_DATAOFF_DISABLE == type) {
        slotIndex = strtok_r(cmd, ";", &saveptr);
        sPort = strtok_r(NULL, ";", &saveptr);
        c->slotIndex = atoi(slotIndex);;
        c->sPort = atoi(sPort);
        return 0;
    }

    if(CMD_TYPE_PPPD_START == type) {
        ttyName = strtok_r(cmd, ";", &saveptr);

        local = strtok_r(NULL, ";", &saveptr);
        remote = strtok_r(NULL, ";", &saveptr);
        dns1 = strtok_r(NULL, ";", &saveptr);
        dns2 = strtok_r(NULL, ";", &saveptr);

        if ( NULL == ttyName || NULL == local || NULL ==  remote || NULL == dns1 || NULL == dns2) {
            ALOGE("ppp ! , parse_cmd() is null !\n" );
            return -2;
        }

        c->ttyName = ttyName;

        snprintf(c->local, sizeof(c->local),"%s",local);
        snprintf(c->remote, sizeof(c->ipv4addr),"%s",remote);
        snprintf(c->dns1, sizeof(c->ipv4addr),"%s",dns1);
        snprintf(c->dns2, sizeof(c->ipv4addr),"%s",dns2);

        ALOGE("ppp Parse the cmdtype :start_pppd =   c->ttyName = %s, c->local = %s, c->remote= %s,  c->dns1 = %s, c->dns2 = %s \n", c->ttyName, c->local, c->remote, c->dns1,c->dns2 );
        return 0;
    }

    if (CMD_TYPE_PPPD_STOP == type) {
        return 0;
    }

    ifname = strtok_r(cmd, ";", &saveptr);
    if (CMD_TYPE_PPPUP == c->cmdtype) {
        /*parse ipv4 address for ppp*/
        ipv4addr = NULL;
        ipv4addr = strtok_r(NULL, ";", &saveptr);
        if ( NULL == ipv4addr || NULL == ifname ) {
             ALOGE("Parse cmd fail: ifname =%s , ipv4addr=%s\n",
             ifname ? ifname : "", ipv4addr ? ipv4addr : "");
             return -2;
        }
        c->ifname = ifname;
        snprintf(c->ipv4addr, sizeof(c->ipv4addr),"%s",ipv4addr);
        ALOGE("ppp , Parse the CMD_TYPE_PPPUP :ifname =  %s, ipv4addr = %s\n", c->ifname, c->ipv4addr);
        return 0;
    }

    v4v6 = strtok_r(NULL, ";", &saveptr);
    autotest = strtok_r(NULL, ";", &saveptr);

    if (ifname == NULL || v4v6 == NULL || autotest == NULL) {
        ALOGE("Parse cmd fail: ifname=%s, v4v6=%s, auto=%s\n",
              ifname ? ifname : "", v4v6 ? v4v6 : "",
              autotest ? autotest : "");
        return -2;
    }

    c->ifname = ifname;
    if (!strcasecmp(v4v6, "1")) {
        c->pdp_type = PDP_ACTIVE_IPV4;
    } else if (!strcasecmp(v4v6, "2")) {
        c->pdp_type = PDP_ACTIVE_IPV6;
    } else if (!strcasecmp(v4v6, "3")) {
        c->pdp_type = PDP_ACTIVE_IPV4 | PDP_ACTIVE_IPV6;
    } else {
        ALOGE("IPV4V6 type is wrong: %s\n", v4v6);
        return -3;
    }

    c->is_autotest = !!atoi(autotest);

    ALOGD("Parse ok: cmd=%d, ifname=%s, ipv6=%s(%x), autotest=%d\n",
          c->cmdtype, c->ifname, v4v6, c->pdp_type, c->is_autotest);
    return 0;
}

int exec_cmd(const char *cmd_fmt, ...) {
    char cmd[128];
    va_list va;
    int ecode;

    va_start(va, cmd_fmt);
    vsnprintf(cmd, sizeof cmd, cmd_fmt, va);
    va_end(va);

    ecode = system(cmd);
    ALOGD("%s exit with %d\n", cmd, ecode);
    return ecode;
}

ExtDataController::ExtDataController(){}

int ExtDataController::do_preifup(struct command *c) {
    char ip_type[64];
    char prop[PROPERTY_VALUE_MAX];

    /* 1-ipv4, 2-ipv6, 3-ipv4v6, if not set, suppose v4v6 is on */
    filterIcmpv6pkts(0, c->ifname);
    snprintf(ip_type, sizeof ip_type, "vendor.net.%s.ip_type", c->ifname);
    property_get(ip_type, prop, "66");
    ALOGD("%s is %s\n", ip_type, prop);
    /*only ipv4, filter icmpv6 pkts.*/
    if (atoi(prop) == 1)
    	filterIcmpv6pkts(1, c->ifname);
    return 0;
}

void ExtDataController::start_autotest_v4(struct command *c) {
    char localip[INET_ADDRSTRLEN];
    char pcv4ip[INET_ADDRSTRLEN];
    in_addr_t ifaddr, pcaddr;
    int usbname_id = 0;

    if (get_ipv4_ifaddr(c->ifname, &ifaddr))
        return;
    if (get_ipv4_pcaddr(&pcaddr))
        return;

    usbname_id = check_usb_name();
    (void) inet_ntop(AF_INET, &ifaddr, localip, sizeof localip);
    (void) inet_ntop(AF_INET, &pcaddr, pcv4ip, sizeof pcv4ip);
    ALOGD("Localip=%s, pcv4ip=%s\n", localip, pcv4ip);

    if (0 == strncmp(localip, s_localip, sizeof localip)
    && (0 == strncmp(pcv4ip, s_pcv4ip, sizeof pcv4ip)))
    return;
    memset(s_localip, 0, sizeof s_localip);
    memset(s_pcv4ip, 0, sizeof s_pcv4ip);
    strncpy(s_localip, localip, sizeof localip);
    strncpy(s_pcv4ip, pcv4ip, sizeof pcv4ip);

    /* Flush old iptables rules */
    exec_cmd("iptables -w -F");
    exec_cmd("iptables -w -P FORWARD ACCEPT");
    exec_cmd("iptables -w -t nat -F");
    exec_cmd("iptables -w -t mangle -F");

    exec_cmd("system/bin/iptables -w -t nat -A PREROUTING -i %s -j DNAT --to-destination"
             " %s", c->ifname, pcv4ip);
    exec_cmd("system/bin/iptables -w -t nat -A POSTROUTING -s %s -j SNAT --to-source %s",
             pcv4ip, localip);
    /* Drop the misc pakcets from PC */
    exec_cmd("system/bin/iptables -w -I FORWARD -o %s -p all ! -d %s/16 -j DROP",
             c->ifname, localip);

    /* Add ip rule and route policy */
    exec_cmd("ip rule del table %d", ROUTE_TABLE_LAN_NETWORK);
    exec_cmd("ip route flush table %d", ROUTE_TABLE_LAN_NETWORK);
    exec_cmd("ip rule add from all iif %s lookup %d",usb_name[usbname_id],
             ROUTE_TABLE_LAN_NETWORK);
    exec_cmd("ip route add default via %s dev %s table %d", localip, c->ifname,
             ROUTE_TABLE_LAN_NETWORK);

    exec_cmd("ip route del default");
    exec_cmd("ip route add default via %s dev %s", localip, c->ifname);

    /* Drop dns and ntp packets from UE */
    exec_cmd("iptables -w -I OUTPUT -s %s -p udp --dport 53 -j DROP", localip);
    exec_cmd("iptables -w -I OUTPUT -s %s -p udp --dport 123 -j DROP", localip);
}

void ExtDataController::start_autotest_v6(struct command *c) {
    const int max_retry = 10;
    int retry;
    int usbname_id = 0;

    ALOGE("start auto test v6.\n");
    gCtls->tetherCtrl.rmV6RadvdIface(c->ifname);
    //exec_cmd("system/bin/ndc tether radvd remove_upstream %s", c->ifname);
    exec_cmd("system/bin/ip -6 rule del table %d", ROUTE_TABLE_LAN_NETWORK);
    exec_cmd("system/bin/ip -6 route flush table %d", ROUTE_TABLE_LAN_NETWORK);
    exec_cmd("system/bin/ip -6 rule del table %d", ROUTE_TABLE_WAN_NETWORK);
    exec_cmd("system/bin/ip -6 route flush table %d", ROUTE_TABLE_WAN_NETWORK);

    /*
     * In ext_data.sh, there's a sleep(5) call here. I think if the ipv6 global
     * address is obtained, we can UP the radvd right now.
     */
    for (retry = 0; retry < max_retry; retry++) {
        if (has_ipv6_globaladdr(c->ifname))
            break;

        usleep(500 * 1000);
    }

    if (retry == max_retry)
        ALOGE("Cannot get the %s's ipv6 global address\n", c->ifname);

        gCtls->tetherCtrl.addV6RadvdIface(c->ifname);
        //exec_cmd("system/bin/ndc tether radvd add_upstream %s", c->ifname);
    /*
     * Image the Network topology showed below, UE act as an IPV6 Router:
                              /------\                   +------+
       +---+                  |      |                   |      |
       |   |2003::3     rndis0|      |seth_lte0   2005::1|      |
       |PC |------------------|  UE  |-------------------|SERVER|
       |   |           2003::2|      |2003::1            |      |
       +---+                  |      |                   |      |
                              \------/                   +------+
     * If the packet was from SERVER to PC, ie src=2005::1,dst=2003::3,
     * UE will be confused that how to deliver this packet, 2003::3 maybe
     * local at seth_lte0 side or rndis0 side. So add policy rule to avoid
     * this embarrassing scenes.
     */

    usbname_id = check_usb_name();
    exec_cmd("system/bin/ip -6 rule add iif %s lookup %d pref %d", usb_name[usbname_id],
             ROUTE_TABLE_LAN_NETWORK, ROUTE_TABLE_PRIORITY);
    exec_cmd("system/bin/ip -6 route add default dev %s table %d", c->ifname,
             ROUTE_TABLE_LAN_NETWORK);
    exec_cmd("system/bin/ip -6 rule add iif %s lookup %d pref %d", c->ifname,
             ROUTE_TABLE_WAN_NETWORK, ROUTE_TABLE_PRIORITY);
    exec_cmd("system/bin/ip -6 route add default dev %s table %d", usb_name[usbname_id],
             ROUTE_TABLE_WAN_NETWORK);

    exec_cmd("system/bin/ip -6 route del default");
    exec_cmd("system/bin/ip -6 route add default dev %s", c->ifname);
    return;
}

void ExtDataController::start_autotest(struct command *c) {
    if (c->pdp_type & PDP_ACTIVE_IPV4)
        start_autotest_v4(c);
    if (c->pdp_type & PDP_ACTIVE_IPV6)
        start_autotest_v6(c);
}

void ExtDataController::stop_autotest_v4(struct command *c) {

    if (c == NULL)
       return;
    exec_cmd("system/bin/iptables -w -F");
    exec_cmd("system/bin/iptables -w -X");
    memset(s_localip, 0, sizeof s_localip);
    memset(s_pcv4ip, 0, sizeof s_pcv4ip);
    return;
}

void ExtDataController::stop_autotest_v6(struct command *c) { 
    int ret;

    ret = gCtls->tetherCtrl.rmV6RadvdIface(c->ifname);
    ALOGE("stop auto test v6's return %d.\n", ret);
    //exec_cmd("system/bin/ndc tether radvd remove_upstream %s", c->ifname);
    return;
}

void ExtDataController::stop_autotest(struct command *c) {
    if (c->pdp_type & PDP_ACTIVE_IPV4)
        stop_autotest_v4(c);
    if (c->pdp_type & PDP_ACTIVE_IPV6)
        stop_autotest_v6(c);
    return;
}

void ExtDataController::do_ifup(struct command *c) {
    if (c->is_autotest)
        start_autotest(c);

    return;
}

void ExtDataController::do_ifdown(struct command *c) {
    if (c->is_autotest)
        stop_autotest(c);

        //destroy network
        SockDiag sd;
        in_addr_t ifaddr;
        char localip[32];
        char ipv6addr[48];
        int ret1,ret2;

        ALOGD("closeall for interface %s",c->ifname);
        ret1 = get_ipv4_ifaddr(c->ifname,&ifaddr);
        if(ret1 == 0){
                if(sd.open()){
                        inet_ntop(AF_INET,&ifaddr,localip,sizeof localip);
                        ALOGD("Closeall:destroy ipv4 sockets %s",localip);
                        ret1 = sd.destroySockets(localip);
                        if(ret1 < 0){
                                ALOGE("Closeall:error destroying sockets -- %s",strerror(-ret1));
                        }
                }else{
                        ALOGE("Closeall:opening SockDiag failed -- %s",strerror(errno));
                }
        }else{
                ALOGE("Closeall:get_ipv4_ifaddr failed");
        }

        ret2 = get_ipv6_globaladdr(c->ifname,ipv6addr);
        if(ret2==0){
                SockDiag sd2;
                if(sd2.open()){
                        ALOGD("Closeall:destroy ipv6 sockets %s",ipv6addr);
                        ret2 = sd2.destroySockets(ipv6addr);
                        if(ret2 < 0){
                                ALOGE("Closeall:error destroying ipv6 sockets -- %s", strerror(-ret2));
                        }
                }else{
                        ALOGE("Closeall:opening SockDiag failed for ipv6 -- %s",strerror(errno));
                }
        }else{
                ALOGE("Closeall:no ipv6 address!");
        }

    return;
}

void ExtDataController::do_dataOffEnable(struct command *c) {
    setDataOffEnable(true, c->slotIndex, c->sPort);
    return;
}

void ExtDataController::do_dataOffDisable(struct command *c) {
    setDataOffEnable(false, c->slotIndex, c->sPort);
    return;
}

int ExtDataController::process_cmd(struct command *c) {
    switch (c->cmdtype) {
        case CMD_TYPE_PREIFUP:
            do_preifup(c);
            break;

        case CMD_TYPE_IFUP:
            do_ifup(c);
            break;

        case CMD_TYPE_IFDOWN:
            do_ifdown(c);
            break;

        case CMD_TYPE_DATAOFF_ENABLE:
             do_dataOffEnable(c);
             break;

        case CMD_TYPE_DATAOFF_DISABLE:
             do_dataOffDisable(c);
             break;

        case CMD_TYPE_PPPUP:
             do_ppproute(c);
             break;

        case CMD_TYPE_PPPD_START:
             do_pppd_start(c);
             break;

        case CMD_TYPE_PPPD_STOP:
             do_pppd_stop();
             break;

        default:
            break;
    }

    return 0;
}

int ExtDataController::filterIcmpv6pkts(int ops, const char *ifname)
{
    int ret;
    char buff[128];

    sprintf(buff,"/system/bin/ip6tables -w -%s OUTPUT -o %s -p icmpv6 -j DROP",
	    ops? "I" : "D", ifname);
    ret = system(buff);
    ALOGD("Do command:%s, return=%d",buff, ret);
    return 0;
}
int ExtDataController::parseExtDataCmd(std::string cmd) {
    struct command cmd2;

    char *str_c = new char[strlen(cmd.c_str())+1];
    strcpy(str_c,cmd.c_str());

    if (parse_cmd(str_c, &cmd2) == 0) {
	process_cmd(&cmd2);
	return 0;
    } else
	return 1;
}

int ExtDataController::setDnsFilterEnable(int enable) {

    exec_cmd("system/bin/iptables -w -%s INPUT -p udp --dport 53 -j DROP", enable? "A" : "D");
    exec_cmd("system/bin/iptables -w -%s OUTPUT -p udp --dport 53 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/iptables -w -%s FORWARD -p udp --dport 53 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/ip6tables -w -%s INPUT -p udp --dport 53 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/ip6tables -w -%s OUTPUT -p udp --dport 53 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/ip6tables -w -%s FORWARD -p udp --dport 53 -j DROP", enable ? "A" : "D");
    //# Bug610743 - Drop MLD packets for PICLAB test
    exec_cmd("system/bin/ip6tables -w -%s OUTPUT -p icmpv6 --icmpv6-type 143 -j DROP", enable ? "A" : "D");
    //filter private dns, the type is tcp and the destination port is 853
    exec_cmd("system/bin/iptables -w -%s INPUT -p tcp --dport 853 -j DROP", enable? "A" : "D");
    exec_cmd("system/bin/iptables -w -%s OUTPUT -p tcp --dport 853 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/iptables -w -%s FORWARD -p tcp --dport 853 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/ip6tables -w -%s INPUT -p tcp --dport 853 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/ip6tables -w -%s OUTPUT -p tcp --dport 853 -j DROP", enable ? "A" : "D");
    exec_cmd("system/bin/ip6tables -w -%s FORWARD -p tcp --dport 853 -j DROP", enable ? "A" : "D");
    return 0;
}

void quoteChainCmd(bool enable, char * ifname) {
    const char *chainName = "bw_data_off";
    if ( NULL != ifname) {
         exec_cmd("system/bin/iptables -w -%s INPUT -i %s -j %s", enable? "A" : "D", ifname, chainName);
         exec_cmd("system/bin/iptables -w -%s OUTPUT -o %s -j %s", enable ? "A" : "D", ifname, chainName);

         exec_cmd("system/bin/ip6tables -w -%s INPUT -i %s -j %s", enable ? "A" : "D", ifname, chainName);
         exec_cmd("system/bin/ip6tables -w -%s OUTPUT -o %s -j %s", enable ? "A" : "D", ifname, chainName);
    }

}

void doChainCmd(bool enable, char * ifname , int port) {

    if ((port <= 0) && (NULL != ifname)) {
         exec_cmd("system/bin/iptables -w -%s bw_data_off -i %s  -p all -j DROP", enable? "A" : "D", ifname);
         exec_cmd("system/bin/iptables -w -%s bw_data_off -o %s -p all -j DROP", enable ? "A" : "D", ifname);

         exec_cmd("system/bin/ip6tables -w -%s bw_data_off -i %s -p all -j DROP", enable ? "A" : "D", ifname);
         exec_cmd("system/bin/ip6tables -w -%s bw_data_off -o %s -p all -j DROP", enable ? "A" : "D", ifname);

    } else {
        exec_cmd("system/bin/iptables -w -%s bw_data_off -p tcp --dport %d -j ACCEPT", "I", port);
        exec_cmd("system/bin/iptables -w -%s bw_data_off -p tcp --sport %d -j ACCEPT", "I", port);

        exec_cmd("system/bin/ip6tables -w -%s bw_data_off -p tcp --dport %d -j ACCEPT", "I", port);
        exec_cmd("system/bin/ip6tables -w -%s bw_data_off -p tcp --sport %d -j ACCEPT", "I", port);
    }

}


int  createChainCmd() {
     const char *chainName = "bw_data_off";
     if (isNeedCreateChain) {
          exec_cmd("system/bin/iptables -w -N %s", chainName);
          exec_cmd("system/bin/ip6tables -w -N %s", chainName);
          isNeedCreateChain = false;
     }
     return 0;
}


void setDataOffChainCmd(bool enable, char * ifname , int port) {
         //新建自定义链
         createChainCmd();
         //执行自定义链
         doChainCmd(enable, ifname, port);
         //引用自定义链
         quoteChainCmd(enable, ifname);
}

int ExtDataController::setDataOffEnable(bool enable, int slotIndex, int port) {
     char eth[PROPERTY_VALUE_MAX] = {0};
     property_get(MODEM_ETH_PROP, eth, "veth");
     char ifname[COMMAND_LEN] = {0};

    //slot1
    if (SLOT1_INDEX == slotIndex) {
         ALOGD(" data off set slot1 !");
        //ifname: seth_lte0/1/2/3/4/5
        //开�? default port is 0
        if(port <= DEFAULT_PORT) {
            for( int i = 0; i <= MAX_SLOT1_SETH_END; i++ ) {
                snprintf(ifname, sizeof(ifname), "%s%d", eth, i);
                setDataOffChainCmd(enable, ifname, port);
            }
        } else {
            setDataOffChainCmd(enable, NULL, port);
        }
    //slot2
    } else if (SLOT2_INDEX == slotIndex) {
         ALOGD("data off set slot2 !");
        //ifname: seth_lte8/8/10/11/12/13
        if(port <= DEFAULT_PORT) {
            for( int j = MAX_SLOT2_SETH_START; j <= MAX_SLOT2_SETH_END; j++ ) {
                snprintf(ifname, sizeof(ifname), "%s%d", eth, j);
                setDataOffChainCmd(enable, ifname, port);
            }
        } else {
            setDataOffChainCmd(enable, NULL, port);
        }
    }
    return 0;
}

int write_file(const char *path, const char *value) {
    int fd, len;

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        ALOGE("open file %s fail: %s\n", path, strerror(errno));
        return -1;
    }

    len = strlen(value);
    if (write(fd, value, len) != len) {
        ALOGE("write %s to file %s fail: %s\n", value, path, strerror(errno));
        close(fd);
        return -1;
    }

    ALOGD("write %s to file %s ok\n", value, path);
    close(fd);
    return 0;
}

void ExtDataController::do_ppproute(struct command *c) {
    char cmd_path[128];

    if (CMD_TYPE_PPPUP == c->cmdtype) {
        /*open forward option*/
        sleep(1);
        snprintf(cmd_path, sizeof(cmd_path), "%s", "/proc/sys/net/ipv4/ip_forward");
        write_file(cmd_path, "1");
        /*del the addr for seth_ltex, it will be assigned to ppp client.*/
        //exec_cmd("system/bin/ip addr del %s dev %s", c->ipv4addr, c->ifname);
        /*add default route in table main*/
        exec_cmd("system/bin/ip route add 0.0.0.0/0 dev %s table main", c->ifname);
        /*add ip rule to allow the pkts in table main*/
        exec_cmd("system/bin/ip rule add from all lookup main priority 31999");
        exec_cmd("system/bin/iptables -w -N ppp_forward");
        exec_cmd("system/bin/iptables -w -I FORWARD 1 -j ppp_forward");
        exec_cmd("system/bin/iptables -w -I ppp_forward -i ppp+ -j ACCEPT");
        exec_cmd("system/bin/iptables -w -I ppp_forward -o ppp+ -j ACCEPT");
    }
    return;
}

void ExtDataController::do_pppd_start(struct command *c) {
    if (CMD_TYPE_PPPD_START == c->cmdtype) {
        PppController *pppCtr = new PppController();
        pppCtr->getTtyList();
        pppCtr->detachPppd("ttyGS0");

        if(NULL != c->ttyName) {
         struct in_addr local, remote, dns1, dns2;

         memset(&local, 0, sizeof(struct in_addr));
         memset(&remote, 0, sizeof(struct in_addr));
         memset(&dns1, 0, sizeof(struct in_addr));
         memset(&dns2, 0, sizeof(struct in_addr));

          if (!inet_aton(c->local, &local)) {
              ALOGE("Invalid local address");
              return ;
          }
          if (!inet_aton(c->remote, &remote)) {
              ALOGE("Invalid remote address");
              return ;
          }
          if (!inet_aton(c->dns1, &dns1)) {
              ALOGE("Invalid dns1 address");
              return ;
          }
          if (!inet_aton(c->dns2, &dns2)) {
              ALOGE("Invalid dns2 address");
              return ;
          }

          int rc = pppCtr->attachPppd(c->ttyName, local, remote, dns1, dns2);
          ALOGD("start pppd attachPppd and rc = %d !\n", rc);

        } else {
            ALOGE("start pppd but param is NULL !\n");
        }
    } else {
         ALOGE("start pppd but type is wrong = %d  !\n",c->cmdtype );
    }
    return;
}

void ExtDataController::do_pppd_stop() {
    PppController *pppCtr = new PppController();
    pppCtr->detachPppd("ttyGS0");
    ALOGE("stop pppd and type is CMD_TYPE_PPPD_STOP !\n" );
    return;
}



}  // namespace net
}  // namespace android
