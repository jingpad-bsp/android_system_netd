/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "TcpSocket2Monitor"

#include <iomanip>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/tcp.h>

#include "Controllers.h"
#include "netdutils/DumpWriter.h"
#include "SockDiag.h"
#include "TcpSocket2Monitor.h"

namespace android {
namespace net {

using std::chrono::duration_cast;
using std::chrono::steady_clock;

constexpr const char* getTcpStateName(int t) {
    switch (t) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN-SENT";
        case TCP_SYN_RECV:
            return "SYN-RECV";
        case TCP_FIN_WAIT1:
            return "FIN-WAIT-1";
        case TCP_FIN_WAIT2:
            return "FIN-WAIT-2";
        case TCP_TIME_WAIT:
            return "TIME-WAIT";
        case TCP_CLOSE:
            return "CLOSE";
        case TCP_CLOSE_WAIT:
            return "CLOSE-WAIT";
        case TCP_LAST_ACK:
            return "LAST-ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_CLOSING:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}

// Helper macro for reading fields into struct tcp_info and handling different struct tcp_info
// versions in the kernel.
#define TCPINFO_GET(ptr, fld, len, zero) \
        (((ptr) != nullptr && (offsetof(struct tcp_info, fld) + sizeof((ptr)->fld)) < len) ? \
        (ptr)->fld : zero)

#if 0
static void tcpInfoPrint(DumpWriter &dw, Fwmark mark, const struct inet_diag_msg *sockinfo,
                         const struct tcp_info *tcpinfo, uint32_t tcpinfoLen) {
    char saddr[INET6_ADDRSTRLEN] = {};
    char daddr[INET6_ADDRSTRLEN] = {};
    inet_ntop(sockinfo->idiag_family, &(sockinfo->id.idiag_src), saddr, sizeof(saddr));
    inet_ntop(sockinfo->idiag_family, &(sockinfo->id.idiag_dst), daddr, sizeof(daddr));

    dw.println(
            "netId=%d uid=%u mark=0x%x saddr=%s daddr=%s sport=%u dport=%u tcp_state=%s(%u) "
            "rtt=%gms sent=%u lost=%u",
            mark.netId,
            sockinfo->idiag_uid,
            mark.intValue,
            saddr,
            daddr,
            ntohs(sockinfo->id.idiag_sport),
            ntohs(sockinfo->id.idiag_dport),
            getTcpStateName(sockinfo->idiag_state), sockinfo->idiag_state,
            TCPINFO_GET(tcpinfo, tcpi_rtt, tcpinfoLen, 0) / 1000.0,
            TCPINFO_GET(tcpinfo, tcpi_segs_out, tcpinfoLen, 0),
            TCPINFO_GET(tcpinfo, tcpi_lost, tcpinfoLen, 0));
}
#endif
void TcpSocket2Monitor::tcpInfoAddStats(const TcpSocket2Monitor::TcpStats& stats) {
    std::vector<int64_t> statsVector(5);
    if (statsVector.size() == 0) {
        for (int i = 0; i < 5; i++) statsVector.push_back(0);
    }

    statsVector[0]   += stats.sent;
    statsVector[1] += stats.lost;
    statsVector[2]   += stats.rttUs;
    statsVector[3] += stats.sentAckDiffMs;
    statsVector[4] += stats.nSockets;
}

int TcpSocket2Monitor::getTcpInfo(String16 *ret)
{
    std::lock_guard<std::mutex> guard(mLock);
    SockDiag sd;
    if (!sd.open()) {
        ALOGE("Error opening sock diag for polling TCP socket info");
        return  0;
    }
    const auto now = steady_clock::now();
    const auto tcpInfoReader = [this, now](Fwmark mark, const struct inet_diag_msg *sockinfo,
                                           const struct tcp_info *tcpinfo,
                                           uint32_t tcpinfoLen) NO_THREAD_SAFETY_ANALYSIS {
      if (sockinfo == nullptr || tcpinfo == nullptr || tcpinfoLen == 0 || mark.intValue == 0) {
            return binder::Status::ok();
      }
      updateSocketStats(now, mark, sockinfo, tcpinfo, tcpinfoLen);

      return binder::Status::ok();
    };

    mNetworkStats.clear();
    if (int ret = sd.getLiveTcpInfos(tcpInfoReader)) {
        ALOGE("Failed to poll TCP socket info: %s", strerror(-ret));
        return 0;
    }

    for (auto const& stats : mNetworkStats) {
            int32_t nSockets = stats.second.nSockets;
        std::string str1;
        std::string str2;
        std::string str3;
        std::string str4;
        uint32_t rtt_ms;

            if (nSockets == 0) {
                continue;
            }
        str1 = "sent:" + std::to_string(stats.second.sent) + ";";
        str2 = "lost:" + std::to_string(stats.second.lost) + ";";
        rtt_ms = stats.second.rttUs/1000/nSockets;
        str3 = "rtt:"  + std::to_string(rtt_ms);
        str4 = str1 + str2 + str3;
#if 0
            netIds.push_back(stats.first);
            sentPackets.push_back(stats.second.sent);
            lostPackets.push_back(stats.second.lost);
            rtts.push_back(stats.second.rttUs / nSockets);
            sentAckDiffs.push_back(stats.second.sentAckDiffMs / nSockets);
	    tcpInfoAddStats(stats.second);
#endif
	     //str5 = "sent123lost321rtt123";
          *ret = String16(str4.c_str());
          ALOGE("poll TCP socket info[%s]",(char*)ret->string());
        }

    return 0;
}

void TcpSocket2Monitor::updateSocketStats(time_point now, Fwmark mark,
                                         const struct inet_diag_msg *sockinfo,
                                         const struct tcp_info *tcpinfo,
                                         uint32_t tcpinfoLen) NO_THREAD_SAFETY_ANALYSIS {
    int32_t lastAck = TCPINFO_GET(tcpinfo, tcpi_last_ack_recv, tcpinfoLen, 0);
    int32_t lastSent = TCPINFO_GET(tcpinfo, tcpi_last_data_sent, tcpinfoLen, 0);
    TcpStats diff = {
        .sent = TCPINFO_GET(tcpinfo, tcpi_segs_out, tcpinfoLen, 0),
        .lost = TCPINFO_GET(tcpinfo, tcpi_lost, tcpinfoLen, 0),
        .rttUs = TCPINFO_GET(tcpinfo, tcpi_rtt, tcpinfoLen, 0),
        .sentAckDiffMs = lastAck - lastSent,
        .nSockets = 1,
    };

    {
        // Update socket stats with the newest entry, computing the diff w.r.t the previous entry.
        const uint64_t cookie = (static_cast<uint64_t>(sockinfo->id.idiag_cookie[0]) << 32)
                | static_cast<uint64_t>(sockinfo->id.idiag_cookie[1]);
        const SocketEntry previous = mSocketEntries[cookie];
        mSocketEntries[cookie] = {
            .sent = diff.sent,
            .lost = diff.lost,
            .lastUpdate = now,
            .mark = mark,
            .uid = sockinfo->idiag_uid,
        };

        diff.sent -= previous.sent;
        diff.lost -= previous.lost;
    }

    {
        // Aggregate the diff per network id.
        auto& stats = mNetworkStats[mark.netId];
        stats.sent += diff.sent;
        stats.lost += diff.lost;
        stats.rttUs += diff.rttUs;
        stats.sentAckDiffMs += diff.sentAckDiffMs;
        stats.nSockets += diff.nSockets;
    }
}

TcpSocket2Monitor::TcpSocket2Monitor() {

}

TcpSocket2Monitor::~TcpSocket2Monitor() {

}

}  // namespace net
}  // namespace android
