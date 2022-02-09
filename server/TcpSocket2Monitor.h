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

#ifndef TCP_SOCKET2_MONITOR_H
#define TCP_SOCKET2_MONITOR_H

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
//#include <vector>

//#include <binder/BinderService.h>
//#include "android/net/BnNetd.h"
//#include "android/net/UidRange.h"
#include "Fwmark.h"
#include "utils/String16.h"

struct inet_diag_msg;
struct tcp_info;

namespace android {
namespace net {

using std::chrono::milliseconds;

class TcpSocket2Monitor {
  public:
    using time_point = std::chrono::time_point<std::chrono::steady_clock>;
    // A subset of fields found in struct inet_diag_msg and struct tcp_info.
    struct TcpStats {
        // Number of packets sent. Tracks struct tcp_sock data_segs_out.
        // Not available on 3.18 kernels.
        uint32_t sent;
        // Number of packets lost. Tracks struct tcp_sock lost_out.
        uint32_t lost;
        // Smoothed round trip time. Tracks struct tcp_sock srtt_us.
        uint32_t rttUs;
	// Milliseconds difference between the last packet sent and last ack received.
        int32_t sentAckDiffMs;
        // Number of socket stats aggregated in this TcpStats entry.
        int32_t nSockets;
    };

    // Socket metadata used for computing TcpStats diff across sock_diag dumps.
    struct SocketEntry {
        // Number of packets sent. Tracks struct tcp_sock data_segs_out.
        // Not available on 3.18 kernels.
        uint32_t sent;
        // Number of packets lost. Tracks struct tcp_sock lost_out.
        uint32_t lost;
        // Last update timestamp for that socket.
        time_point lastUpdate;
        // Socket mark.
        Fwmark mark;
        // The uid owning the socket.
        uint32_t uid;
    };

    void tcpInfoAddStats(const TcpSocket2Monitor::TcpStats& stats);
    int getTcpInfo(String16* retStr);
    void updateSocketStats(time_point now, Fwmark mark,
                                          const struct inet_diag_msg *sockinfo,
                                          const struct tcp_info *tcpinfo,
                                          uint32_t tcpinfoLen);
    TcpSocket2Monitor();
    ~TcpSocket2Monitor();

    private:
        std::mutex mLock;
        std::unordered_map<uint64_t, SocketEntry> mSocketEntries GUARDED_BY(mLock);
        std::unordered_map<uint32_t, TcpStats> mNetworkStats GUARDED_BY(mLock);

    // Lock guarding all reads and writes to member variables.
    // Used by the polling thread for sleeping between poll operations.
    // computing diffs between sock_diag dumps. Entries for closed sockets are continously cleaned
    // after every dump operation based on timestamps of last updates.
    // Map of TcpStats entries aggregated per network and keyed per network id.
    // This map tracks per-network data for a single sock_diag dump and is cleared before every dump
    // operation.
};

}  // namespace net
}  // namespace android

#endif /* TCP_SOCKET_MONITOR_H */
