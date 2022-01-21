/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_URL_HELP_H
#define RIST_URL_HELP_H

const char help_urlstr[] = "\nUsage: append to end of individual rist:// url(s) as ?param1=value1&param2=value2...\n"
"  Simple, Main and Advanced Profiles\n"
"    param buffer=###  buffer size in milliseconds\n"
"    param bandwidth=###  max bandwidth in Kbps\n"
"    param return-bandwidth=###  max bandwidth for messaging return in Kbps\n"
"    param reorder-buffer=###  reordering buffer size in ms\n"
"    param cname=abcde  arbitrary name for stream for display in logging\n"
"    param rtt-min=###  minimum expected rtt\n"
"    param rtt-max=###  maximum expected rtt\n"
"    param verbose-level=#  Disable -1; Error 3, Warning 4, Notice 5, Info 6, Debug 7, simulation/dry-run 100\n"
"    param timing-mode=#  0 = RTP Timestamp (defaut); 1 = Arrival Time, 2 = RTP/RTCP Timestamp+NTP\n"
"  Main and Advanced Profiles\n"
"    param aes-type=#  128 = AES-128, 256 = AES-256 must have passphrase too\n"
"    param secret=abcde  encryption passphrase\n"
"    param virt-dst-port destination port inside the GRE header\n"
"    param session-timeout=###  timeout in ms for closing of connection where keep-alive fails\n"
"    param keepalive-interval=###  interval in ms\n"
"    param key-rotation=##  number of IP packets before a key rotation is triggered\n"
"    param congestion-control=#  mitigation mode: (0=disabled, 1=normal, 2=aggressive)\n"
"    param min-retries=##  min retries count before congestion control kicks in\n"
"    param max-retries=##  max retries count\n"
"    param weight=#  default weight for multi-path load balancing. Use 0 for duplicate paths.\n"
"    param username=abcde  Username to identify this peer during authentication\n"
"    param password=abcde  Password corresponding to this peer's Username\n"
"    param mux-mode=#  Controls how rist payload is muxed/demuxed (0=rist/raw, 1=auto-detect, \n"
"                      2=vrt_src_port, 3=ipv4)\n"
"    param mux-filter=#  When using mux-mode=ipv4, this is the string to be used for data filter.\n"
"                        It should be written as destination IP:PORT\n"
"  Advanced Profile\n"
"    param compression=1|0  enable lz4 levels\n"
"\n"
"Usage: append to end of individual udp:// or rtp:// url(s) as ?param1=value1&param2=value2...\n"
"  param miface=(device)  device name (e.g. eth0) for multicast\n"
"  param stream-id=#  ID number (arbitrary) for multiplex/demultiplexing steam in peer connector\n"
"  param rtp-timestamp=#  carry over the timestamp to/from the rtp header into/from rist (0 or 1)\n"
"  param rtp-sequence=#  carry over the sequence number to/from the rtp header into/from rist (0 or 1)\n"
"  param rtp-ptype=# override the default RTP PTYPE to this value\n"
"\n";

#endif
