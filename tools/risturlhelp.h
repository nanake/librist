/* librist. Copyright 2019-2020 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
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
"  Main and Advanced Profiles\n"
"    param aes-type=#  128 = AES-128, 256 = AES-256 must have passphrase too\n"
"    param secret=abcde  encryption passphrase\n"
"    param virt-dst-port destination port inside the GRE header\n"
"    param session-timeout=###  timeout in ms for closing of connection where keep-alive fails\n"
"    param keepalive-interval=###  interval in ms\n"
"    param key-rotation=##  number of IP packets before a key rotation is triggered\n"
"    param congestion-control=#  mitigation mode: (0=disable, 1=normal, 2=aggressive)\n"
"    param min-retries=##  min retries count before congestion control kicks in\n"
"    param max-retries=##  max retries count\n"
"    param weight=#  default weight for multi-path load balancing. Use 0 for duplicate paths.\n"
"  Advanced Profile\n"
"    param compression=1|0  enable lz4 levels\n"
"\n"
"Usage: append to end of individual udp:// url(s) as ?param1=value1&param2=value2...\n"
"  param miface=(device)  device name (e.g. eth0) for multicast\n"
"  param stream-id=#  ID number (arbitrary) for multiplex/demultiplexing steam in peer connector\n"
"\n";

#endif