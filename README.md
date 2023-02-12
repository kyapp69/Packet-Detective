# Packet Detective
## Libpcap network sniffer designed for Linux OS

<p align="center">
<img src="demo/demo.gif" width="850">
</p>

## Features 
- Capture network traffic on a chosen interface (or capture on default).
- Get alert if possible login details are found! (non TLS traffic)
- Filter traffic by IP / Protocols / Ports and more!

## Filter examples
```
To get all traffic that involves 1.1.1.1:
host 1.1.1.1

To select all IPv4 traffic between 192.168.1.1 and 192.168.1.7:
ip host 192.168.1.1 and host 192.168.1.7

To select all IPv4 traffic between 192.168.1.1 and any host except 192.168.1.7:
ip host 192.168.1.1 and not host 192.168.1.7

To select all TCP traffic, including port 80 between 192.168.1.1 and 192.168.1.7:
ip host 192.168.1.1 and host 192.168.1.7 and tcp and port 80

To select all UDP traffic with even source ports between 192.168.1.1 and 192.168.1.7 or 192.168.1.6
ip and udp and (host 192.168.1.1 and (host 192.168.1.7) or (host 192.168.1.6)) and (udp[0:2] & 1 = 0)

More at - 
https://www.tcpdump.org/manpages/pcap-filter.7.html
https://www.kaitotek.com/resources/documentation/concepts/packet-filter/pcap-filter-syntax#pcap_filter_syntax

```

