# Description
This is a reference network performance test tool for vDCM.

It transmits/receives RTP streams to/from the network using standard POSIX socket I/O in a very similar way as the vDCM xgress app.
While the vDCM xgress app is a very feature rich application, this tool is only the very bare minimum to put/get packets to/from the wire.
The source code is small and simple, hence it is a good reference tool to debug the performance of
networks on which vDCM software has to run.

The tool transmits dummy MPEG transport streams (consisting of null packets only) over RTP, which enables 
- packet loss and packet reordering monitoring at the receiver side
- interoperability with vDCM: the receiving side can monitor the output of vDCM and the sending side can feed the input of vDCM
  (for instance in the context of a packet loss investigation).
  
# Build & install

Running "make" in the root directory produces two binaries: rtprx and rtptx.
They can be copied manually to the target, there are no library dependencies.

# Usage

RTP transmit tool:
```
rtptx <locip> <dstip> <dstport0> <#TSs> <TS bitrate (Mbps)>
```
- <locip> is the local IPv4-address to bind to. Use 0.0.0.0 if you don't care.
- <dstip> is the destination IPv4-address to send the RTP streams to. This has to be a valid unicast or multicast address.
- <dstport0> UDP port number of first RTP stream. Second stream gets dstport0 + 1 and so on.
- <#TSs> Number of streams to transmit. Every stream runs in a separate thread.
- <TS bitrate (Mbps)> Bitrate per stream, expressed in Mbps. This bitrate applies to the MPEG stream, i.e. the RTP payload.
  So this does not include the overhead of the RTP header, UDP header, IP header and everything below.
  Streams are always transmitted as 7 MPEG packets per UDP packet, so when converting TS bitrate to wire bitrate, 
  take into account a payload of 7 * 188 bytes per RTP packet.
  
RTP receive tool:
```
rtprx <locip> <dstip> <srcip> <dstport0> <#TSs>
```
- <locip> is the local IPv4-address to bind to. Use 0.0.0.0 if you don't care.
- <dstip> is the destination IPv4-address for multicast streams. When set to any valid multicast address, this multicast group is joined, using IGMP (optionally source specific). Use 0.0.0.0 for unicast streams.
- <srcip> is the source IPv4-address for multicast streams. When multicast is used, this address is used as source address for source specific multicast. Use 0.0.0.0 for unicast streams and non-source specific multicast.
- <dstport0> UDP port number of first RTP stream. Second stream is expected on dstport0 + 1 and so on.
- <#TSs> Number of streams to receive. Every stream runs in a separate thread.

Note: all IP-addresses specified on the command line may be replaced with comma-separated lists (no white space allowed) of any number of IP-addresses.
When multiple addresses are specified, they are applied in a round robin fashion. For instance if "rtptx" is called with locip1,locip2 as first argument,
then the first stream will be bound to locip1, the second to locip2, the third to locip1 again and so on.
This may be necessary to hit performance optimizations such as RSS (Receive Side Scaling).

When these command line tools are invoked, they just keep running until they are interrupted or killed. Their output is an ASCII
table with statistical information that is refreshed regularly, for example:

```
[root@hostA ~]# ./rtptx $(for i in $(seq 124 131); do echo -n 10.8.0.$i,; done) 10.8.6.142 30000 8 1000
```
starts sending RTP streams on hostA: 8 RTP streams of 1000 Mbps each, destination IP=10.8.6.142, source IP=distributed across the comma separated list 10.8.0.124,10.8.0.125,…,10.8.0.131.
It gives output like this:
```
Total TS bitrate: 8000 Mbps.
UDP pkts per second per TS: 94984
Total UDP pkts per second: 759878
Using UDP destination ports 30000 -> 30007.
      port |       sent | rate(Mbps) |    load(%)
==================================================
     30000 |  125310410 |    999.947 |         52
     30001 |  125310410 |    999.947 |         55
     30002 |  125310410 |    999.947 |         52
     30003 |  125310410 |    999.947 |         59
     30004 |  125310410 |    999.947 |         50
     30005 |  125310410 |    999.947 |         51
     30006 |  125310410 |   1000.446 |         55
     30007 |  125310410 |    999.947 |         49
==================================================
     total | 1002483280 |   8000.075 |        423
```

```
[root@hostB ~]# ./rtprx 10.8.6.142 0.0.0.0 0.0.0.0 30000 10
```
starts listening on hostB for RTP streams with destination IP 10.8.6.142, UDP destination port numbers 30000 to 30009.
It gives output like this:
```
      port |      valid |    missing |  reordered |  duplicate |      reset | rate(Mbps)
=========================================================================================
     30000 |    5069813 |          0 |          0 |          0 |          0 |    999.940
     30001 |    5069813 |          0 |          0 |          0 |          0 |   1000.092
     30002 |    5069813 |          0 |          0 |          0 |          0 |    999.940
     30003 |    5069813 |          0 |          0 |          0 |          0 |   1000.092
     30004 |    5069808 |          0 |          0 |          0 |          0 |   1000.124
     30005 |    5069793 |          0 |          0 |          0 |          0 |   1000.034
     30006 |    5069744 |          0 |          0 |          0 |          0 |   1000.050
     30007 |    5069780 |          0 |          0 |          0 |          0 |   1000.203
     30008 |          0 |          0 |          0 |          0 |          0 |      0.000
     30009 |          0 |          0 |          0 |          0 |          0 |      0.000
=========================================================================================
     total |   40558383 |          0 |          0 |          0 |          0 |   8000.475
```
