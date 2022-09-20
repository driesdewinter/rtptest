#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <asm/byteorder.h>

#include "bpfprog.h"

/* Lesson#1: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
struct bpf_map_def SEC("maps") global_params_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct global_params),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") xsk_map = {
    .type        = BPF_MAP_TYPE_XSKMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(int),
    .max_entries = 1024,  // at least the maximum number of rx queues
};


struct vlanhdr {
  __u16 tag;           ///< 3 bits priority | 1 bit CFI | 12 bit Vlan ID
  __u16 type;          ///< Next EtherType
};

struct depihdr {
  __u32 session_id;        ///< This number is used by the receiving device (RPD) to distinguish the streams (identical to the PORT field when using UDP).
  union
  {
    __u32 sub_layer_header;
    struct
    {
      __u32 x:1;               ///< 1 bit, set to zero (to be ignored by receiver).
      __u32 flow_id:3;          ///< 3 bits, flow identifier.
      __u32 extended_header:2;  ///< 2 bits, Extended Header bits. Set to '00'
      __u32 sequence_bit:1;     ///< 1 bit, Sequence bit. Set to 1 to indicate the Sequence field is valid.
      __u32 vccv:1;            ///< 1 bit, VCCV bit. Set to 0.
      __u32 reserved:8;        ///< 1 byte, Reserved field, set to zero (ignored by receiver).
      __u32 sequence_number:16; ///< 2 bytes, increments by one for each data packet sent. May be used by receiver to detect packet loss.
    };
  };
}; // total depi header length: 8 bytes (=64 bits)

struct rtphdr {
  __u8  csrc_count:4;       ///< Contains the number of CSRC identifiers that follow the SSRC
  __u8  extension:1;       ///< Indicates presence of an extension header between the header and payload data
  __u8  padding:1;         ///< Used to indicate if there are extra padding bytes at the end of the RTP packet
  __u8  version:2;         ///< Indicates the version of the protocol. Current version is 2

  __u8  payload_type:7;     ///< Indicates the format of the payload and thus determines its interpretation by the application
  __u8  marker:1;          ///< If it is set, it means that the current data has some special relevance for the application

  __u16 sequence_number;    ///< The sequence number is incremented for each RTP data packet sent and is to be used by the receiver to detect packet loss and to accommodate out-of-order delivery
  __u32 timestamp;         ///< Used by the receiver to play back the received samples at appropriate time and interval
  __u32 ssrc;              ///< Synchronization source identifier uniquely identifies the source of a stream
}; // total rtp header length: 12 bytes (=96 bits)

static const __u8 IPPROTO_L2TPV3 = 115;

SEC("prog")
int handle_packet(struct xdp_md *ctx)
{
  const void *cur = (const void *)(long)ctx->data;
  const void *end = (const void *)(long)ctx->data_end;

  __u32 mapkey = 0;
  const struct global_params* global_params = bpf_map_lookup_elem(&global_params_map, &mapkey);
  if (!global_params) return XDP_PASS;

  const struct ethhdr* eth = (const struct ethhdr*)cur;
  if (end < cur + sizeof(struct ethhdr)) return XDP_PASS; // too short to hold ethernet header
  cur += sizeof(struct ethhdr);
  __u16 eth_proto = __be16_to_cpu(eth->h_proto);

  if (eth_proto == ETH_P_8021Q)
  {
    const struct vlanhdr* vlan = (const struct vlanhdr*)cur;
    if (end < cur + sizeof(struct vlanhdr)) return XDP_PASS; // too short to hold vlan header
    cur += sizeof(struct vlanhdr);
    eth_proto = __be16_to_cpu(vlan->type);
  }

  __u8 ip_proto = IPPROTO_NONE;

  if (eth_proto == ETH_P_IP)
  {
    const struct iphdr* ip = (const struct iphdr*)cur;
    // check iphdr in two steps: first check fixed iphdr length to make sure that iphdr::ihl points to valid data and then the options.
    if (end < cur + sizeof(struct iphdr)) return XDP_PASS; // too short to hold iphdr
    if (end < cur + ip->ihl * 4) return XDP_PASS; // too short to hold IP options
    cur += ip->ihl * 4;
    if (__be16_to_cpu(ip->frag_off) & 0x1fff) return XDP_PASS; // it's an IP fragment
    ip_proto = ip->protocol;
  }
  else if (eth_proto == ETH_P_IPV6)
  {
    const struct ipv6hdr* ip = (const struct ipv6hdr*)cur;
    if (end < cur + sizeof(struct ipv6hdr)) return XDP_PASS; // too short to hold ip6_hdr
    cur += sizeof(struct ipv6hdr);
    ip_proto = ip->nexthdr;
  }
  else
  {
    return XDP_PASS; // not an IPv4 or IPv6 packet
  }

  if (ip_proto == IPPROTO_UDP)
  {
    const struct udphdr* udp = (const struct udphdr*)cur;
    if (end < cur + sizeof(struct udphdr)) return XDP_PASS; // too short to hold UDP header
    cur += sizeof(struct udphdr);
    __u16 dstport = __be16_to_cpu(udp->dest);
    if (dstport < global_params->udp_lo) return XDP_PASS;
    if (dstport > global_params->udp_hi) return XDP_PASS;
  }
  else if (ip_proto == IPPROTO_L2TPV3)
  {
    if (end < cur + sizeof(struct depihdr)) return XDP_PASS; // too short to hold DEPI header
    cur += sizeof(struct depihdr);
  }
  else
  {
    return XDP_PASS; // not a UDP or DEPI packet
    // If this parse failure happens unexpectedly, it is also possible that an IPv6 extension header is present, which is not supported.
  }

  // TODO DDW quick and dirty video checks

  // this is a video packet
  //return XDP_PASS;
  return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
}
