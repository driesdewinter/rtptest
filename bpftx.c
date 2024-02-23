#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("prog")
int handle_packet(struct xdp_md *ctx)
{
  (void)ctx;
  return XDP_PASS;
}

