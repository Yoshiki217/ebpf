#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

SEC("prog")
int xdp_drop_icmp(struct xdp_md *ctx)
{
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr *eth = data;
  __u16 h_proto;


  if (data + sizeof(*eth) > data_end)
    return XDP_PASS;
    
  h_proto = eth->h_proto;

  if (h_proto == htons(ETH_P_IP))
  {
    return XDP_DROP;
  }

  return XDP_PASS;

}

char _license[] SEC("license") = "GPL";  