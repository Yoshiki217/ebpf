#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/ip.h>

SEC("prog")
int xdp_drop_icmp(struct xdp_md *ctx)
{
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr *eth = data;
  __u16 h_proto;

  if (data + sizeof(*eth) > data_end)
    return XDP_PASS;

  if (eth->h_proto == htons(ETH_P_IP))
  {
    __u16	nhoff;
    struct iphdr *iph = data + nhoff;
    if ((void*)&iph[1] > data_end)
      return XDP_PASS;

    if (iph->protocol == 1) 
    {
      return XDP_DROP;
    }
  }

  return XDP_PASS;

}

char _license[] SEC("license") = "GPL";  