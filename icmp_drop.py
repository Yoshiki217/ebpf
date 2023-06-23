#! /usr/bin/pyrhon3

from bcc import BPF
import time

bpf_code = '''
int icmp_drop(struct xdp_md *ctx){
  void* data = (void *)(long)ctx -> data;
  void* data_end = (void *)(long)ctx -> data_end;
  struct ethhdr *eth = data;
  int hdr_size = sizeof(*eth), proto;
  
  if(data + hdr_size > data_end)
    return XDP_PASS;
  if(eth -> h_proto == htones(ETH_P_IP)){
    struct iphdr *iph = data + hdr_size;
    if((void*)&iph[1] > data_end)
    return XDP_PASS;
    
    if(iph -> protocol == 1){
      return XDP_DROP;
    }
  }
  
  return XDP_PASS;
}
'''

bpf = BPF(text = bpf_code)
func = bpf.load_func("icmp_drop", BPF.XDP)

bpf.attach_xdp("lo",func)
print("ICMP Drop")

while True:
  try:
    time.sleep(1)
  except KeyboardInterrupt:
    break

print ("END ICMP Drop")
bpf.remove_xdp("lo")