#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
  void *data = (void *)(unsigned long)skb->data;
  void *data_end = (void *)(unsigned long)skb->data_end;

  // Eth header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  // IP header
  struct iphdr *ip = (struct iphdr *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_SHOT;
  if (ip->protocol != IPPROTO_TCP)
    return TC_ACT_OK;

  // Parse TCP header
  struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
  if ((void *)(tcp + 1) > data_end)
    return TC_ACT_SHOT;

  unsigned int src_ip = ip->saddr;
  unsigned int dst_ip = ip->daddr;
  unsigned short src_port = bpf_ntohs(tcp->source);
  unsigned short dst_port = bpf_ntohs(tcp->dest);
  unsigned char ip_version = ip->version;
  unsigned char byte1 = (src_ip >> 24) & 0xFF;
  unsigned char byte2 = (src_ip >> 16) & 0xFF;
  unsigned char byte3 = (src_ip >> 8) & 0xFF;
  unsigned char byte4 = src_ip & 0xFF;
  unsigned char bytex1 = (dst_ip >> 24) & 0xFF;
  unsigned char bytex2 = (dst_ip >> 16) & 0xFF;
  unsigned char bytex3 = (dst_ip >> 8) & 0xFF;
  unsigned char bytex4 = dst_ip & 0xFF;

  unsigned char flags = tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) |
                        (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5) |
                        (tcp->ece << 6) | (tcp->cwr << 7);

  bpf_printk("Ingress: src_ip=%d.%d.%d.%d, dst_ip=%d.%d.%d.%d,\n src_port=%d, "
             "dst_port=%d, ip_version=%d, TCP flags=0x%x\n",
             byte4, byte3, byte2, byte1, bytex4, bytex3, bytex2, bytex1,
             src_port, dst_port, ip_version, flags);
  if (tcp->urg)
    bpf_printk("URG ");
  if (tcp->ack)
    bpf_printk("ACK ");
  if (tcp->psh)
    bpf_printk("PSH ");
  if (tcp->rst)
    bpf_printk("RST ");
  if (tcp->syn)
    bpf_printk("SYN ");
  if (tcp->fin)
    bpf_printk("FIN ");

  bpf_printk("\n_______________________________________________________________________________________");

  return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
  void *data = (void *)(unsigned long)skb->data;
  void *data_end = (void *)(unsigned long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_SHOT;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  struct iphdr *ip = (struct iphdr *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_SHOT;
  if (ip->protocol != IPPROTO_TCP)
    return TC_ACT_OK;

  struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
  if ((void *)(tcp + 1) > data_end)
    return TC_ACT_SHOT;

  unsigned int src_ip = ip->saddr;
  unsigned int dst_ip = ip->daddr;
  unsigned short src_port = bpf_ntohs(tcp->source);
  unsigned short dst_port = bpf_ntohs(tcp->dest);
  unsigned char ip_version = ip->version;
  unsigned char byte1 = (src_ip >> 24) & 0xFF;
  unsigned char byte2 = (src_ip >> 16) & 0xFF;
  unsigned char byte3 = (src_ip >> 8) & 0xFF;
  unsigned char byte4 = src_ip & 0xFF;
  unsigned char bytex1 = (dst_ip >> 24) & 0xFF;
  unsigned char bytex2 = (dst_ip >> 16) & 0xFF;
  unsigned char bytex3 = (dst_ip >> 8) & 0xFF;
  unsigned char bytex4 = dst_ip & 0xFF;

  unsigned char flags = tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) |
                        (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5) |
                        (tcp->ece << 6) | (tcp->cwr << 7);

  bpf_printk("Egress: src_ip=%d.%d.%d.%d, dst_ip=%d.%d.%d.%d,\n src_port=%d, "
             "dst_port=%d, ip_version=%d, TCP flags=0x%x\n",
             byte4, byte3, byte2, byte1, bytex4, bytex3, bytex2, bytex1,
             src_port, dst_port, ip_version, flags);
  if (tcp->urg)
    bpf_printk("URG ");
  if (tcp->ack)
    bpf_printk("ACK ");
  if (tcp->psh)
    bpf_printk("PSH ");
  if (tcp->rst)
    bpf_printk("RST ");
  if (tcp->syn)
    bpf_printk("SYN ");
  if (tcp->fin)
    bpf_printk("FIN ");

  bpf_printk("\n_______________________________________________________________________________________");

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
