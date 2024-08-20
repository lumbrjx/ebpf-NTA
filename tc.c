#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    bpf_printk("Packet ingress: ifindex=%d, len=%u\n", skb->ifindex, skb->len);
    return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    bpf_printk("Packet egress: ifindex=%d, len=%u\n", skb->ifindex, skb->len);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

