// Redirect ICMP, ARP, and TCP packets to veth0. Pass everything else.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// Replace this with the real ifindex of veth0 (check with: ip link show veth0)
#define VETH_IFINDEX 3   

SEC("xdp")
int xdp_redirect_packets(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = __bpf_ntohs(eth->h_proto);

    // Redirect ARP directly at L2
    if (h_proto == ETH_P_ARP) {
        bpf_printk("Redirecting ARP packet to veth0\n");
        return bpf_redirect(VETH_IFINDEX, 0);
    }

    // Handle IPv4 packets
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // ICMP
        if (ip->protocol == IPPROTO_ICMP) {
            bpf_printk("Redirecting ICMP packet to veth0\n");
            return bpf_redirect(VETH_IFINDEX, 0);
        }

        // TCP
        if (ip->protocol == IPPROTO_TCP) {
            bpf_printk("Redirecting TCP packet to veth0\n");
            return bpf_redirect(VETH_IFINDEX, 0);
        }
    }

    // Everything else passes
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
