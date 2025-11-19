#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

// encryption key (in practice, it should be taken from the main module)
static const unsigned char crypto_key[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

// encryption function (encrypts TCP/UDP protocol only)
static __always_inline int encrypt_packet(struct xdp_md* ctx, __u32 offset, __u32 size) {
    // This is just an example idea — in practice we need to use the Crypto API in the kernel
    // which is not possible directly in eBPF. So we just make a simple change
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if (data + offset + size > data_end) return XDP_PASS;

    unsigned char* packet = data + offset;
    for (__u32 i = 0; i < size; i++) {
        packet[i] ^= crypto_key[i % 32]; // Simple XOR — use AES-GCM in practice
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_crypto_func(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end) return XDP_PASS;

        __u32 payload_offset = sizeof(*eth) + (ip->ihl * 4);
        __u32 payload_size = bpf_ntohs(ip->tot_len) - (ip->ihl * 4);

        if (ip->protocol == IPPROTO_TCP) {
            payload_offset += sizeof(struct tcphdr);
            payload_size -= sizeof(struct tcphdr);
        }
        else if (ip->protocol == IPPROTO_UDP) {
            payload_offset += sizeof(struct udphdr);
            payload_size -= sizeof(struct udphdr);
        }
        else {
            return XDP_PASS;
        }

        encrypt_packet(ctx, payload_offset, payload_size);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";