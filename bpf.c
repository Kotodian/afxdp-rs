// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (c) 2022 Miguel Guarniz */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPV6_ADDR_LEN 16
#define IPV4_RULE_COUNT 10
#define IPV6_RULE_COUNT 10
#define DEFAULT_QUEUE_IDS 64
#define NOOP 0

struct ip4_addr {
    __be32 saddr;
    __be32 daddr;
};

struct ip6_addr {
    __u8 saddr[16];
    __u8 daddr[16];
};

struct rule {
    __u32 action;
    __u32 quick;
    __u32 proto;
    __be16 sport;
    __be16 dport;

    struct ip4_addr ip4_addr;
    struct ip6_addr ip6_addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, IPV4_RULE_COUNT);
    __type(key, __u32);
    __type(value, struct rule);
} ipv4_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, IPV6_RULE_COUNT);
    __type(key, __u32);
    __type(value, struct rule);
} ipv6_rules SEC(".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_XSKMAP);
  __uint (key_size, sizeof (int));
  __uint (value_size, sizeof (int));
  __uint (max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC (".maps");

struct hdr_cursor {
    void *pos;
};

static int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;

    if (eth + 1 > data_end)
        return -1;

    nh->pos = eth + 1;
    *ethhdr = eth;
    return eth->h_proto;
}

static int parse_ip4hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;

    /* check min hdr size */
    if (hdrsize < sizeof(struct iphdr))
        return -1;

    /* variable-length header */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;
    return iph->protocol;
}

static int parse_udphdr(struct hdr_cursor *nh, void *data_end, struct udphdr **udphdr)
{
    struct udphdr *udph = nh->pos;

    if (udph + 1 > data_end)
        return -1;

    nh->pos = udph + 1;
    *udphdr = udph;
    return 0;
}

static int parse_tcphdr(struct hdr_cursor *nh, void *data_end, struct tcphdr **tcphdr)
{
    struct tcphdr *tcph = nh->pos;
    int hdrsize;

    if (tcph + 1 > data_end)
        return -1;

    hdrsize = tcph->doff * 4;

    if (hdrsize < sizeof(struct tcphdr))
        return -1;

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *tcphdr = tcph;
    return 0;
}

static int get_ipv4_rule(int i, struct rule **rule)
{
    struct rule *res = bpf_map_lookup_elem(&ipv4_rules, &i);
    if (!res)
        return -1;
    *rule = res;
    return 0;
}

static int eval_ipv4_rule(struct rule *rule, struct rule *pack)
{
    return (rule->proto == 0 || rule->proto == pack->proto) &&
           (rule->sport == 0 || rule->sport == pack->sport) &&
           (rule->dport == 0 || rule->dport == pack->dport) &&
           (rule->ip4_addr.saddr == 0 || rule->ip4_addr.saddr == pack->ip4_addr.saddr) &&
           (rule->ip4_addr.daddr == 0 || rule->ip4_addr.daddr == pack->ip4_addr.daddr);

}

static int is_zero(const __u8 a[IPV6_ADDR_LEN])
{
    for (int i = 0; i < IPV6_ADDR_LEN ; i++) {
        if (a[i] != 0)
            return 0;
    }
    return 1;
}

static int equals(__u8 a[IPV6_ADDR_LEN], __u8 b[IPV6_ADDR_LEN])
{
    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

static int eval_rules(int ip_version, struct rule *packet)
{
    struct rule *rule = NULL;
    int action = -1;
    if (ip_version == bpf_htons(ETH_P_IP)) {
        for (int i=0; i < IPV4_RULE_COUNT; i++) {
            if (get_ipv4_rule(i, &rule) < 0) {
                bpf_printk("Error: failed to get rule [index %d]", i);
                return -1;
            }
            if (eval_ipv4_rule(rule, packet)) {
                action = rule->action;
            }
        }
    }
    // if action != 1 then it must have matched a rule
    if (rule && rule->quick && action != -1)
        return action;

    return action;
}

static void print_rule(struct rule *rule)
{
    bpf_printk("action [ %u ] (DROP: 1) (PASS: 2)", rule->action);
    bpf_printk("proto [ %u ]", rule->proto);
    bpf_printk("ports [ src %u ] [ dst %u ]", bpf_ntohs(rule->sport), bpf_ntohs(rule->dport));
    bpf_printk("ipv4 [ src %pI4 ] [ dst %pI4 ]", &(rule->ip4_addr.saddr), &(rule->ip4_addr.daddr));
    bpf_printk("ipv6 [ src %pI6 ]", &rule->ip6_addr.saddr);
    bpf_printk("ipv6 [ dst %pI6 ]", &rule->ip6_addr.daddr);
}

struct
{
  __uint (priority, 10);
  __uint (XDP_PASS, 1);
} XDP_RUN_CONFIG (xdp_pf);

SEC("xdp")
int xdp_pf(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // L2, L3 & L4 structures
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    struct udphdr *udphdr;
    struct tcphdr *tcphdr;

    int action;
    int proto;
    __be16 sport = 0;
    __be16 dport = 0;
    struct ip4_addr ip4 = {0};
    struct ip6_addr ip6 = {0};
    struct hdr_cursor nh = { .pos = data };
    int ip_version = parse_ethhdr(&nh, data_end, &ethhdr);

    // ETH_P_IP(0x0800) and ETH_P_IPV6(0x86DD)
    if (ip_version == bpf_htons(ETH_P_IP)) {
        if ((proto = parse_ip4hdr(&nh, data_end, &iphdr)) < 0)
            goto out;
        ip4.saddr = iphdr->saddr;
        ip4.daddr = iphdr->daddr;
    }

    // parse UDP and tcp
    if (proto == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udphdr) == -1)
            goto out;
        sport = udphdr->source;
        dport = udphdr->dest;
    } else if (proto == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcphdr) == -1)
            goto out;
        sport = tcphdr->source;
        dport = tcphdr->dest;
    }

    // eval packet against rules
    struct rule packet = { NOOP, NOOP, proto, sport, dport, ip4, ip6 };
    if ((action = eval_rules(ip_version ,&packet)) >= 0) {
        // (struct rule) packet has info about (net) packet except action
        // so we add action only for logging purposes
        packet.action = action;
        print_rule(&packet);
        return action;
    }
    out:
    // default action
    return bpf_redirect_map (&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char __license[] SEC("license") = "GPL";

