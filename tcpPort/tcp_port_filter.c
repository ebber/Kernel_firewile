#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>

static struct nf_hook_ops nfho;

unsigned int hook_func_tcp_port_filter(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state) {

	struct tcphdr *tcph;

	if (skb) {
		tcph = tcp_hdr(skb);

		if (tcph) {
			// drop packet if destination port is 8888, otherwise
			// keep it
			if (tcph->dest == 0xb822) {
				return NF_DROP;
			} else {
				return NF_ACCEPT;
			}
		}
	}

	// in case skb or tcph is null, keep the packet
	return NF_ACCEPT;
}

int init_module() {
	nfho.hook = hook_func_tcp_port_filter;

	nfho.hooknum = NF_INET_PRE_ROUTING;

	nfho.pf = PF_INET;

	nfho.priority = NF_IP_PRI_FIRST;

	nf_register_net_hook(&init_net, &nfho);

	printk(KERN_INFO "customized tcp port filter loaded.\n");
	return 0;
}

void cleanup_module() {
	printk("customized tcp port filter unloaded\n");
	nf_unregister_net_hook(&init_net, &nfho);
}
