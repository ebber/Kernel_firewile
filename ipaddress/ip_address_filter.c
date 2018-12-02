#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>


static struct nf_hook_ops nfho;

unsigned int hook_func_outgoing(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state) {

	struct iphdr *iph;

	if (skb) {
		iph = ip_hdr(skb);
	
		if (iph) {
			if (iph->daddr == 0x272eeb67) {
				return NF_DROP;
			} else {
				return NF_ACCEPT;
			}
		}
	}

	return NF_ACCEPT;
}

int init_module() {
	nfho.hook = hook_func_outgoing;

	nfho.hooknum = NF_INET_POST_ROUTING;

	nfho.pf = PF_INET;

	nfho.priority = NF_IP_PRI_FIRST;

	nf_register_net_hook(&init_net, &nfho);

	printk(KERN_INFO "customized ip address filter\n");
	return 0;
}

void cleanup_module() {
	printk("customized ip address filter unloaded\n");
	nf_unregister_net_hook(&init_net, &nfho);
}
