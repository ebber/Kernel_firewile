#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Erik Beitel");
MODULE_DESCRIPTION("A skeleton Linux module for a firewall.");
MODULE_VERSION("0.01");


static struct nf_hook_ops nfho; 

//function to be called by hook
unsigned int hook_func_incoming(void *priv, 
                                struct sk_buff *skb, 
                                const struct nf_hook_state *state)
{
  return NF_DROP;           /* Drop ALL packets */
}

//Called when module loaded using 'insmod'
int init_module()
{
  //function to call when conditions below met
  nfho.hook = hook_func_incoming; 

  //called right after packet received, first hook in Netfilter
  nfho.hooknum = NF_INET_PRE_ROUTING; 
  
  //IPV4 packets
  nfho.pf = PF_INET;                          
  
  //set to highest priority over all other hook functions
  nfho.priority = NF_IP_PRI_FIRST;  
  
  //register hook
  nf_register_net_hook(&nfho);                    
  
  printk(KERN_INFO "simple firewall loaded\n");
  return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{ 
  printk("simple firewall unloaded\n");
  nf_unregister_net_hook(&nfho);                //cleanup and unregister hook
}

//module_init(mod_init);
//module_exit(mod_exit);
