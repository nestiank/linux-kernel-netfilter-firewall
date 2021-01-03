/********
Loadable kernel module for filtering TCP packets
Date: 07 Dec 2020
********/

#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/proc_fs.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/string.h>

#define PROC_DIRNAME "sp2020"
#define PROC_FILENAME_ADD "add"
#define PROC_FILENAME_DEL "del"
#define PROC_FILENAME_SHOW "show"

// Constants
#define PROXY_IP "131.1.1.1"
#define MAX_RULE_SIZE 50
#define REMOVED_RULE 'R'

// Global pointers for module initiation
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file_add;
static struct proc_dir_entry *proc_file_del;
static struct proc_dir_entry *proc_file_show;

// Struct for storing netfilter rules
int rules_index = 0;
struct netfilter_rule {
	int port;
	char rule;
} rules[MAX_RULE_SIZE];

// Address and string mutual conversion functions
static unsigned int as_addr_to_net(char *str) {
	unsigned char addr[4];

	sscanf(str, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);

	return *(unsigned int *)addr;
}
static char *as_net_to_addr(unsigned int addr, char *str) {
	unsigned char addr_cut[4] = {
		((unsigned char*)&addr)[0], ((unsigned char*)&addr)[1],
		((unsigned char*)&addr)[2], ((unsigned char*)&addr)[3]
	};
	
	sprintf(str, "%u.%u.%u.%u", addr_cut[0], addr_cut[1], addr_cut[2], addr_cut[3]);

	return str;
}

// Netfilter hook functions
static unsigned int my_hook_pre(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	char saddr[16], daddr[16];
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int i, check_port = ntohs(th->source);

	// Read rules about proxy requests
	for (i = 0; i < rules_index; i++) {
		if (rules[i].rule == 'P') {
			if (rules[i].port == check_port) {
				// Perform proxy
				ih->daddr = as_addr_to_net(PROXY_IP);
				th->dest = th->source;
				printk(KERN_ALERT "%-15s:%2u, %5d, %5d, %-15s, %-15s, %d, %d, %d, %d\n",
					"PROXY(INBOUND)", ih->protocol, ntohs(th->source), ntohs(th->dest),
					as_net_to_addr(ih->saddr, saddr), as_net_to_addr(ih->daddr, daddr),
					th->syn, th->fin, th->ack, th->rst);

				return NF_ACCEPT;
			}
		}
	}

	// Read rules about inbound packets
	for (i = 0; i < rules_index; i++) {
		if (rules[i].rule == 'I') {
			if (rules[i].port == check_port) {
				// Drop the packet
				printk(KERN_ALERT "%-15s:%2u, %5d, %5d, %-15s, %-15s, %d, %d, %d, %d\n",
					"DROP(INBOUND)", ih->protocol, ntohs(th->source), ntohs(th->dest),
					as_net_to_addr(ih->saddr, saddr), as_net_to_addr(ih->daddr, daddr),
					th->syn, th->fin, th->ack, th->rst);
				
				return NF_DROP;
			}
		}
	}

	// Accept the packet
	printk(KERN_ALERT "%-15s:%2u, %5d, %5d, %-15s, %-15s, %d, %d, %d, %d\n",
		"INBOUND", ih->protocol, ntohs(th->source), ntohs(th->dest),
		as_net_to_addr(ih->saddr, saddr), as_net_to_addr(ih->daddr, daddr),
		th->syn, th->fin, th->ack, th->rst);
	
	return NF_ACCEPT;
}
static unsigned int my_hook_forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	char saddr[16], daddr[16];
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int i, check_port = ntohs(th->dest);

	// Read rules about fowarding-needed packets
	for (i = 0; i < rules_index; i++) {
		if (rules[i].rule == 'F') {
			if (rules[i].port == check_port) {
				// Drop the packet
				printk(KERN_ALERT "%-15s:%2u, %5d, %5d, %-15s, %-15s, %d, %d, %d, %d\n",
					"DROP(FORWARD)", ih->protocol, ntohs(th->source), ntohs(th->dest),
					as_net_to_addr(ih->saddr, saddr), as_net_to_addr(ih->daddr, daddr),
					th->syn, th->fin, th->ack, th->rst);

				return NF_DROP;
			}
		}
	}

	// Accept the packet
	printk(KERN_ALERT "%-15s:%2u, %5d, %5d, %-15s, %-15s, %d, %d, %d, %d\n",
		"FORWARD", ih->protocol, ntohs(th->source), ntohs(th->dest),
		as_net_to_addr(ih->saddr, saddr), as_net_to_addr(ih->daddr, daddr),
		th->syn, th->fin, th->ack, th->rst);
	
	return NF_ACCEPT;
}
static unsigned int my_hook_post(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	char saddr[16], daddr[16];
	struct iphdr *ih = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int i, check_port = ntohs(th->dest);

	// Read rules about outbound packets
	for (i = 0; i < rules_index; i++) {
		if (rules[i].rule == 'O') {
			if (rules[i].port == check_port) {
				// Drop the packet
				printk(KERN_ALERT "%-15s:%2u, %5d, %5d, %-15s, %-15s, %d, %d, %d, %d\n",
					"DROP(OUTBOUND)", ih->protocol, ntohs(th->source), ntohs(th->dest),
					as_net_to_addr(ih->saddr, saddr), as_net_to_addr(ih->daddr, daddr),
					th->syn, th->fin, th->ack, th->rst);

				return NF_DROP;
			}
		}
	}

	// Accept the packet
	printk(KERN_ALERT "%-15s:%2u, %5d, %5d, %-15s, %-15s, %d, %d, %d, %d\n",
		"OUTBOUND", ih->protocol, ntohs(th->source), ntohs(th->dest),
		as_net_to_addr(ih->saddr, saddr), as_net_to_addr(ih->daddr, daddr),
		th->syn, th->fin, th->ack, th->rst);
	
	return NF_ACCEPT;
}

// Global struct for netfilter hook registration
static struct nf_hook_ops my_nf_pre = {
	.hook = my_hook_pre,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops my_nf_forward = {
	.hook = my_hook_forward,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops my_nf_post = {
	.hook = my_hook_post,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST
};

static int my_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "File %s opened.\n", file->f_path.dentry->d_name.name);

	return 0;
}
static ssize_t my_add(struct file *file, const char __user *user_buffer, size_t len, loff_t *pos) {
	char buffer[20];

	// Copy rules from user space to kernel space
	if (copy_from_user(buffer, user_buffer, 20)) {
		return -EFAULT;
	}

	// Add the rule
	if (rules_index < MAX_RULE_SIZE) {
		rules[rules_index].rule = buffer[0];
		sscanf(buffer + 2, "%d", &rules[rules_index].port);
		rules_index++;

		printk(KERN_INFO "Rule added.\n");
	}
	else {
		printk(KERN_INFO "Rule overflow.\n");
	}

	*pos += 20;

	return 20;
}
static ssize_t my_del(struct file *file, const char __user *user_buffer, size_t len, loff_t *pos) {
	char buffer[5];
	int i, index, cnt = 0;

	// Copy rules from user space to kernel space
	if (copy_from_user(buffer, user_buffer, 5)) {
		return -EFAULT;
	}

	sscanf(buffer, "%d", &index);

	// Read rules
	if (index < rules_index) {
		// Find the rule
		for (i = 0; i < rules_index; i++) {
			if (rules[i].rule != 'R') {
				if (cnt == index) {
					rules[i].rule = 'R';
					printk(KERN_INFO "Rule deleted.\n");
					break;
				}
				else {
					cnt++;
				}
			}
		}
		if (i == rules_index) {
			printk(KERN_INFO "Rule with that index does not exist.\n");
		}
	}
	else {
		printk(KERN_INFO "Rule with that index does not exist.\n");
	}

	*pos += 5;

	return 5;
}
static ssize_t my_read(struct file *file, char __user *user_buffer, size_t len, loff_t *pos) {
	int i, cnt = 0;
	int len_sum = 0;
	char temp_buffer[15];
	char buffer[MAX_RULE_SIZE * 15];

	// Quick check for executing this function only once
	if (*pos >= rules_index) {
		printk(KERN_INFO "Rule printed.\n");
		return 0;
	}

	// Read rules
	for (i = 0; i < rules_index; i++) {
		switch(rules[i].rule) {
			case 'I':
			case 'O':
			case 'F':
			case 'P': {
				sprintf(temp_buffer, "%d(%c): %d\n", cnt++, rules[i].rule, rules[i].port);
				strncpy(buffer + len_sum, temp_buffer, strlen(temp_buffer));
				len_sum += strlen(temp_buffer);
				break;
			}
			default: {
				break;
			}
		}
	}

	// Copy rules from kernel space to user space
	if (copy_to_user(user_buffer, buffer, len_sum)) {
		return -EFAULT;
	}

	*pos += rules_index;

	return len_sum;
}

// Global struct for module initiation
static const struct file_operations my_fops_add = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = my_add
};
static const struct file_operations my_fops_del = {
	.owner = THIS_MODULE,
	.open = my_open,
	.write = my_del
};
static const struct file_operations my_fops_show = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = my_read
};

static int __init my_init(void)
{
	// Creating a proc directory and files inside
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	proc_file_add = proc_create(PROC_FILENAME_ADD, 0600, proc_dir, &my_fops_add);
	proc_file_del = proc_create(PROC_FILENAME_DEL, 0600, proc_dir, &my_fops_del);
	proc_file_show = proc_create(PROC_FILENAME_SHOW, 0600, proc_dir, &my_fops_show);

	// For linux kernel version 4.13.0 or above
	nf_register_net_hook(&init_net, &my_nf_pre);
	nf_register_net_hook(&init_net, &my_nf_forward);
	nf_register_net_hook(&init_net, &my_nf_post);

	// Otherwise
	// nf_register_hook(&my_nf_pre);
	// nf_register_hook(&my_nf_forward);
	// nf_register_hook(&my_nf_post);

	printk(KERN_INFO "Project module is now initiated.\n");

	return 0;
}
static void __exit my_exit(void)
{
	// For linux kernel version 4.13.0 or above
	nf_unregister_net_hook(&init_net, &my_nf_pre);
	nf_unregister_net_hook(&init_net, &my_nf_forward);
	nf_unregister_net_hook(&init_net, &my_nf_post);

	// Otherwise
	// nf_unregister_hook(&my_nf_pre);
	// nf_unregister_hook(&my_nf_forward);
	// nf_unregister_hook(&my_nf_post);

	// For linux kernel version 4.0.0 or above
	remove_proc_subtree(PROC_DIRNAME, NULL);

	// Otherwise
	// remove_proc_entry(PROC_FILENAME_ADD, proc_dir);
	// remove_proc_entry(PROC_FILENAME_DEL, proc_dir);
	// remove_proc_entry(PROC_FILENAME_SHOW, proc_dir);
	// remove_proc_entry(PROC_DIRNAME, NULL);

	printk(KERN_INFO "Project module is now gone away.\n");

	return;
}

module_init(my_init);
module_exit(my_exit);

// License information to comply with GPL
MODULE_AUTHOR("System Programming");
MODULE_DESCRIPTION("Course Project LKM");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
