#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/sysrq.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/lglock.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/namei.h>
#include <linux/bitops.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/nsproxy.h>

#define VERSION_STR "0.0.1"

#ifndef CONFIG_X86_64
#error "This code does not support your architecture"
#endif

static char *aclpath __devinitdata = "procprotect";
static struct qstr aclqpath;

module_param(aclpath, charp, 0);
MODULE_PARM_DESC(aclpath, "Root of directory that stores acl tags for /proc files.");

MODULE_AUTHOR("Sapan Bhatia <sapanb@cs.princeton.edu>");
MODULE_DESCRIPTION("Lightweight ACLs for /proc.");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION_STR);

struct procprotect_ctx {
	struct inode **inode;
};

struct acl_entry {
	unsigned int ino;
	struct hlist_node hlist;
};

#define HASH_SIZE (1<<16)

struct hlist_head procprotect_hash[HASH_SIZE];

struct proc_dir_entry *proc_entry;

/*
  Entry point of intercepted call. We need to do two things here:
  - Decide if we need the heavier return hook to be called
  - Save the first argument, which is in a register, for consideration in the return hook
*/
static int do_lookup_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
	int ret = -1;
	struct procprotect_ctx *ctx;
	struct nameidata *nd = (struct nameidata *) regs->di;
	struct qstr *q = (struct qstr *) regs->si;
	struct dentry *parent = nd->path.dentry;
	struct inode *pinode = parent->d_inode;
	
	if (pinode->i_sb->s_magic == PROC_SUPER_MAGIC) {	
		ctx = (struct procprotect_ctx *) ri->data;
		ctx->inode = (struct inode **) regs->cx;
		ret = 0;
	}

	return ret;
}

static int run_acl(unsigned long ino) {
	struct hlist_node *n;
	struct acl_entry *entry;
	hlist_for_each_entry_rcu(entry, 
		n, &procprotect_hash[ino & (HASH_SIZE-1)],
		hlist) {
		if (entry->ino==ino) {
			return 0;
		}
	}
	return 1;
}

/* The entry hook ensures that the return hook is only called for
accesses to /proc */

static int do_lookup_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procprotect_ctx *ctx = (struct procprotect_ctx *) ri->data;
	int ret = regs->ax;
	
	if (ret==0) {
		/* The kernel is going to honor the request. Here's where we step in */
		struct inode *inode = *(ctx->inode);
		//printk(KERN_CRIT "Checking inode %x number %u",inode,inode->i_ino);
		if (!run_acl(inode->i_ino)) {
			if (current->nsproxy->mnt_ns!=init_task.nsproxy->mnt_ns)
				regs->ax = -EPERM;
		}
	}
	
	return 0;
}

static struct kretprobe proc_probe = {
	.entry_handler = (kprobe_opcode_t *) do_lookup_entry,
        .handler = (kprobe_opcode_t *) do_lookup_ret,
	.maxactive = 20,
	.data_size = sizeof(struct procprotect_ctx)
};

static void add_entry(char *pathname) {
	struct path path;
	if (kern_path(pathname, 0, &path)) {
		printk(KERN_CRIT "Path lookup failed for %s",pathname);
	}	
	else {
		unsigned int ino = path.dentry->d_inode->i_ino;
		struct acl_entry *entry;
		entry = kmalloc(GFP_KERNEL, sizeof(struct acl_entry));
		entry->ino = ino;
		
		if (!entry) {
			printk(KERN_CRIT "Could not allocate memory for %s",pathname);
		}
		else {
			if (run_acl(ino)) {
				hlist_add_head_rcu(&entry->hlist,&procprotect_hash[ino&(HASH_SIZE-1)]);
				printk(KERN_CRIT "Added inode %u",ino);
			}
			else {
				printk(KERN_CRIT "Did not add inode %u, already in list", ino);
			}
		}
	}
}


static void __exit procprotect_exit(void)
{
	unregister_kretprobe(&proc_probe);
	struct hlist_node *n;
	struct acl_entry *entry;
	int i;

	for (i=0;i<HASH_SIZE;i++) {
		hlist_for_each_entry_rcu(entry, 
			n, &procprotect_hash[i],
			hlist) {
				kfree(entry);
		}
	}
	
	remove_proc_entry("procprotect",NULL);
	printk("Procprotect: Stopped procprotect.\n");
}



int procfile_write(struct file *file, const char *buffer, unsigned long count, void *data) {		
	char pathname[PATH_MAX];

	if (current->nsproxy->mnt_ns!=init_task.nsproxy->mnt_ns)
		return -EPERM;

	if (copy_from_user(pathname, buffer, count)) {
		return -EFAULT;
	}
	if (count && (pathname[count-1]==10 || pathname[count-1]==13)) {
		pathname[count-1]='\0';
	}
	else
		pathname[count]='\0';
	add_entry(pathname);	
	printk(KERN_CRIT "Length of buffer=%d",strlen(pathname));
	return count;
}

static int __init procprotect_init(void)
{
	printk("Procprotect: starting procprotect version %s with ACLs at path %s.\n",
	       VERSION_STR, aclpath);
	int ret;
	int i;

	for(i=0;i<HASH_SIZE;i++) {
		INIT_HLIST_HEAD(&procprotect_hash[i]);
	}

	  aclqpath.name = aclpath;
	  aclqpath.len = strnlen(aclpath, PATH_MAX);

          proc_probe.kp.addr = 
                  (kprobe_opcode_t *) kallsyms_lookup_name("do_lookup");
          if (!proc_probe.kp.addr) {
                  printk("Couldn't find %s to plant kretprobe\n", "do_execve");
                  return -1;
          }
  
          if ((ret = register_kretprobe(&proc_probe)) <0) {
                  printk("register_kretprobe failed, returned %d\n", ret);
                  return -1;
          }
          printk("Planted kretprobe at %p, handler addr %p\n",
                 proc_probe.kp.addr, proc_probe.handler);

	proc_entry = create_proc_entry("procprotect", 0644, NULL);
	proc_entry->write_proc = procfile_write;
        return ret;
}



module_init(procprotect_init);
module_exit(procprotect_exit);
