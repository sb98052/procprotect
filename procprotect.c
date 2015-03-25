#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/version.h>
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

#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */

#define VERSION_STR "0.0.1"

#ifndef CONFIG_X86_64
#error "This code does not support your architecture"
#endif

static char *aclpath = "procprotect";

static struct qstr aclqpath;

module_param(aclpath, charp, 0);
MODULE_PARM_DESC(aclpath, "Root of directory that stores acl tags for /proc files.");

MODULE_AUTHOR("Sapan Bhatia <sapanb@cs.princeton.edu>");
MODULE_DESCRIPTION("Lightweight ACLs for /proc.");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION_STR);

struct procprotect_ctx {
	struct inode **inode;
	struct qstr *q;
	struct path *path;
	int flags;
};

struct acl_entry {
	unsigned int ino;
	struct hlist_node hlist;
};

/*
   Added by Guilherme Sperb Machado <gsm@machados.org>
   According to recent changes in the kernel, the nameidata struct
   became opaque. So, let's declare it in our implementation.
   Source: https://github.com/torvalds/linux/commit/1f55a6ec940fb45e3edaa52b6e9fc40cf8e18dcb
   */
struct nameidata {
        struct path     path;
        struct qstr     last;
        struct path     root;
        struct inode    *inode; /* path.dentry.d_inode */
        unsigned int    flags;
        unsigned        seq;
        int             last_type;
        unsigned        depth;
        char *saved_names[MAX_NESTED_LINKS + 1];
};

#define HASH_SIZE (1<<10)

struct hlist_head procprotect_hash[HASH_SIZE];

struct proc_dir_entry *proc_entry;

static int run_acl(unsigned long ino) {
	struct acl_entry *entry;
	hlist_for_each_entry_rcu_notrace(entry,
				 &procprotect_hash[ino & (HASH_SIZE-1)],
				 hlist) {
		if (entry->ino==ino) {
			return 0;
		}
	}
	return 1;
}

/*
   Entry point of intercepted call. We need to do two things here:
   - Decide if we need the heavier return hook to be called
   - Save the first argument, which is in a register, for consideration in the return hook
   */
static int lookup_fast_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
	int ret = -1;
	struct procprotect_ctx *ctx;
	struct nameidata *nd = (struct nameidata *) regs->di;
	struct dentry *parent;
	struct inode *pinode;

	if (!nd) return ret;
	parent = nd->path.dentry;

	if (!parent) return ret;
	pinode = parent->d_inode;

	if (!pinode || !pinode->i_sb || !current || !current->nsproxy) return ret;

	if (pinode->i_sb->s_magic == PROC_SUPER_MAGIC
			&& current->nsproxy->mnt_ns!=init_task.nsproxy->mnt_ns) {
		ctx = (struct procprotect_ctx *) ri->data;
		ctx->inode = (struct inode **)regs->dx;
		ctx->flags = nd->flags;
		ret = 0;
	}

	return ret;
}

/* The entry hook ensures that the return hook is only called for
   accesses to /proc */

int printed=0;

static int lookup_fast_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procprotect_ctx *ctx = (struct procprotect_ctx *) ri->data;
	int ret = regs->ax;

	if (ret==0) {
		/* The kernel is going to honor the request. Here's where we step in */
		struct inode *inode = *(ctx->inode);
		if (!run_acl(inode->i_ino)) {
			regs->ax = -EPERM;
		}
	}


	return 0;
}

static int lookup_slow_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
	int ret = -1;
	struct procprotect_ctx *ctx;
	struct nameidata *nd = (struct nameidata *) regs->di;
	struct path *p = (struct path *) regs->si;
	struct dentry *parent;
	struct inode *pinode;

	if (!nd) return ret;
	parent = nd->path.dentry;
	if (!parent) return ret;
	pinode= parent->d_inode;

	if (pinode->i_sb->s_magic == PROC_SUPER_MAGIC
			&& current->nsproxy->mnt_ns!=init_task.nsproxy->mnt_ns) {

		ctx = (struct procprotect_ctx *) ri->data;
		ctx->q = &nd->last;
		ctx->flags = nd->flags;
		ctx->path = p;
		ret = 0;
	}

	return ret;
}

/* The entry hook ensures that the return hook is only called for
   accesses to /proc */

/*static int print_once = 0;*/

static int lookup_slow_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procprotect_ctx *ctx;
	struct inode *inode;
	int ret;

	if (!ri || !ri->data) {return 0;}
	ctx = (struct procprotect_ctx *) ri->data;

	ret = regs->ax;

	if (ret==0) {
		struct path *p = ctx->path;
		if (!p || !p->dentry || !p->dentry->d_inode /* This last check was responsible for the f18 bug*/) {
			return 0;
		}
		inode = p->dentry->d_inode;
		if (!run_acl(inode->i_ino)) {
			regs->ax = -EPERM;
		}
	}

	return 0;
}

struct open_flags {
  int open_flag;
  umode_t mode;
  int acc_mode;
  int intent;
};

static struct file *do_last_probe(struct nameidata *nd, struct path *path, struct file *file,
						 struct open_flags *op, const char *pathname) {
	struct dentry *parent = nd->path.dentry;
	struct inode *pinode = parent->d_inode;
	/*struct qstr *q = &nd->last;*/


	if (pinode->i_sb->s_magic == PROC_SUPER_MAGIC && current->nsproxy->mnt_ns!=init_task.nsproxy->mnt_ns) {
		/*if (!strncmp(q->name,"sysrq-trigger",13)) {
			printk(KERN_CRIT "do_last sysrqtrigger: %d",op->open_flag);
		}*/
		op->open_flag &= ~O_CREAT;
	}
	jprobe_return();
	return file;
}

static struct jprobe dolast_probe = {
	.entry = do_last_probe
};

static struct kretprobe fast_probe = {
	.entry_handler = lookup_fast_entry,
	.handler = lookup_fast_ret,
	.maxactive = 20,
	.data_size = sizeof(struct procprotect_ctx)
};

static struct kretprobe slow_probe = {
	.entry_handler = lookup_slow_entry,
	.handler = lookup_slow_ret,
	.maxactive = 20,
	.data_size = sizeof(struct procprotect_ctx)
};

int once_only = 0;

static int init_probes(void) {
	int ret;
	dolast_probe.kp.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("do_last");

	if (!dolast_probe.kp.addr) {
		printk("Couldn't find %s to plant kretprobe\n", "do_last");
		return -1;
	}

	if ((ret = register_jprobe(&dolast_probe)) <0) {
		printk("register_jprobe failed, returned %u\n", ret);
		return -1;
	}
	fast_probe.kp.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("lookup_fast");

	if (!fast_probe.kp.addr) {
		printk("Couldn't find %s to plant kretprobe\n", "lookup_fast");
		return -1;
	}

	slow_probe.kp.addr =
		(kprobe_opcode_t *) kallsyms_lookup_name("lookup_slow");

	if (!slow_probe.kp.addr) {
		printk("Couldn't find %s to plant kretprobe\n", "lookup_slow");
		return -1;
	}

	if ((ret = register_kretprobe(&fast_probe)) <0) {
		printk("register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	printk("Planted kretprobe at %p, handler addr %p\n",
			fast_probe.kp.addr, fast_probe.handler);

	if ((ret = register_kretprobe(&slow_probe)) <0) {
		printk("register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
	printk("Planted kretprobe at %p, handler addr %p\n",
			slow_probe.kp.addr, slow_probe.handler);
	return 0;
}

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
	struct acl_entry *entry;
	int i;

	unregister_kretprobe(&fast_probe);
	unregister_kretprobe(&slow_probe);
	unregister_jprobe(&dolast_probe);

	for (i=0;i<HASH_SIZE;i++) {
		hlist_for_each_entry_rcu(entry,
				 &procprotect_hash[i],
				 hlist) {
			kfree(entry);
		}
	}

	remove_proc_entry("procprotect",NULL);
	printk("Procprotect: Stopped procprotect.\n");
}



ssize_t procfile_write(struct file *file, const char *buffer, size_t count, loff_t *data) {
	char *pathname;
	pathname = (char *) kmalloc(count, GFP_KERNEL);

	if (!pathname) {
		printk(KERN_CRIT "Could not allocate memory for pathname buffer");
		return -EFAULT;
	}

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

	if (!once_only) {
		once_only=1;
		if (init_probes()==-1)
			printk(KERN_CRIT "Could not install procprotect probes. Reload module to retry.");
	}
	printk(KERN_CRIT "Length of buffer=%d",(int)strlen(pathname));
	kfree(pathname);
	return count;
}

static const struct file_operations procprotect_fops = {
	.owner = THIS_MODULE,
	.write = procfile_write
};


static int __init procprotect_init(void)
{
	int ret = 0;
	int i;

	printk("Procprotect: starting procprotect version %s with ACLs at path %s.\n",
			VERSION_STR, aclpath);

	for(i=0;i<HASH_SIZE;i++) {
		INIT_HLIST_HEAD(&procprotect_hash[i]);
	}

	aclqpath.name = aclpath;
	aclqpath.len = strnlen(aclpath, PATH_MAX);

	proc_entry = proc_create("procprotect", 0644, NULL, &procprotect_fops);

	return ret;
}



module_init(procprotect_init);
module_exit(procprotect_exit);
