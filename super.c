/*
 * superblock operations for HAMMER Filesystem
 */

#include <linux/module.h>
#include <linux/fs.h>          /* for BLOCK_SIZE */
#include <linux/version.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/buffer_head.h> /* for sb_bread */

#include "dfly_wrap.h"
#include "hammer2.h"
#include "dfly/vm/vm_extern.h"
#include "dfly/sys/buf.h"
#include "dfly/sys/buf2.h"
#include "dfly/cpu/i386/include/atomic.h"

#include <linux/bitops.h>

#define MNAMELEN 80

/*
 * Flags set by internal operations,
 * but visible to the user.
 * XXX some of these are not quite right.. (I've never seen the root flag set)
 */
#define MNT_LOCAL       0x00001000      /* filesystem is stored locally */
#define MNT_QUOTA       0x00002000      /* quotas are enabled on filesystem */
#define MNT_ROOTFS      0x00004000      /* identifies the root filesystem */
#define MNT_USER        0x00008000      /* mounted by a user */
#define MNT_IGNORE      0x00800000      /* do not show entry in df */

/*
 * External filesystem command modifier flags.
 * Unmount can use the MNT_FORCE flag.
 * XXX These are not STATES and really should be somewhere else.
 */
#define MNT_UPDATE      0x00010000      /* not a real mount, just an update */
#define MNT_DELEXPORT   0x00020000      /* delete export host lists */
#define MNT_RELOAD      0x00040000      /* reload filesystem data */
#define MNT_FORCE       0x00080000      /* force unmount or readonly change */
#define MNT_CMDFLAGS    (MNT_UPDATE|MNT_DELEXPORT|MNT_RELOAD|MNT_FORCE)

/* from vfs/hammer/hammer2_vfsops.c */
struct hammer2_sync_info {
	int error;
	int waitfor;
};

TAILQ_HEAD(hammer2_mntlist, hammer2_mount);
static struct hammer2_mntlist hammer2_mntlist;
static struct lock hammer2_mntlk;

int hammer2_debug;
int hammer2_cluster_enable = 1;
int hammer2_hardlink_enable = 1;
long hammer2_iod_file_read;
long hammer2_iod_meta_read;
long hammer2_iod_indr_read;
long hammer2_iod_file_write;
long hammer2_iod_meta_write;
long hammer2_iod_indr_write;
long hammer2_iod_volu_write;
long hammer2_ioa_file_read;
long hammer2_ioa_meta_read;
long hammer2_ioa_indr_read;
long hammer2_ioa_file_write;
long hammer2_ioa_meta_write;
long hammer2_ioa_indr_write;
long hammer2_ioa_volu_write;


static int hammer2fs_install_volume(struct hammer2_mount *hmp,
					struct super_block *sb);
struct inode *hammer2fs_iget(struct super_block *sb, ino_t ino);
static struct dentry *hammer2fs_mount(struct file_system_type *fs_type,
        		   	int flags, const char *, void *);

extern int get_sb_bdev(struct file_system_type *fs_type,
        int flags, const char *dev_name, void *data,
        int (*fill_super)(struct super_block *, void *, int),
        struct vfsmount *mnt);
int hammer2fs_statfs(struct dentry *, struct kstatfs *);

typedef unsigned long	vm_offset_t;    /* address space bounded offset */
typedef unsigned long	vm_size_t;      /* address space bounded size */


/*
 * Retrieve and reference the file pointer associated with a descriptor.
 *
 * MPSAFE
 */
/*
struct file *
holdfp(struct filedesc *fdp, int fd, int flag)
{
        struct file* fp;

        spin_lock(&fdp->fd_spin);
        if (((u_int)fd) >= fdp->fd_nfiles) {
                fp = NULL;
                goto done;
        }
        if ((fp = fdp->fd_files[fd].fp) == NULL)
                goto done;
        if ((fp->f_flag & flag) == 0 && flag != -1) {
                fp = NULL;
                goto done;
        }
        fhold(fp);
done:
        spin_unlock(&fdp->fd_spin);
        return (fp);
}
*/

/*
 * Calculate the total number of references to a special device.  This
 * routine may only be called for VBLK and VCHR vnodes since v_rdev is
 * an overloaded field.  Since udev2dev can now return NULL, we have
 * to check for a NULL v_rdev.
 */
/*
int
count_dev(cdev_t dev)
{
	struct vnode *vp;
	int count = 0;

	if (SLIST_FIRST(&dev->si_hlist)) {
		lwkt_gettoken(&spechash_token);
		SLIST_FOREACH(vp, &dev->si_hlist, v_cdevnext) {
			count += vp->v_opencount;
		}
		lwkt_reltoken(&spechash_token);
	}
	return(count);
}

int
vcount(struct vnode *vp)
{
	if (vp->v_rdev == NULL)
		return(0);
	return(count_dev(vp->v_rdev));
} */

/*
 * Copies a NUL-terminated string from user space to kernel space.
 * The number of bytes copied, including the terminator, is returned in
 * (*res).
 *
 * Returns 0 on success, EFAULT or ENAMETOOLONG on failure.
 */
int
copyinstr(const void *udaddr, void *kaddr, size_t len, size_t *res)
{
	int error;
	size_t n;
	const char *uptr = udaddr;
	char *kptr = kaddr;

	if (res)
		*res = 0;
	while (len) {
		n = PAGE_SIZE - ((vm_offset_t)uptr & PAGE_MASK);
		if (n > 32)
			n = 32;
		if (n > len)
			n = len;
		if ((error = copyin(uptr, kptr, n)) != 0)
			return(error);
		while (n) {
			if (res)
				++*res;
			if (*kptr == 0)
				return(0);
			++kptr;
			++uptr;
			--n;
			--len;
		}

	}
	return(ENAMETOOLONG);
}

static
int
hammer2_remount(struct mount *mp, char *path, struct vnode *devvp,
                struct ucred *cred)
{
	return (0);
}

/*
 * Support code for hammer2_mount().  Read, verify, and install the volume
 * header into the HMP
 *
 * XXX read four volhdrs and use the one with the highest TID whos CRC
 *     matches.
 *
 * XXX check iCRCs.
 *
 * XXX For filesystems w/ less than 4 volhdrs, make sure to not write to
 *     nonexistant locations.
 *
 * XXX Record selected volhdr and ring updates to each of 4 volhdrs
 */
static
int
hammer2_install_volume_header(hammer2_mount_t *hmp)
{
	hammer2_volume_data_t *vd;
	struct buf *bp;
	hammer2_crc32_t crc0, crc, bcrc0, bcrc;
	int error_reported;
	int error;
	int valid;
	int i;

	error_reported = 0;
	error = 0;
	valid = 0;
	bp = NULL;

	/*
	 * There are up to 4 copies of the volume header (syncs iterate
	 * between them so there is no single master).  We don't trust the
	 * volu_size field so we don't know precisely how large the filesystem
	 * is, so depend on the OS to return an error if we go beyond the
	 * block device's EOF.
	 */
	for (i = 0; i < HAMMER2_NUM_VOLHDRS; i++) {
		error = bread(hmp->devvp, i * HAMMER2_ZONE_BYTES64,
			      HAMMER2_VOLUME_BYTES, &bp);
		if (error) {
			brelse(bp);
			bp = NULL;
			continue;
		}

		vd = (struct hammer2_volume_data *) bp->b_data;
		if ((vd->magic != HAMMER2_VOLUME_ID_HBO) &&
		    (vd->magic != HAMMER2_VOLUME_ID_ABO)) {
			brelse(bp);
			bp = NULL;
			continue;
		}

		if (vd->magic == HAMMER2_VOLUME_ID_ABO) {
			/* XXX: Reversed-endianness filesystem */
			kprintf("hammer2: reverse-endian filesystem detected");
			brelse(bp);
			bp = NULL;
			continue;
		}

		crc = vd->icrc_sects[HAMMER2_VOL_ICRC_SECT0];
		crc0 = hammer2_icrc32(bp->b_data + HAMMER2_VOLUME_ICRC0_OFF,
				      HAMMER2_VOLUME_ICRC0_SIZE);
		bcrc = vd->icrc_sects[HAMMER2_VOL_ICRC_SECT1];
		bcrc0 = hammer2_icrc32(bp->b_data + HAMMER2_VOLUME_ICRC1_OFF,
				       HAMMER2_VOLUME_ICRC1_SIZE);
		if ((crc0 != crc) || (bcrc0 != bcrc)) {
			kprintf("hammer2 volume header crc "
				"mismatch copy #%d\t%08x %08x",
				i, crc0, crc);
			error_reported = 1;
			brelse(bp);
			bp = NULL;
			continue;
		}
		if (valid == 0 || hmp->voldata.mirror_tid < vd->mirror_tid) {
			valid = 1;
			hmp->voldata = *vd;
		}
		brelse(bp);
		bp = NULL;
	}
	if (valid) {
		error = 0;
		if (error_reported)
			kprintf("hammer2: a valid volume header was found\n");
	} else {
		error = EINVAL;
		kprintf("hammer2: no valid volume headers found!\n");
	}
	return (error);
}
/* corresponds to hammer2_vfs_mount */
/*
 * Mount or remount HAMMER2 fileystem from physical media
 *
 *	mountroot
 *		mp		mount point structure
 *		path		NULL
 *		data		<unused>
 *		cred		<unused>
 *
 *	mount
 *		mp		mount point structure
 *		path		path to mount point
 *		data		pointer to argument structure in user space
 *			volume	volume path (device@LABEL form)
 *			hflags	user mount flags
 *		cred		user credentials
 *
 * RETURNS:	0	Success
 *		!0	error number
 */

static int
hammer2fs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct ucred *cred;
	struct mount *mp;
	struct hammer2_mount_info info;
	hammer2_pfsmount_t *pmp;
	hammer2_mount_t *hmp;
	hammer2_key_t lhc;
	struct vnode *devvp;
	struct nlookupdata nd;
	hammer2_chain_t *parent;
	hammer2_chain_t *schain;
	hammer2_chain_t *rchain;
    char devstr[MNAMELEN];

	char *path;
	size_t size;
	size_t done;
	char *dev;
	char *label;
	int ronly = 1;
	int create_hmp;
	int error;
	struct file *file;

	hmp = NULL;
	pmp = NULL;
	dev = NULL;
	label = NULL;
	devvp = NULL;

	kprintf("hammer2_mount\n");

	if (path == NULL) {
		/*
		 * Root mount
		 */
		bzero(&info, sizeof(info));
		info.cluster_fd = -1;
		return (EOPNOTSUPP);
	} else {
		/*
		 * Non-root mount or updating a mount
		 */
		error = copyin(data, &info, sizeof(info));
		if (error)
			return (error);

		error = copyinstr(info.volume, devstr, MNAMELEN - 1, &done);
		if (error)
			return (error);

		/* Extract device and label */
		dev = devstr;
		label = strchr(devstr, '@');
		if (label == NULL ||
		    ((label + 1) - dev) > done) {
			return (EINVAL);
		}
		*label = '\0';
		label++;
		if (*label == '\0')
			return (EINVAL);

		if (mp->mnt_flag & MNT_UPDATE) {
			/* Update mount */
			/* HAMMER2 implements NFS export via mountctl */
			hmp = MPTOHMP(mp);
			devvp = hmp->devvp;
			error = hammer2_remount(mp, path, devvp, cred);
			return error;
		}
	}

	/*
	 * PFS mount
	 *
	 * Lookup name and verify it refers to a block device.
	 */
	error = nlookup_init(&nd, dev, UIO_SYSSPACE, NLC_FOLLOW);
	if (error == 0)
		error = nlookup(&nd);
	if (error == 0)
		error = cache_vref(&nd.nl_nch, nd.nl_cred, &devvp);
	nlookup_done(&nd);

	if (error == 0) {
		if (vn_isdisk(devvp, &error))
			error = vfs_mountedon(devvp);
	}

	/*
	 * Determine if the device has already been mounted.  After this
	 * check hmp will be non-NULL if we are doing the second or more
	 * hammer2 mounts from the same device.
	 */
	lockmgr(&hammer2_mntlk, LK_EXCLUSIVE);
	TAILQ_FOREACH(hmp, &hammer2_mntlist, mntentry) {
		if (hmp->devvp == devvp)
			break;
	}

	/*
	 * Open the device if this isn't a secondary mount
	 */
	if (hmp) {
		create_hmp = 0;
	} else {
		create_hmp = 1;
/* XX vcount
		if (error == 0 && vcount(devvp) > 0)
			error = EBUSY;
*/

		/*
		 * Now open the device
		 */
		if (error == 0) {
			ronly = ((mp->mnt_flag & MNT_RDONLY) != 0);
			vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY);
			error = vinvalbuf(devvp, V_SAVE, 0, 0);
			if (error == 0) {
				error = VOP_OPEN(devvp,
						 ronly ? FREAD : FREAD | FWRITE,
						 FSCRED, NULL);
			}
			vn_unlock(devvp);
		}
		if (error && devvp) {
			vrele(devvp);
			devvp = NULL;
		}
		if (error) {
			lockmgr(&hammer2_mntlk, LK_RELEASE);
			return error;
		}
	}

	/*
	 * Block device opened successfully, finish initializing the
	 * mount structure.
	 *
	 * From this point on we have to call hammer2_unmount() on failure.
	 */
	pmp = kmalloc(sizeof(*pmp), M_HAMMER2, M_WAITOK | M_ZERO);
	mp->mnt_data = (qaddr_t)pmp;
	pmp->mp = mp;
	/* kmalloc_create(&pmp->mmsg, "HAMMER2-pfsmsg"); */
	lockinit(&pmp->msglk, "h2msg", 0, 0);
	TAILQ_INIT(&pmp->msgq);
	RB_INIT(&pmp->staterd_tree);
	RB_INIT(&pmp->statewr_tree);

	if (create_hmp) {
		hmp = kmalloc(sizeof(*hmp), M_HAMMER2, M_WAITOK | M_ZERO);
		hmp->ronly = ronly;
		hmp->devvp = devvp;
/* XX kmalloc create
		kmalloc_create(&hmp->minode, "HAMMER2-inodes");
		kmalloc_create(&hmp->mchain, "HAMMER2-chains");
*/
		TAILQ_INSERT_TAIL(&hammer2_mntlist, hmp, mntentry);
	}
	ccms_domain_init(&pmp->ccms_dom);
	pmp->hmp = hmp;
	pmp->router.pmp = pmp;
	++hmp->pmp_count;
	lockmgr(&hammer2_mntlk, LK_RELEASE);
	kprintf("hammer2_mount hmp=%p pmpcnt=%d\n", hmp, hmp->pmp_count);
	
	mp->mnt_flag = MNT_LOCAL;
	/* mp->mnt_kern_flag |= MNTK_ALL_MPSAFE; */	/* all entry pts are SMP */

	if (create_hmp) {
		/*
		 * vchain setup. vchain.data is special cased to NULL.
		 * vchain.refs is initialized and will never drop to 0.
		 */
		hmp->vchain.refs = 1;
		hmp->vchain.data = (void *)&hmp->voldata;
		hmp->vchain.bref.type = HAMMER2_BREF_TYPE_VOLUME;
		hmp->vchain.bref.data_off = 0 | HAMMER2_PBUFRADIX;
		hmp->vchain.bref_flush = hmp->vchain.bref;
		ccms_cst_init(&hmp->vchain.cst, NULL);
		/* hmp->vchain.u.xxx is left NULL */
		lockinit(&hmp->alloclk, "h2alloc", 0, 0);
		lockinit(&hmp->voldatalk, "voldata", 0, LK_CANRECURSE);

		/*
		 * Install the volume header
		 */
		error = hammer2_install_volume_header(hmp);
		if (error) {
			/* XXX hammer2_vfs_unmount(mp, MNT_FORCE); */
			return error;
		}
	}

	/*
	 * required mount structure initializations
	 */
/* XX statfs fix me
	mp->mnt_stat.f_iosize = HAMMER2_PBUFSIZE;
	mp->mnt_stat.f_bsize = HAMMER2_PBUFSIZE;

	mp->mnt_vstat.f_frsize = HAMMER2_PBUFSIZE;
	mp->mnt_vstat.f_bsize = HAMMER2_PBUFSIZE;
*/
	/*
	 * Optional fields
	 */
	/* mp->mnt_iosize_max = MAXPHYS; */

	/*
	 * First locate the super-root inode, which is key 0 relative to the
	 * volume header's blockset.
	 *
	 * Then locate the root inode by scanning the directory keyspace
	 * represented by the label.
	 */
	if (create_hmp) {
		parent = &hmp->vchain;
		hammer2_chain_lock(hmp, parent, HAMMER2_RESOLVE_ALWAYS);
		schain = hammer2_chain_lookup(hmp, &parent,
				      HAMMER2_SROOT_KEY, HAMMER2_SROOT_KEY, 0);
		hammer2_chain_unlock(hmp, parent);
		if (schain == NULL) {
			kprintf("hammer2_mount: invalid super-root\n");
			/* hammer2_vfs_unmount(mp, MNT_FORCE);
XXX umount */
			return EINVAL;
		}
		hammer2_chain_ref(hmp, schain);	/* for hmp->schain */
		hmp->schain = schain;		/* left locked */
	} else {
		schain = hmp->schain;
		hammer2_chain_lock(hmp, schain, HAMMER2_RESOLVE_ALWAYS);
	}

	parent = schain;
	lhc = hammer2_dirhash(label, strlen(label));
	rchain = hammer2_chain_lookup(hmp, &parent,
				      lhc, lhc + HAMMER2_DIRHASH_LOMASK,
				      0);
	while (rchain) {
		if (rchain->bref.type == HAMMER2_BREF_TYPE_INODE &&
		    rchain->u.ip &&
		    strcmp(label, rchain->data->ipdata.filename) == 0) {
			break;
		}
		rchain = hammer2_chain_next(hmp, &parent, rchain,
					    lhc, lhc + HAMMER2_DIRHASH_LOMASK,
					    0);
	}
	hammer2_chain_unlock(hmp, parent);
	if (rchain == NULL) {
		kprintf("hammer2_mount: PFS label not found\n");
		/* XX hammer2_vfs_unmount(mp, MNT_FORCE);
*/
		return EINVAL;
	}
	if (rchain->flags & HAMMER2_CHAIN_MOUNTED) {
		hammer2_chain_unlock(hmp, rchain);
		kprintf("hammer2_mount: PFS label already mounted!\n");
		/* XX hammer2_vfs_unmount(mp, MNT_FORCE);
*/
		return EBUSY;
	}
	atomic_set_int(&rchain->flags, HAMMER2_CHAIN_MOUNTED);

	hammer2_chain_ref(hmp, rchain);	/* for pmp->rchain */
	hammer2_chain_unlock(hmp, rchain);
	pmp->rchain = rchain;		/* left held & unlocked */
	pmp->iroot = rchain->u.ip;	/* implied hold from rchain */
	pmp->iroot->pmp = pmp;

	kprintf("iroot %p\n", pmp->iroot);

	/*
	 * Ref the cluster management messaging descriptor.  The mount
	 * program deals with the other end of the communications pipe.
	 */
	/* pmp->msg_fp = holdfp(curproc->p_fd, info.cluster_fd, -1); */
/* XX spinlock kernel  
	spin_lock(&files->file_lock);
	pmp->msg_fp = locate_fd(curproc->p_fd, info.cluster_fd, -1); 
*/
	if (pmp->msg_fp == NULL) {
		kprintf("hammer2_mount: bad cluster_fd!\n");
/*
		hammer2_vfs_unmount(mp, MNT_FORCE);
*/
		return EBADF;
	}
/* XX
	lwkt_create(hammer2_cluster_thread_rd, pmp, &pmp->msgrd_td,
		    NULL, 0, -1, "hammer2-msgrd");
	lwkt_create(hammer2_cluster_thread_wr, pmp, &pmp->msgwr_td,
		    NULL, 0, -1, "hammer2-msgwr");
*/
	/*
	 * Finish setup
	 */
	/* vfs_getnewfsid(mp);
	vfs_add_vnodeops(mp, &hammer2_vnode_vops, &mp->mnt_vn_norm_ops);
	vfs_add_vnodeops(mp, &hammer2_spec_vops, &mp->mnt_vn_spec_ops);
	vfs_add_vnodeops(mp, &hammer2_fifo_vops, &mp->mnt_vn_fifo_ops);
*/

	/* copyinstr(info.volume, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, &size);
*/
/*
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
*/

	bzero(mp->mnt_stat.f_mntonname, sizeof(mp->mnt_stat.f_mntonname));
/*
	copyinstr(path, mp->mnt_stat.f_mntonname,
		  sizeof(mp->mnt_stat.f_mntonname) - 1,
		  &size);
*/

	/*
	 * Initial statfs to prime mnt_stat.
	 */
	/* hammer2_vfs_statfs(mp, &mp->mnt_stat, cred);
*/
	return 0;
}

/**
 * Load a HAMMER volume by name.  Returns 0 on success or a positive error
 * code on failure.
 */
/* corresponds to hammer2_install_volume */
static int
hammer2fs_install_volume(struct hammer2_mount *hmp, struct super_block *sb)
{
	struct buffer_head *bh;

	hammer2_volume_data_t *vd;
	struct buf *bp;
	hammer2_crc32_t crc0, crc, bcrc0, bcrc;
	int error_reported;
	int error;
	int valid;
	int i;

	error_reported = 0;
	error = 0;
	valid = 0;
	bp = NULL;

	/*
	 * There are up to 4 copies of the volume header (syncs iterate
	 * between them so there is no single master).  We don't trust the
	 * volu_size field so we don't know precisely how large the filesystem
	 * is, so depend on the OS to return an error if we go beyond the
	 * block device's EOF.
	 */
	for (i = 0; i < HAMMER2_NUM_VOLHDRS; i++) {
		error = bread(hmp->devvp, i * HAMMER2_ZONE_BYTES64,
			      HAMMER2_VOLUME_BYTES, &bp);
		if (error) {
			brelse(bp);
			bp = NULL;
			continue;
		}

		vd = (struct hammer2_volume_data *) bp->b_data;
		if ((vd->magic != HAMMER2_VOLUME_ID_HBO) &&
		    (vd->magic != HAMMER2_VOLUME_ID_ABO)) {
			brelse(bp);
			bp = NULL;
			continue;
		}

		if (vd->magic == HAMMER2_VOLUME_ID_ABO) {
			/* XXX: Reversed-endianness filesystem */
			kprintf("hammer2: reverse-endian filesystem detected");
			brelse(bp);
			bp = NULL;
			continue;
		}

		crc = vd->icrc_sects[HAMMER2_VOL_ICRC_SECT0];
		crc0 = hammer2_icrc32(bp->b_data + HAMMER2_VOLUME_ICRC0_OFF,
				      HAMMER2_VOLUME_ICRC0_SIZE);
		bcrc = vd->icrc_sects[HAMMER2_VOL_ICRC_SECT1];
		bcrc0 = hammer2_icrc32(bp->b_data + HAMMER2_VOLUME_ICRC1_OFF,
				       HAMMER2_VOLUME_ICRC1_SIZE);
		if ((crc0 != crc) || (bcrc0 != bcrc)) {
			kprintf("hammer2 volume header crc "
				"mismatch copy #%d\t%08x %08x",
				i, crc0, crc);
			error_reported = 1;
			brelse(bp);
			bp = NULL;
			continue;
		}
		if (valid == 0 || hmp->voldata.mirror_tid < vd->mirror_tid) {
			valid = 1;
			hmp->voldata = *vd;
		}
		brelse(bp);
		bp = NULL;
	}
	if (valid) {
		error = 0;
		if (error_reported)
			kprintf("hammer2: a valid volume header was found\n");
	} else {
		error = EINVAL;
		kprintf("hammer2: no valid volume headers found!\n");
	}
	return (error);
}

/*
 * Report critical errors.  ip may be NULL.
 */
/* from vfs/hammer/hammer2_vfsops.c */
void
hammer2_critical_error(hammer2_mount_t hmp, hammer2_inode_t ip,
	int error, const char *msg)
{
	printk(KERN_CRIT "HAMMER: Critical error %s\n", msg);
	/* hmp->error = error;
*/
}

static struct dentry *hammer2fs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	/* return get_sb_bdev(fs_type, flags, dev_name, data, */
	return mount_bdev(fs_type, flags, dev_name, data,
				hammer2fs_fill_super);
}

int hammer2fs_statfs(struct dentry *dentry, struct kstatfs *kstatfs)
{
	return -ENOMEM;
}

struct file_system_type hammer2fs_type = {
	.owner    = THIS_MODULE,
	.name     = "hammer2",
/*	.get_sb   = hammer2fs_get_sb, */
     .mount    = hammer2fs_mount,
	.kill_sb  = kill_anon_super,
	.fs_flags = FS_REQUIRES_DEV
};

struct super_operations hammer2fs_super_operations = {
	.statfs  = hammer2fs_statfs
};

/* corresponds to hammer2_vfs_init */
static int __init init_hammer2fs(void)
{
	printk(KERN_INFO "HAMMER2FS version 4 loaded\n");
	return register_filesystem(&hammer2fs_type);
}

static void __exit exit_hammer2fs(void)
{
	unregister_filesystem(&hammer2fs_type);
}

MODULE_DESCRIPTION("HAMMER2 Filesystem");
MODULE_AUTHOR("Matthew Dillon, ");
MODULE_LICENSE("GPL");
module_init(init_hammer2fs)
module_exit(exit_hammer2fs)
