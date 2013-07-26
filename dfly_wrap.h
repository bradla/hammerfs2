#ifndef _DFLY_WRAP_H
#define _DFLY_WRAP_H

/*
 * Header file providing compability "glue" between
 * DragonFly BSD and Linux: Contains mostly dummy
 * definitions and no-op functions.
 *
 * Use as follows: First include linux headers, then
 * dfly_wrap.h, then dfly headers.
 */

#include <linux/types.h>  // for u_ont32_t, uint64_t
#include <asm/bug.h>      // for BUG_ON
#include <linux/time.h>   // for struct timespec
#include <linux/bio.h>    // for struct bio
#include <linux/kernel.h> // for printk, simple_strtoul
#include <linux/ctype.h>  // for isascii, isdigit, isalpha, isupper, isspace
#include <linux/slab.h>   // for kmalloc
#include <linux/string.h> // for memcmp, memcpy, memset
#include <linux/buffer_head.h> // for brelse
/*#include "dfly/libkern/strtouq.c" */

/*
 * required DragonFly BSD definitions
 */

// indicate we are in kernel
#define _KERNEL 1

// from sys/cdefs.h
#define __unused

#define PRIV_HAMMER_IOCTL        650     /* can hammer_ioctl(). */

// from sys/dirent.h
#define DT_DBF	15		/* database record file*/

// from sys/stat.h
#define S_IFDB	0110000		/* record access file */
#define UF_NOHISTORY    0x00000040      /* do not retain history/snapshots */
#define SF_NOHISTORY    0x00400000      /* do not retain history/snapshots */

/*
 * Flags passed to getblk()
 *
 * GETBLK_PCATCH - Allow signals to be caught.  getblk() is allowed to return
 *                 NULL if this flag is passed.
 *
 * GETBLK_BHEAVY - This is a heavy weight buffer, meaning that resolving
 *                 writes can require additional buffers.
 *
 * GETBLK_SZMATCH- blksize must match pre-existing b_bcount.  getblk() can
 *                 return NULL.
 *
 * GETBLK_NOWAIT - Do not use a blocking lock.  getblk() can return NULL.
 */
#define GETBLK_PCATCH   0x0001  /* catch signals */
#define GETBLK_BHEAVY   0x0002  /* heavy weight buffer */
#define GETBLK_SZMATCH  0x0004  /* pre-existing buffer must match */
#define GETBLK_NOWAIT   0x0008  /* non-blocking */

#define FINDBLK_TEST    0x0010  /* test only, do not lock */
#define FINDBLK_NBLOCK  0x0020  /* use non-blocking lock, can return NULL */
#define FINDBLK_REF     0x0040  /* ref the buf to prevent reuse */

#define B_AGE           0x00000001      /* Reuse more quickly */
#define B_NEEDCOMMIT    0x00000002      /* Append-write in progress. */
#define B_NOTMETA       0x00000004      /* This really isn't metadata */
#define B_DIRECT        0x00000008      /* direct I/O flag (pls free vmio) */
#define B_DEFERRED      0x00000010      /* vfs-controlled deferment */
#define B_CACHE         0x00000020      /* Bread found us in the cache. */
#define B_HASHED        0x00000040      /* Indexed via v_rbhash_tree */
#define B_DELWRI        0x00000080      /* Delay I/O until buffer reused. */
#define B_BNOCLIP       0x00000100      /* EOF clipping b_bcount not allowed */
#define B_HASBOGUS      0x00000200      /* Contains bogus pages */
#define B_EINTR         0x00000400      /* I/O was interrupted */
#define B_ERROR         0x00000800      /* I/O error occurred. */
#define B_IODEBUG       0x00001000      /* (Debugging only bread) */
#define B_INVAL         0x00002000      /* Does not contain valid info. */
#define B_LOCKED        0x00004000      /* Locked in core (not reusable). */
#define B_NOCACHE       0x00008000      /* Destroy buffer AND backing store */
#define B_MALLOC        0x00010000      /* malloced b_data */
#define B_CLUSTEROK     0x00020000      /* Pagein op, so swap() can count it. */
#define B_MARKER        0x00040000      /* Special marker buf in queue */
#define B_RAW           0x00080000      /* Set by physio for raw transfers. */
#define B_HEAVY         0x00100000      /* Heavy-weight buffer */
#define B_DIRTY         0x00200000      /* Needs writing later. */
#define B_RELBUF        0x00400000      /* Release VMIO buffer. */
#define B_UNUSED23      0x00800000      /* Request wakeup on done */
#define B_VNCLEAN       0x01000000      /* On vnode clean list */
#define B_VNDIRTY       0x02000000      /* On vnode dirty list */
#define B_PAGING        0x04000000      /* volatile paging I/O -- bypass VMIO */
#define B_ORDERED       0x08000000      /* Must guarantee I/O ordering */
#define B_RAM           0x10000000      /* Read ahead mark (flag) */
#define B_VMIO          0x20000000      /* VMIO flag */
#define B_CLUSTER       0x40000000      /* pagein op, so swap() can count it */
#define B_VFSFLAG1      0x80000000      /* VFSs can set this flag */


typedef	struct	_uquad	{ u_long val[2]; } u_quad;
typedef	struct	_quad	{   long val[2]; } quad;
typedef	long *	qaddr_t;	/* should be typedef quad * qaddr_t; */
typedef unsigned long long u_quad_t;

/*
 * The vnode is the focus of all file activity in UNIX.
 * There is a unique vnode allocated for each active file,
 * each current directory, each mounted-on file, text file, and the root.
 */

/*
 * vnode types. VNON means no type.
 */
enum vtype 	{ VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD };

/*
 * Vnode tag types.
 * These are for the benefit of external programs only (e.g., pstat)
 * and should NEVER be inspected inside the kernel.
 */
/*
  * Vnode tag types.
  * These are for the benefit of external programs only (e.g., pstat)
  * and should NEVER be inspected by the kernel.
  */
  enum vtagtype   {
           VT_NON, VT_UFS, VT_NFS, VT_MFS, VT_PC, VT_LFS, VT_LOFS, VT_FDESC,
           VT_PORTAL, VT_NULL, VT_UNUSED10, VT_KERNFS, VT_PROCFS, VT_AFS,
           VT_ISOFS, VT_UNION, VT_MSDOSFS, VT_TFS, VT_VFS, VT_CODA, VT_NTFS,
           VT_HPFS, VT_NWFS, VT_SMBFS, VT_UDF, VT_EXT2FS, VT_SYNTH,
           VT_USERFS, VT_HAMMER, VT_DEVFS, VT_TMPFS
   };


/*
 * This defines the maximum size of the private data area
 * permitted for any file system type. A defined constant 
 * is used rather than a union structure to cut down on the
 * number of header files that must be included.
 */
#define	VN_MAXPRIVATE	188

typedef u_int64_t       sysid_t;

/*
* sysref - embedded in resource structures.
*
* NOTE: The cpuid determining which cpu's RB tree the sysref is
* associated with is integrated into the sysref.
*
* NOTE: A resource can be in varying states of construction or
* deconstruction, denoted by having a negative refcnt.  To keep
* performance nominal we reuse sysids that are NOT looked up via
* syslink (meaning we don't have to adjust their location in the
* RB tree).  The objcache is used to cache the RB tree linkage.
*/
struct sysref {
        /* RB_ENTRY(sysref) rbnode; */        /* per-cpu red-black tree node */
        sysid_t sysid;                  /* machine-wide unique sysid */
        int     refcnt;                 /* normal reference count */
        int     flags;
        struct sysref_class *srclass;   /* type of resource and API */
};

/*
 * The vnode infrastructure is being reorgranized.  Most reference-related
 * fields are locked by the BGL, and most file I/O related operations and
 * vnode teardown functions are locked by the vnode lock.
 *
 * File read operations require a shared lock, file write operations require
 * an exclusive lock.  Most directory operations (read or write) currently
 * require an exclusive lock due to the side effects stored in the directory
 * inode (which we intend to fix).
 *
 * File reads and writes are further protected by a range lock.  The intention
 * is to be able to break I/O operations down into more easily managed pieces
 * so vm_page arrays can be passed through rather then UIOs.  This work will
 * occur in multiple stages.  The range locks will also eventually be used to
 * deal with clustered cache coherency issues and, more immediately, to
 * protect operations associated with the kernel-managed journaling module.
 *
 * NOTE: Certain fields within the vnode structure requires v_token to be
 *       held.  The vnode's normal lock need not be held when accessing
 *       these fields as long as the vnode is deterministically referenced
 *       (i.e. can't be ripped out from under the caller).  This is typical
 *       for code paths based on descriptors or file pointers, but not for
 *       backdoor code paths that come in via the buffer cache.
 *
 *      v_rbclean_tree
 *      v_rbdirty_tree
 *      v_rbhash_tree
 *      v_pollinfo
 *
 * NOTE: The vnode operations vector, v_ops, is a double-indirect that
 *       typically points to &v_mount->mnt_vn_use_ops.  We use a double
 *       pointer because mnt_vn_use_ops may change dynamically when e.g.
 *       journaling is turned on or off.
 *
 * NOTE: v_filesize is currently only applicable when a VM object is
 *       associated with the vnode.  Otherwise it will be set to NOOFFSET.
 *
 * NOTE: The following fields require a spin or token lock.  Note that
 *       additional subsystems may use v_token or v_spin for other
 *       purposes, e.g. vfs/fifofs/fifo_vnops.c
 *
 *       v_namecache    v_spin
 *       v_rb*          v_token
 */
RB_HEAD(buf_rb_tree, buf);
RB_HEAD(buf_rb_hash, buf);

struct vnode {
        struct spinlock v_spin;
        int     v_flag;                         /* vnode flags (see below) */
        int     v_writecount;
        int     v_opencount;                    /* number of explicit opens */
        int     v_auxrefs;                      /* auxiliary references */
        struct sysref v_sysref;                 /* normal references */
       /*  struct bio_track v_track_read; */          /* track I/O's in progress */
       /*  struct bio_track v_track_write; */         /* track I/O's in progress */
        struct mount *v_mount;                  /* ptr to vfs we are in */
        struct vop_ops **v_ops;                 /* vnode operations vector */
        /* TAILQ_ENTRY(vnode) v_freelist; */          /* vnode freelist/cachelist */
        /* TAILQ_ENTRY(vnode) v_nmntvnodes; */        /* vnodes for mount point */
        /* struct buf_rb_tree v_rbclean_tree; */      /* RB tree of clean bufs */
        /* struct buf_rb_tree v_rbdirty_tree; */      /* RB tree of dirty bufs */
        /* struct buf_rb_hash v_rbhash_tree; */       /* RB tree general lookup */
       /*  LIST_ENTRY(vnode) v_synclist; */          /* vnodes with dirty buffers */
        enum    vtype v_type;                   /* vnode type */
        union {
                struct socket   *vu_socket;     /* unix ipc (VSOCK) */
                struct {
                        int     vu_umajor;      /* device number for attach */
                        int     vu_uminor;
                        struct cdev     *vu_cdevinfo; /* device (VCHR, VBLK) */
                        /* SLIST_ENTRY(vnode) vu_cdevnext; */
                } vu_cdev;
                struct fifoinfo *vu_fifoinfo;   /* fifo (VFIFO) */
        } v_un;
        off_t   v_filesize;                     /* file EOF or NOOFFSET */
        off_t   v_lazyw;                        /* lazy write iterator */
        off_t   v_lastw;                        /* last write (write cluster) */
        off_t   v_cstart;                       /* start block of cluster */
        off_t   v_lasta;                        /* last allocation */
        int     v_clen;                         /* length of current cluster */
        struct vm_object *v_object;             /* Place to store VM object */
        /* struct  lock v_lock;   */                 /* file/dir ops lock */
       /*  struct  lwkt_token v_token; */             /* (see above) */
        enum    vtagtype v_tag;                 /* type of underlying data */
        void    *v_data;                        /* private data for fs */
        /* struct namecache_list v_namecache; */      /* (S) associated nc entries */
        struct  {
                /* struct  kqinfo vpi_kqinfo; */      /* identity of poller(s) */
        } v_pollinfo;
        struct vmresident *v_resident;          /* optional vmresident */
        struct mount *v_pfsmp;                  /* real mp for pfs/nullfs mt */
#ifdef  DEBUG_LOCKS
        const char *filename;                   /* Source file doing locking */
        int line;                               /* Line number doing locking */
#endif
};

typedef struct uuid uuid_t;
typedef u_int32_t       udev_t;  
/*
 * Vnode attributes.  A field value of VNOVAL represents a field whose value
 * is unavailable (getattr) or which is not to be changed (setattr).
 *
 * Some vattr fields may be wider then what is reported to userland.
 */
struct vattr {
           enum vtype      va_type;        /* vnode type (for create) */
           u_int64_t       va_nlink;       /* number of references to file */
           u_short         va_mode;        /* files access mode and type */
           uid_t           va_uid;         /* owner user id */
           gid_t           va_gid;         /* owner group id */
           udev_t          va_fsid;        /* file system id */
           ino_t           va_fileid;      /* file id */
           u_quad_t        va_size;        /* file size in bytes */
           long            va_blocksize;   /* blocksize preferred for i/o */
           struct timespec va_atime;       /* time of last access */
           struct timespec va_mtime;       /* time of last modification */
           struct timespec va_ctime;       /* time file changed */
           u_int64_t       va_gen;         /* generation number of file */
           u_long          va_flags;       /* flags defined for file */
           int             va_rmajor;      /* device the special file represents */
           int             va_rminor;
           u_quad_t        va_bytes;       /* bytes of disk space held by file */
           u_quad_t        va_filerev;     /* file modification number */
           u_int           va_vaflags;     /* operations flags, see below */
           long            va_spare;       /* remain quad aligned */
           int64_t         va_unused01;
          /* uuid_t          va_uid_uuid; */    /* native uuids if available */
          /* uuid_t          va_gid_uuid; */
          /*  uuid_t          va_fsid_uuid; */
};

/*
* Flags for va_vaflags.
*
* NOTE: The short versions for the uid, gid, and fsid are always populated
* even when the uuid versions are available.
*/
#define VA_UTIMES_NULL 0x0001 /* utimes argument was NULL */
#define VA_EXCLUSIVE 0x0002 /* exclusive create request */
#define VA_UID_UUID_VALID 0x0004 /* uuid fields also populated */
#define VA_GID_UUID_VALID 0x0008 /* uuid fields also populated */
#define VA_FSID_UUID_VALID 0x0010 /* uuid fields also populated */



// from cpu/i386/include/param.h
#define SMP_MAXCPU      16

// from sys/malloc.h
struct malloc_type {
    struct malloc_type *ks_next;    /* next in list */
    long    ks_memuse[SMP_MAXCPU];  /* total memory held in bytes */
    long    ks_loosememuse;         /* (inaccurate) aggregate memuse */
    long    ks_limit;       /* most that are allowed to exist */
    long    ks_size;        /* sizes of this thing that are allocated */
    long    ks_inuse[SMP_MAXCPU]; /* # of allocs currently in use */
    int64_t ks_calls;     /* total packets of this type ever allocated */
    long    ks_maxused;     /* maximum number ever used */
    uint32_t ks_magic;    /* if it's not magic, don't touch it */
    const char *ks_shortdesc;       /* short description */
    uint16_t ks_limblocks; /* number of times blocked for hitting limit */
    uint16_t ks_mapblocks; /* number of times blocked for kernel map */
    long    ks_reserved[4]; /* future use (module compatibility) */
};

#define M_MAGIC         877983977       /* time when first defined :-) */
#define MALLOC_DECLARE(type) \
    extern struct malloc_type type[1]
#define MALLOC_DEFINE(type, shortdesc, longdesc)        \
    struct malloc_type type[1] = {                  \
        { NULL, { 0 }, 0, 0, 0, { 0 }, 0, 0, M_MAGIC, shortdesc, 0, 0 } \
    };
#define M_WAITOK        0x0002  /* wait for resources / alloc from cache */
#define M_ZERO          0x0100  /* bzero() the allocation */
#define M_USE_RESERVE   0x0200  /* can eat into free list reserve */

#define kfree(addr, type) dfly_kfree(addr, type)
#define kmalloc(size, type, flags) dfly_kmalloc(size, type, flags)

MALLOC_DECLARE(M_TEMP);

void dfly_kfree (void *addr, struct malloc_type *type);
void *dfly_kmalloc (unsigned long size, struct malloc_type *type, int flags);

// from sys/ktr.h
#define KTR_INFO_MASTER_EXTERN(master)

// from sys/proc.h
#define PRISON_ROOT     0x1

struct lwp {};

// from sys/thread.h
#define crit_enter()
#define crit_exit()

struct thread {
    struct lwp  *td_lwp;        /* (optional) associated lwp */
};
typedef struct thread *thread_t;

extern int  lwkt_create (void (*func)(void *), void *, struct thread **,
                         struct thread *, int, int, const char *, ...);
extern void lwkt_exit (void);

// from platform/pc32/include/thread.h
#define curthread   ((thread_t)NULL)

// from sys/types.h
typedef u_int32_t udev_t;         /* device number */
typedef uint64_t u_quad_t;        /* quads */

// from sys/param.h
#define MAXBSIZE        65536   /* must be power of 2 */

#define PCATCH          0x00000100      /* tsleep checks signals */

// from sys/time.h
extern time_t   time_second;

struct krate {
    int freq;
    int ticks;
    int count;
};

void getmicrotime (struct timeval *tv);

// from sys/statvfs.h
struct statvfs {
    long    f_blocks;               /* total data blocks in file system */
};

// from sys/buf.h
struct buf {
off_t	b_offset;		/* Offset into file */
					/* Function to call upon completion. */
long	b_resid;		/* Remaining I/O. */
long	b_bufsize;		/* Allocated buffer size. */
int	b_error;		/* Errno value. */
long	b_flags;		/* B_* flags. */
unsigned long    b_bcount;
    caddr_t b_data;                 /* Memory, superblocks, indirect etc. */
};
/* struct vnode;
*/
int bread (struct super_block*, off_t, int, struct buf **);
void bawrite(struct buf *);
void    bqrelse (struct buf *);
#ifndef _LINUX_BUFFER_HEAD_H
void brelse (struct buf *);
#endif
void dfly_brelse (struct buf *);
struct buf_rb_tree {
    void    *rbh_root;
};
int     bd_heatup (void);

// from sys/mount.h
#define MNT_RDONLY      0x00000001      /* read only Filesystem */
#define MNT_WAIT        1       /* synchronously wait for I/O to complete */
#define MNT_NOWAIT      2       /* start all I/O, but do not wait for it */

#define MNAMELEN 80

struct statfs {
    long    f_blocks;               /* total data blocks in file system */
    char    f_mntonname[MNAMELEN];  /* directory on which mounted */
    char    f_mntfromname[MNAMELEN];/* mounted filesystem */
};
struct netexport {};
struct export_args {};
struct mount {
    int mnt_flag;               /* flags shared with user */
    struct statfs   mnt_stat;               /* cache of Filesystem stats */
    struct statvfs  mnt_vstat;              /* extended stats */
    qaddr_t         mnt_data;               /* private data */
  
};

int vfs_mountedon (struct vnode *);    /* is a vfs mounted on vp */

// from sys/uio.h
enum uio_seg {
    UIO_USERSPACE,          /* from user data space */
    UIO_SYSSPACE,           /* from system space */
    UIO_NOCOPY              /* don't copy, already in object */
};

// from sys/vfscache.h
/* struct vattr {};
*/
/*enum vtype { VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VDATABASE };
*/

// from sys/vfsops.h
#define VOP_OPEN(vp, mode, cred, fp)                    \
        vop_open(*(vp)->v_ops, vp, mode, cred, fp)
#define VOP_CLOSE(vp, fflag)                            \
        vop_close(*(vp)->v_ops, vp, fflag)
#define VOP_FSYNC(vp, waitfor)                          \
        vop_fsync(*(vp)->v_ops, vp, waitfor)

struct vop_inactive_args {};
struct vop_reclaim_args {};
struct vop_ops {};
struct ucred;

int vop_open(struct vop_ops *ops, struct vnode *vp, int mode,
             struct ucred *cred, struct file *file);
int vop_close(struct vop_ops *ops, struct vnode *vp, int fflag);
int vop_fsync(struct vop_ops *ops, struct vnode *vp, int waitfor);

// sys/conf.h
#define si_mountpoint   __si_u.__si_disk.__sid_mountpoint

struct cdev {
   union {
        struct {
                struct mount *__sid_mountpoint;
        } __si_disk;
   } __si_u;
};

int count_udev (int x, int y);

// from sys/vnode.h
#define VMSC_GETVP      0x01
#define VMSC_NOWAIT     0x10
#define VMSC_ONEPASS    0x20

#define V_SAVE          0x0001          /* vinvalbuf: sync file first */

#define v_umajor        v_un.vu_cdev.vu_umajor
#define v_uminor        v_un.vu_cdev.vu_uminor
#define v_rdev          v_un.vu_cdev.vu_cdevinfo

#define VINACTIVE       0x04000 /* The vnode is inactive (did VOP_INACTIVE) */


int vinvalbuf (struct vnode *vp, int save, int slpflag, int slptimeo);
int vn_isdisk (struct vnode *vp, int *errp);
int vn_lock (struct vnode *vp, int flags);
void vn_unlock (struct vnode *vp);
void vrele (struct vnode *vp);
int vmntvnodescan(struct mount *mp, int flags,
                  int (*fastfunc)(struct mount *mp, struct vnode *vp, void *data),
                  int (*slowfunc)(struct mount *mp, struct vnode *vp, void *data),
                  void *data);

// from sys/ucred.h
struct ucred {};
#define FSCRED ((struct ucred *)-1)     /* Filesystem credential */

// from sys/namecache.h
struct nchandle {};
int cache_vref(struct nchandle *, struct ucred *, struct vnode **);

// from sys/nlookup.h
#define NLC_FOLLOW              0x00000001      /* follow leaf symlink */

struct nlookupdata {
    struct nchandle nl_nch;         /* start-point and result */
    struct ucred    *nl_cred;       /* credentials for nlookup */
};

int nlookup_init(struct nlookupdata *, const char *, enum uio_seg, int);
int nlookup(struct nlookupdata *);
void nlookup_done(struct nlookupdata *);

// from cpu/*/*/stdarg.h
typedef __builtin_va_list   __va_list;  /* internally known to gcc */
#define __va_start(ap, last) \
        __builtin_va_start(ap, last)
#define __va_end(ap) \
        __builtin_va_end(ap)

// from sys/systm.h
#define KKASSERT(exp) BUG_ON(!(exp))
#define KASSERT(exp,msg) BUG_ON(!(exp))
#define kprintf printk
#define ksnprintf snprintf
#define strtoul simple_strtoul
#define bcopy memcpy
#define bzero(buf, len) memset(buf, 0, len)
void Debugger (const char *msg);
uint32_t crc32(const void *buf, size_t size);
uint32_t crc32_ext(const void *buf, size_t size, uint32_t ocrc);
int tsleep (void *, int, const char *, int);
void wakeup (void *chan);
int copyin (const void *udaddr, void *kaddr, size_t len);
int copyout (const void *kaddr, void *udaddr, size_t len);
u_quad_t strtouq (const char *, char **, int);
int kvprintf (const char *, __va_list);

struct buf *getblk (struct vnode *, off_t, int, int, int);
int     cluster_read (struct vnode *, off_t, off_t, int,
 			size_t, size_t, struct buf **);
static  inline void BUF_KERNPROC(struct buf *bp);
int     cluster_awrite (struct buf *);
void    bdwrite (struct buf *);
struct  file *holdfp (struct filedesc *fdp, int fd, int flag);

 
// from kern/vfs_subr.c
#define KERN_MAXVNODES           5      /* int: max vnodes */

// from sys/sysctl.h
extern int desiredvnodes;

// from sys/errno.h
#define EFTYPE          79              /* Inappropriate file type or format */

// from sys/fcntl.h
#define FREAD           0x0001
#define FWRITE          0x0002

// from sys/lock.h
#define LK_EXCLUSIVE    0x00000002      /* exclusive lock */
#define LK_RETRY        0x00020000 /* vn_lock: retry until locked */

// from sys/libkern.h
#define bcmp(cs, ct, count) memcmp(cs, ct, count)

// from cpu/i386/include/param.h
#define MAXPHYS         (128 * 1024)    /* max raw I/O transfer size */

// from sys/signal2.h
#define CURSIG(lp)              __cursig(lp, 1, 0)
int __cursig(struct lwp *, int, int);

// from sys/buf.h
extern int      hidirtybufspace;

// from sys/kernel.h
extern int hz;                          /* system clock's frequency */

// from sys/iosched.h
void bwillwrite(int bytes);

// from sys/priv.h
#define PRIV_ROOT       1       /* Catch-all during development. */

int priv_check_cred(struct ucred *cred, int priv, int flags);

// from cpu/i386/include/limits.h
#define UQUAD_MAX       ULLONG_MAX      /* max value for a uquad_t */

/*
 * conflicting Linux definitions
 */

// in linux/module.h
#undef LIST_HEAD

// in linux/rbtree.h
#undef RB_BLACK
#undef RB_RED
#undef RB_ROOT

#endif /* _DFLY_WRAP_H */
