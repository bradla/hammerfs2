/*
 * Copyright (c) 2011-2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 * by Venkatesh Srinivas <vsrinivas@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This header file contains structures used internally by the HAMMERFS
 * implementation.  See hammer_disk.h for on-disk structures.
 */

//#ifndef _HAMMER2_H
//#define _HAMMER2_H

#include <linux/buffer_head.h> // for sb_bread

#include "dfly_wrap.h"

#include "dfly/sys/conf.h"
#include "dfly/sys/systm.h"
#include "dfly/sys/tree.h"
#include "dfly/sys/mountctl.h"
#include "dfly/sys/vnode.h"
#include "dfly/sys/proc.h"
#include "dfly/sys/priv.h"
#include "dfly/sys/globaldata.h"
#include "dfly/sys/lockf.h"
#include "dfly/sys/buf.h"
#include "dfly/sys/ktr.h"
#include "dfly/sys/buf2.h"
#include "dfly/sys/signal2.h"
#include <asm/param.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/mount.h>
#include <linux/stat.h>
#include "dfly/sys/queue.h"
#include "hammer2_disk.h"
#include "hammer2_mount.h"
#include "hammer2_ioctl.h"
#include "lock.h"


#define MOUNTTONULLMOUNT(mp) ((struct null_mount *)((mp)->mnt_data))

/* #if defined(_KERNEL) || defined(_KERNEL_STRUCTURES)
*/
MALLOC_DECLARE(M_HAMMER2);


/*
 * This header file contains structures used internally by the HAMMER2
 * implementation.  See hammer2_disk.h for on-disk structures.
 */
#if !defined(KTR_HAMMER2)
#define KTR_HAMMER	KTR_ALL
#endif
KTR_INFO_MASTER_EXTERN(hammer2);

/*
 * Misc structures
 */
struct hammer2_mount;

typedef struct hammer2_node_locklist *hammer2_node_locklist_t;

/*
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/tree.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/mountctl.h>
#include <sys/priv.h>
#include <sys/stat.h>
#include <sys/thread.h>
#include <sys/globaldata.h>
#include <sys/lockf.h>
#include <sys/buf.h>
#include <sys/queue.h>
#include <sys/limits.h>
#include <sys/buf2.h>
#include <sys/signal2.h>
#include <sys/tree.h>
*/
#include "hammer2_disk.h"
#include "hammer2_mount.h"
#include "hammer2_ioctl.h"
#include "hammer2_ccms.h"
#include "hammer2_network.h"

struct hammer2_chain;

struct hammer2_inode;
struct hammer2_mount;
struct hammer2_pfsmount;
struct hammer2_span;
struct hammer2_state;
struct hammer2_msg;

/*
 * The chain structure tracks blockref recursions all the way to
 * the root volume.  These consist of indirect blocks, inodes,
 * and eventually the volume header.
 *
 * The chain structure is embedded in the hammer2_mount, hammer2_inode,
 * and other system memory structures.  The chain structure typically
 * implements the reference count and busy flag for the larger structure.
 *
 * It is always possible to track a chain element all the way back to the
 * root by following the (parent) links.  (index) is a type-dependent index
 * in the parent indicating where in the parent the chain element resides.
 *
 * When a blockref is added or deleted the related chain element is marked
 * modified and all of its parents are marked SUBMODIFIED (the parent
 * recursion can stop once we hit a node that is already marked SUBMODIFIED).
 * A deleted chain element must remain intact until synchronized against
 * its parent.
 *
 * The blockref at (parent, index) is not adjusted until the modified chain
 * element is flushed and unmarked.  Until then the child's blockref may
 * not match the blockref at (parent, index).
 */

RB_HEAD(hammer2_chain_tree, hammer2_chain);
RB_HEAD(hammer2_state_tree, hammer2_state);
TAILQ_HEAD(flush_deferral_list, hammer2_chain);

struct hammer2_chain {
	ccms_cst_t	cst;			/* attr or data cst */
	struct hammer2_blockref	bref;
	struct hammer2_blockref	bref_flush;	/* synchronized w/MOVED bit */
	struct hammer2_chain	*parent;	/* return chain to root */
	struct hammer2_chain_tree rbhead; 
	struct hammer2_state	*state;		/* if active cache msg */
	RB_ENTRY(hammer2_chain) rbnode;
	TAILQ_ENTRY(hammer2_chain) flush_node;	/* flush deferral list */
	union {
		struct hammer2_inode *ip;
		struct hammer2_indblock *np;
		struct hammer2_data *dp;
		void *mem;
	} u;

	struct buf	*bp;		/* buffer cache (ro) */
	hammer2_media_data_t *data;	/* modified copy of data (rw) */
	u_int		bytes;		/* physical size of data */
	int		index;		/* index in parent */
	u_int		refs;
	u_int		flags;
};

typedef struct hammer2_chain hammer2_chain_t;

int hammer2_chain_cmp(hammer2_chain_t *chain1, hammer2_chain_t *chain2);
RB_PROTOTYPE(hammer2_chain_tree, hammer2_chain, rbnode, hammer2_chain_cmp);

/*
 * MOVED - This bit is set during the flush when the MODIFIED bit is cleared,
 *	   indicating that the parent's blocktable must inherit a change to
 *	   the bref (typically a block reallocation)
 *
 *	   It must also be set in situations where a chain is not MODIFIED
 *	   but whos bref has changed (typically due to fields other than
 *	   a block reallocation).
 */
#define HAMMER2_CHAIN_MODIFIED		0x00000001	/* active mods */
#define HAMMER2_CHAIN_DIRTYEMBED	0x00000002	/* inode embedded */
#define HAMMER2_CHAIN_DIRTYBP		0x00000004	/* dirty on unlock */
#define HAMMER2_CHAIN_SUBMODIFIED	0x00000008	/* 1+ subs modified */
#define HAMMER2_CHAIN_DELETED		0x00000010
#define HAMMER2_CHAIN_INITIAL		0x00000020	/* initial create */
#define HAMMER2_CHAIN_FLUSHED		0x00000040	/* flush on unlock */
#define HAMMER2_CHAIN_MOVED		0x00000080	/* bref changed */
#define HAMMER2_CHAIN_IOFLUSH		0x00000100	/* bawrite on put */
#define HAMMER2_CHAIN_DEFERRED		0x00000200	/* on a deferral list*/
#define HAMMER2_CHAIN_DESTROYED		0x00000400	/* destroying */
#define HAMMER2_CHAIN_MODIFIED_AUX	0x00000800	/* hmp->vchain only */
#define HAMMER2_CHAIN_MODIFY_TID	0x00001000	/* mod updates field */
#define HAMMER2_CHAIN_MOUNTED		0x00002000	/* PFS is mounted */

/*
 * Flags passed to hammer2_chain_lookup() and hammer2_chain_next()
 */
#define HAMMER2_LOOKUP_NOLOCK		0x00000001	/* ref only */
#define HAMMER2_LOOKUP_NODATA		0x00000002	/* data left NULL */
#define HAMMER2_LOOKUP_SHARED		0x00000100

/*
 * Flags passed to hammer2_chain_modify() and hammer2_chain_resize()
 *
 * NOTE: OPTDATA allows us to avoid instantiating buffers for INDIRECT
 *	 blocks in the INITIAL-create state.
 *
 * NOTE: NO_MODIFY_TID tells the function to not set HAMMER2_CHAIN_MODIFY_TID
 *	 when marking the chain modified (used when a sub-chain modification
 *	 propagates upward).
 */
#define HAMMER2_MODIFY_NOSUB		0x00000001	/* do not set SUBMOD */
#define HAMMER2_MODIFY_OPTDATA		0x00000002	/* data can be NULL */
#define HAMMER2_MODIFY_NO_MODIFY_TID	0x00000004

/*
 * Flags passed to hammer2_chain_lock()
 */
#define HAMMER2_RESOLVE_NEVER		1
#define HAMMER2_RESOLVE_MAYBE		2
#define HAMMER2_RESOLVE_ALWAYS		3
#define HAMMER2_RESOLVE_MASK		0x0F

#define HAMMER2_RESOLVE_SHARED		0x10

/*
 * Cluster different types of storage together for allocations
 */
#define HAMMER2_FREECACHE_INODE		0
#define HAMMER2_FREECACHE_INDIR		1
#define HAMMER2_FREECACHE_DATA		2
#define HAMMER2_FREECACHE_UNUSED3	3
#define HAMMER2_FREECACHE_TYPES		4

/*
 * BMAP read-ahead maximum parameters
 */
#define HAMMER2_BMAP_COUNT		16	/* max bmap read-ahead */
#define HAMMER2_BMAP_BYTES		(HAMMER2_PBUFSIZE * HAMMER2_BMAP_COUNT)

/*
 * Misc
 */
#define HAMMER2_FLUSH_DEPTH_LIMIT	40	/* stack recursion limit */

/*
 * HAMMER2 IN-MEMORY CACHE OF MEDIA STRUCTURES
 *
 * There is an in-memory representation of all on-media data structure.
 *
 * When accessed read-only the data will be mapped to the related buffer
 * cache buffer.
 *
 * When accessed read-write (marked modified) a kmalloc()'d copy of the
 * is created which can then be modified.  The copy is destroyed when a
 * filesystem block is allocated to replace it.
 *
 * Active inodes (those with vnodes attached) will maintain the kmalloc()'d
 * copy for both the read-only and the read-write case.  The combination of
 * (bp) and (data) determines whether (data) was allocated or not.
 *
 * The in-memory representation may remain cached (for example in order to
 * placemark clustering locks) even after the related data has been
 * detached.
 */

/*
 * A hammer2 inode.
 *
 * NOTE: The inode's attribute CST which is also used to lock the inode
 *	 is embedded in the chain (chain.cst) and aliased w/ attr_cst.
 */
struct hammer2_inode {
	struct hammer2_mount	*hmp;		/* Global mount */
	struct hammer2_pfsmount	*pmp;		/* PFS mount */
	struct hammer2_inode	*pip;		/* parent inode */
	struct vnode		*vp;
	ccms_cst_t		topo_cst;	/* directory topology cst */
	hammer2_chain_t		chain;
	struct hammer2_inode_data ip_data;
	struct lockf		advlock;
	u_int			depth;		/* directory depth */
	hammer2_off_t		delta_dcount;	/* adjust data_count */
	hammer2_off_t		delta_icount;	/* adjust inode_count */
};

typedef struct hammer2_inode hammer2_inode_t;

/*
 * A hammer2 indirect block
 */
struct hammer2_indblock {
	hammer2_chain_t		chain;
};

typedef struct hammer2_indblock hammer2_indblock_t;

/*
 * A hammer2 data block
 */
struct hammer2_data {
	hammer2_chain_t		chain;
};

typedef struct hammer2_data hammer2_data_t;

struct hammer2_freecache {
	hammer2_off_t	bulk;
	hammer2_off_t	single;
};

typedef struct hammer2_freecache hammer2_freecache_t;

/*
 * Structure used to represent a virtual circuit for a messaging
 * route.  Typically associated from hammer2_state but the hammer2_pfsmount
 * structure also has one to represent the point-to-point link.
 */
struct hammer2_router {
	struct hammer2_pfsmount *pmp;
	struct hammer2_state	*state;		/* received LNK_SPAN state */
	uint64_t		target;		/* target */
};

typedef struct hammer2_router hammer2_router_t;

/*
 * Global (per device) mount structure for device (aka vp->v_mount->hmp)
 */
struct hammer2_mount {
	struct vnode	*devvp;		/* device vnode */
	int		ronly;		/* read-only mount */
	int		pmp_count;	/* PFS mounts backed by us */
	TAILQ_ENTRY(hammer2_mount) mntentry; /* hammer2_mntlist */

	struct malloc_type *minode;
	int 		ninodes;
	int 		maxinodes;

	struct malloc_type *mchain;
	int		nipstacks;
	int		maxipstacks;
	hammer2_chain_t vchain;		/* anchor chain */
	hammer2_chain_t *schain;	/* super-root */
	struct lock	alloclk;	/* lockmgr lock */
	struct lock	voldatalk;	/* lockmgr lock */

	hammer2_volume_data_t voldata;
	hammer2_freecache_t freecache[HAMMER2_FREECACHE_TYPES]
				     [HAMMER2_MAX_RADIX+1];
};

typedef struct hammer2_mount hammer2_mount_t;

/*
 * Per-PFS mount structure for device (aka vp->v_mount)
 */
struct hammer2_pfsmount {
	struct mount		*mp;		/* kernel mount */
	struct hammer2_mount	*hmp;		/* device global mount */
	hammer2_chain_t 	*rchain;	/* PFS root chain */
	hammer2_inode_t		*iroot;		/* PFS root inode */
	struct malloc_type	*mmsg;
	ccms_domain_t		ccms_dom;
	struct netexport	export;		/* nfs export */
	int			ronly;		/* read-only mount */
	struct file		*msg_fp;	/* cluster pipe->userland */
	thread_t		msgrd_td;	/* cluster thread */
	thread_t		msgwr_td;	/* cluster thread */
	int			msg_ctl;	/* wakeup flags */
	int			msg_seq;	/* cluster msg sequence id */
	uint32_t		reserved01;
	struct lock		msglk;		/* lockmgr lock */
	TAILQ_HEAD(, hammer2_msg) msgq;		/* transmit queue */
	struct hammer2_state	*conn_state;	/* active LNK_CONN state */
	struct hammer2_state	*freerd_state;	/* allocation cache */
	struct hammer2_state	*freewr_state;	/* allocation cache */
	struct hammer2_state_tree staterd_tree;	/* active messages */
	struct hammer2_state_tree statewr_tree;	/* active messages */
	struct hammer2_router	router;
};

typedef struct hammer2_pfsmount hammer2_pfsmount_t;

/*
 * msg_ctl flags (atomic)
 */
#define HAMMER2_CLUSTERCTL_KILL		0x00000001
#define HAMMER2_CLUSTERCTL_KILLRX	0x00000002 /* staged helper exit */
#define HAMMER2_CLUSTERCTL_KILLTX	0x00000004 /* staged helper exit */
#define HAMMER2_CLUSTERCTL_SLEEPING	0x00000008 /* interlocked w/msglk */

/*
 * Transactional state structure, representing an open transaction.  The
 * transaction might represent a cache state (and thus have a chain
 * association), or a VOP op, LNK_SPAN, or other things.
 */
struct hammer2_state {
	RB_ENTRY(hammer2_state) rbnode;		/* indexed by msgid */
	struct hammer2_pfsmount	*pmp;
	struct hammer2_router *router;		/* related LNK_SPAN route */
	uint32_t	txcmd;			/* mostly for CMDF flags */
	uint32_t	rxcmd;			/* mostly for CMDF flags */
	uint64_t	msgid;			/* {spanid,msgid} uniq */
	int		flags;
	int		error;
	struct hammer2_chain *chain;		/* msg associated w/chain */
	struct hammer2_msg *msg;
	int (*func)(struct hammer2_state *, struct hammer2_msg *);
	union {
		void *any;
		hammer2_pfsmount_t *pmp;
	} any;
};

#define HAMMER2_STATE_INSERTED	0x0001
#define HAMMER2_STATE_DYNAMIC	0x0002
#define HAMMER2_STATE_DELPEND	0x0004		/* transmit delete pending */

struct hammer2_msg {
	TAILQ_ENTRY(hammer2_msg) qentry;	/* serialized queue */
	struct hammer2_router *router;
	struct hammer2_state *state;
	size_t		hdr_size;
	size_t		aux_size;
	char		*aux_data;
	hammer2_msg_any_t any;
};

typedef struct hammer2_link hammer2_link_t;
typedef struct hammer2_state hammer2_state_t;
typedef struct hammer2_msg hammer2_msg_t;

int hammer2_state_cmp(hammer2_state_t *state1, hammer2_state_t *state2);
RB_PROTOTYPE(hammer2_state_tree, hammer2_state, rbnode, hammer2_state_cmp);

typedef struct hammer2_node	*hammer2_node_t;

/* #if defined(_KERNEL)
*/

MALLOC_DECLARE(M_HAMMER2);

#define VTOI(vp)	((hammer2_inode_t *)(vp)->v_data)
#define ITOV(ip)	((ip)->vp)

static __inline
hammer2_pfsmount_t *
MPTOPMP(struct mount *mp)
{
	return ((hammer2_pfsmount_t *)mp->mnt_data);
}

static __inline
hammer2_mount_t *
MPTOHMP(struct mount *mp)
{
	return (((hammer2_pfsmount_t *)mp->mnt_data)->hmp);
}

extern struct vop_ops hammer2_vnode_vops;
extern struct vop_ops hammer2_spec_vops;
extern struct vop_ops hammer2_fifo_vops;

extern int hammer2_debug;
extern int hammer2_cluster_enable;
extern int hammer2_hardlink_enable;
extern long hammer2_iod_file_read;
extern long hammer2_iod_meta_read;
extern long hammer2_iod_indr_read;
extern long hammer2_iod_file_write;
extern long hammer2_iod_meta_write;
extern long hammer2_iod_indr_write;
extern long hammer2_iod_volu_write;
extern long hammer2_ioa_file_read;
extern long hammer2_ioa_meta_read;
extern long hammer2_ioa_indr_read;
extern long hammer2_ioa_file_write;
extern long hammer2_ioa_meta_write;
extern long hammer2_ioa_indr_write;
extern long hammer2_ioa_volu_write;

/*
 * hammer2_subr.c
 */
void hammer2_inode_lock_ex(hammer2_inode_t *ip);
void hammer2_inode_unlock_ex(hammer2_inode_t *ip);
void hammer2_inode_lock_sh(hammer2_inode_t *ip);
void hammer2_inode_unlock_sh(hammer2_inode_t *ip);
void hammer2_inode_busy(hammer2_inode_t *ip);
void hammer2_inode_unbusy(hammer2_inode_t *ip);
void hammer2_voldata_lock(hammer2_mount_t *hmp);
void hammer2_voldata_unlock(hammer2_mount_t *hmp);

void hammer2_mount_exlock(hammer2_mount_t *hmp);
void hammer2_mount_shlock(hammer2_mount_t *hmp);
void hammer2_mount_unlock(hammer2_mount_t *hmp);

int hammer2_get_dtype(hammer2_inode_t *ip);
int hammer2_get_vtype(hammer2_inode_t *ip);
u_int8_t hammer2_get_obj_type(enum vtype vtype);
void hammer2_time_to_timespec(u_int64_t xtime, struct timespec *ts);
u_int64_t hammer2_timespec_to_time(struct timespec *ts);
u_int32_t hammer2_to_unix_xid(uuid_t *uuid);
void hammer2_guid_to_uuid(uuid_t *uuid, u_int32_t guid);

hammer2_key_t hammer2_dirhash(const unsigned char *name, size_t len);
int hammer2_bytes_to_radix(size_t bytes);

int hammer2_calc_logical(hammer2_inode_t *ip, hammer2_off_t uoff,
			 hammer2_key_t *lbasep, hammer2_key_t *leofp);
void hammer2_update_time(uint64_t *timep);

/*
 * hammer2_inode.c
 */
struct vnode *hammer2_igetv(hammer2_inode_t *ip, int *errorp);

void hammer2_inode_lock_nlinks(hammer2_inode_t *ip);
void hammer2_inode_unlock_nlinks(hammer2_inode_t *ip);
hammer2_inode_t *hammer2_inode_alloc(hammer2_pfsmount_t *pmp, void *data);
void hammer2_inode_free(hammer2_inode_t *ip);
void hammer2_inode_ref(hammer2_inode_t *ip);
void hammer2_inode_drop(hammer2_inode_t *ip);
int hammer2_inode_calc_alloc(hammer2_key_t filesize);

int hammer2_inode_create(hammer2_inode_t *dip,
			struct vattr *vap, struct ucred *cred,
			const uint8_t *name, size_t name_len,
			hammer2_inode_t **nipp);

int hammer2_inode_duplicate(hammer2_inode_t *dip,
			hammer2_inode_t *oip, hammer2_inode_t **nipp,
			const uint8_t *name, size_t name_len);
int hammer2_inode_connect(hammer2_inode_t *dip, hammer2_inode_t *oip,
			const uint8_t *name, size_t name_len);

int hammer2_unlink_file(hammer2_inode_t *dip,
			const uint8_t *name, size_t name_len,
			int isdir, hammer2_inode_t *retain_ip);
int hammer2_hardlink_consolidate(hammer2_inode_t **ipp, hammer2_inode_t *tdip);
int hammer2_hardlink_deconsolidate(hammer2_inode_t *dip,
			hammer2_chain_t **chainp, hammer2_inode_t **ipp);
int hammer2_hardlink_find(hammer2_inode_t *dip, hammer2_chain_t **chainp,
			hammer2_inode_t **ipp);

/*
 * hammer2_chain.c
 */
void hammer2_modify_volume(hammer2_mount_t *hmp);
hammer2_chain_t *hammer2_chain_alloc(hammer2_mount_t *hmp,
				hammer2_blockref_t *bref);
void hammer2_chain_free(hammer2_mount_t *hmp, hammer2_chain_t *chain);
void hammer2_chain_ref(hammer2_mount_t *hmp, hammer2_chain_t *chain);
void hammer2_chain_drop(hammer2_mount_t *hmp, hammer2_chain_t *chain);
int hammer2_chain_lock(hammer2_mount_t *hmp, hammer2_chain_t *chain, int how);
void hammer2_chain_moved(hammer2_mount_t *hmp, hammer2_chain_t *chain);
void hammer2_chain_modify(hammer2_mount_t *hmp, hammer2_chain_t *chain,
				int flags);
void hammer2_chain_resize(hammer2_inode_t *ip, hammer2_chain_t *chain,
				int nradix, int flags);
void hammer2_chain_unlock(hammer2_mount_t *hmp, hammer2_chain_t *chain);
hammer2_chain_t *hammer2_chain_find(hammer2_mount_t *hmp,
				hammer2_chain_t *parent, int index);
hammer2_chain_t *hammer2_chain_get(hammer2_mount_t *hmp,
				hammer2_chain_t *parent,
				int index, int flags);
hammer2_chain_t *hammer2_chain_lookup(hammer2_mount_t *hmp,
				hammer2_chain_t **parentp,
				hammer2_key_t key_beg, hammer2_key_t key_end,
				int flags);
hammer2_chain_t *hammer2_chain_next(hammer2_mount_t *hmp,
				hammer2_chain_t **parentp,
				hammer2_chain_t *chain,
				hammer2_key_t key_beg, hammer2_key_t key_end,
				int flags);
hammer2_chain_t *hammer2_chain_create(hammer2_mount_t *hmp,
				hammer2_chain_t *parent,
				hammer2_chain_t *chain,
				hammer2_key_t key, int keybits,
				int type, size_t bytes);
void hammer2_chain_delete(hammer2_mount_t *hmp, hammer2_chain_t *parent,
				hammer2_chain_t *chain, int retain);
void hammer2_chain_flush(hammer2_mount_t *hmp, hammer2_chain_t *chain,
				hammer2_tid_t modify_tid);
void hammer2_chain_commit(hammer2_mount_t *hmp, hammer2_chain_t *chain);

/*
 * hammer2_ioctl.c
 */
int hammer2_ioctl(hammer2_inode_t *ip, u_long com, void *data,
				int fflag, struct ucred *cred);

/*
 * hammer2_msg.c
 */
int hammer2_state_msgrx(hammer2_msg_t *msg);
int hammer2_state_msgtx(hammer2_msg_t *msg);
void hammer2_state_cleanuprx(hammer2_msg_t *msg);
void hammer2_state_cleanuptx(hammer2_msg_t *msg);
int hammer2_msg_execute(hammer2_msg_t *msg);
void hammer2_state_free(hammer2_state_t *state);
void hammer2_msg_free(hammer2_msg_t *msg);
hammer2_msg_t *hammer2_msg_alloc(hammer2_router_t *router, uint32_t cmd,
				int (*func)(hammer2_state_t *, hammer2_msg_t *),
				void *data);
void hammer2_msg_write(hammer2_msg_t *msg);
void hammer2_msg_reply(hammer2_msg_t *msg, uint32_t error);
void hammer2_msg_result(hammer2_msg_t *msg, uint32_t error);

/*
 * hammer2_msgops.c
 */
int hammer2_msg_dbg_rcvmsg(hammer2_msg_t *msg);
int hammer2_msg_adhoc_input(hammer2_msg_t *msg);

/*
 * hammer2_vfsops.c
 */
void hammer2_clusterctl_wakeup(hammer2_pfsmount_t *pmp);
void hammer2_volconf_update(hammer2_pfsmount_t *pmp, int index);
void hammer2_cluster_reconnect(hammer2_pfsmount_t *pmp, struct file *fp);

/*
 * hammer2_freemap.c
 */
hammer2_off_t hammer2_freemap_alloc(hammer2_mount_t *hmp,
				int type, size_t bytes);
void hammer2_freemap_free(hammer2_mount_t *hmp, hammer2_off_t data_off,
				int type);


