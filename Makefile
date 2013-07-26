MODULE := hammer2
obj-m := $(MODULE).o
$(MODULE)-objs := hammer2.o

#obj-$(CONFIG_HAMMER_FS) += hammer2.o

hammer2-objs := dfly_wrap.o
hammer2-objs += hammer2_inode.o hammer2_ccms.o
hammer2-objs += hammer2_chain.o hammer2_freemap.o hammer2_subr.o hammer2_icrc.o
hammer2-objs += hammer2_ioctl.o hammer2_msg.o hammer2_msgops.o super.o  

#hammer-objs += crc32.o hammer_object.o hammer_btree.o hammer_transaction.o
#hammer-objs += hammer_signal.o hammer_blockmap.o hammer_cursor.o
#hammer-objs += hammer_flusher.o hammer_pfs.o hammer_mirror.o hammer_prune.o hammer_rebalance.o
#hammer-objs += hammer_reblock.o hammer_recover.o hammer_dedup.o hammer_ioctl.o
#hammer-objs += hammer_subs.o strtouq.o hammer_io.o hammer_inode.o inode.o hammer_volume.o hammer_undo.o hammer_redo.o

ifndef EXTRA_CFLAGS
	export EXTRA_CFLAGS = -I$(shell pwd)/fs/hammerfs/dfly
endif

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f .*.cmd *.o .*.o.d modules.order
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
