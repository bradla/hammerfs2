/*
 * Copyright (c) 2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/mountctl.h>
#include <sys/dirent.h>
#include <sys/uio.h>
*/

#include "dfly_wrap.h"
#include "hammer2.h"
#include "dfly/vm/vm_extern.h"
#include "dfly/sys/buf.h"
#include "dfly/sys/buf2.h"


int
hammer2_msg_adhoc_input(hammer2_msg_t *msg)
{
	kprintf("ADHOC INPUT MSG %08x\n", msg->any.head.cmd);
	return(0);
}

int
hammer2_msg_dbg_rcvmsg(hammer2_msg_t *msg)
{
	switch(msg->any.head.cmd & HAMMER2_MSGF_CMDSWMASK) {
	case HAMMER2_DBG_SHELL:
		/*
		 * Execute shell command (not supported atm)
		 */
		hammer2_msg_reply(msg, HAMMER2_MSG_ERR_NOSUPP);
		break;
	case HAMMER2_DBG_SHELL | HAMMER2_MSGF_REPLY:
		if (msg->aux_data) {
			msg->aux_data[msg->aux_size - 1] = 0;
			kprintf("DEBUGMSG: %s\n", msg->aux_data);
		}
		break;
	default:
		hammer2_msg_reply(msg, HAMMER2_MSG_ERR_NOSUPP);
		break;
	}
	return(0);
}
