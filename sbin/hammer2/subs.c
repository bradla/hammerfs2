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

#include "hammer2.h"

/*
 * Obtain a file descriptor that the caller can execute ioctl()'s on.
 */
int
hammer2_ioctl_handle(const char *sel_path)
{
	struct hammer2_ioc_version info;
	int fd;

	if (sel_path == NULL)
		sel_path = ".";

	fd = open(sel_path, O_RDONLY, 0);
	if (fd < 0) {
		fprintf(stderr, "hammer2: Unable to open %s: %s\n",
			sel_path, strerror(errno));
		return(-1);
	}
	if (ioctl(fd, HAMMER2IOC_VERSION_GET, &info) < 0) {
		fprintf(stderr, "hammer2: '%s' is not a hammer2 filesystem\n",
			sel_path);
		close(fd);
		return(-1);
	}
	return (fd);
}

/*
 * Execute the specified function as a detached independent process/daemon,
 * unless we are in debug mode.  If we are in debug mode the function is
 * executed as a pthread in the current process.
 */
void
hammer2_demon(void *(*func)(void *), void *arg)
{
	pthread_t thread = NULL;
	pid_t pid;
	int ttyfd;

	/*
	 * Do not disconnect in debug mode
	 */
	if (DebugOpt) {
                pthread_create(&thread, NULL, func, arg);
		NormalExit = 0;
		return;
	}

	/*
	 * Otherwise disconnect us.  Double-fork to get rid of the ppid
	 * association and disconnect the TTY.
	 */
	if ((pid = fork()) < 0) {
		fprintf(stderr, "hammer2: fork(): %s\n", strerror(errno));
		exit(1);
	}
	if (pid > 0) {
		while (waitpid(pid, NULL, 0) != pid)
			;
		return;		/* parent returns */
	}

	/*
	 * Get rid of the TTY/session before double-forking to finish off
	 * the ppid.
	 */
	ttyfd = open("/dev/null", O_RDWR);
	if (ttyfd >= 0) {
		if (ttyfd != 0)
			dup2(ttyfd, 0);
		if (ttyfd != 1)
			dup2(ttyfd, 1);
		if (ttyfd != 2)
			dup2(ttyfd, 2);
		if (ttyfd > 2)
			close(ttyfd);
	}

	ttyfd = open("/dev/tty", O_RDWR);
	if (ttyfd >= 0) {
		ioctl(ttyfd, TIOCNOTTY, 0);
		close(ttyfd);
	}
	setsid();

	/*
	 * Second fork to disconnect ppid (the original parent waits for
	 * us to exit).
	 */
	if ((pid = fork()) < 0) {
		_exit(2);
	}
	if (pid > 0)
		_exit(0);

	/*
	 * The double child
	 */
	setsid();
	pthread_create(&thread, NULL, func, arg);
	pthread_exit(NULL);
	_exit(2);	/* NOT REACHED */
}

/*
 * This swaps endian for a hammer2_msg_hdr.  Note that the extended
 * header is not adjusted, just the core header.
 */
void
hammer2_bswap_head(hammer2_msg_hdr_t *head)
{
	head->magic	= bswap16(head->magic);
	head->reserved02 = bswap16(head->reserved02);
	head->salt	= bswap32(head->salt);

	head->msgid	= bswap64(head->msgid);
	head->source	= bswap64(head->source);
	head->target	= bswap64(head->target);

	head->cmd	= bswap32(head->cmd);
	head->aux_crc	= bswap32(head->aux_crc);
	head->aux_bytes	= bswap32(head->aux_bytes);
	head->error	= bswap32(head->error);
	head->aux_descr = bswap64(head->aux_descr);
	head->reserved38= bswap32(head->reserved38);
	head->hdr_crc	= bswap32(head->hdr_crc);
}

const char *
hammer2_time64_to_str(uint64_t htime64, char **strp)
{
	struct tm *tp;
	time_t t;

	if (*strp) {
		free(*strp);
		*strp = NULL;
	}
	*strp = malloc(64);
	t = htime64 / 1000000;
	tp = localtime(&t);
	strftime(*strp, 64, "%d-%b-%Y %H:%M:%S", tp);
	return (*strp);
}

const char *
hammer2_uuid_to_str(uuid_t *uuid, char **strp)
{
	uint32_t status;
	if (*strp) {
		free(*strp);
		*strp = NULL;
	}
	uuid_to_string(uuid, strp, &status);
	return (*strp);
}

const char *
hammer2_iptype_to_str(uint8_t type)
{
	switch(type) {
	case HAMMER2_OBJTYPE_UNKNOWN:
		return("UNKNOWN");
	case HAMMER2_OBJTYPE_DIRECTORY:
		return("DIR");
	case HAMMER2_OBJTYPE_REGFILE:
		return("FILE");
	case HAMMER2_OBJTYPE_FIFO:
		return("FIFO");
	case HAMMER2_OBJTYPE_CDEV:
		return("CDEV");
	case HAMMER2_OBJTYPE_BDEV:
		return("BDEV");
	case HAMMER2_OBJTYPE_SOFTLINK:
		return("SOFTLINK");
	case HAMMER2_OBJTYPE_HARDLINK:
		return("HARDLINK");
	case HAMMER2_OBJTYPE_SOCKET:
		return("SOCKET");
	case HAMMER2_OBJTYPE_WHITEOUT:
		return("WHITEOUT");
	default:
		return("ILLEGAL");
	}
}

const char *
hammer2_pfstype_to_str(uint8_t type)
{
	switch(type) {
	case HAMMER2_PFSTYPE_NONE:
		return("NONE");
	case HAMMER2_PFSTYPE_ADMIN:
		return("ADMIN");
	case HAMMER2_PFSTYPE_CACHE:
		return("CACHE");
	case HAMMER2_PFSTYPE_COPY:
		return("COPY");
	case HAMMER2_PFSTYPE_SLAVE:
		return("SLAVE");
	case HAMMER2_PFSTYPE_SOFT_SLAVE:
		return("SOFT_SLAVE");
	case HAMMER2_PFSTYPE_SOFT_MASTER:
		return("SOFT_MASTER");
	case HAMMER2_PFSTYPE_MASTER:
		return("MASTER");
	default:
		return("ILLEGAL");
	}
}

const char *
sizetostr(hammer2_off_t size)
{
	static char buf[32];

	if (size < 1024 / 2) {
		snprintf(buf, sizeof(buf), "%6.2f", (double)size);
	} else if (size < 1024 * 1024 / 2) {
		snprintf(buf, sizeof(buf), "%6.2fKB",
			(double)size / 1024);
	} else if (size < 1024 * 1024 * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fMB",
			(double)size / (1024 * 1024));
	} else if (size < 1024 * 1024 * 1024LL * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fGB",
			(double)size / (1024 * 1024 * 1024LL));
	} else {
		snprintf(buf, sizeof(buf), "%6.2fTB",
			(double)size / (1024 * 1024 * 1024LL * 1024LL));
	}
	return(buf);
}

/*
 * Allocation wrappers give us shims for possible future use
 */
void *
hammer2_alloc(size_t bytes)
{
	void *ptr;

	ptr = malloc(bytes);
	assert(ptr);
	bzero(ptr, bytes);
	return (ptr);
}

void
hammer2_free(void *ptr)
{
	free(ptr);
}

int
hammer2_connect(const char *hostname)
{
	struct sockaddr_in lsin;
	struct hostent *hen;
	int fd;

	/*
	 * Acquire socket and set options
	 */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "cmd_debug: socket(): %s\n",
			strerror(errno));
		return -1;
	}

	/*
	 * Connect to the target
	 */
	bzero(&lsin, sizeof(lsin));
	lsin.sin_family = AF_INET;
	lsin.sin_addr.s_addr = 0;
	lsin.sin_port = htons(HAMMER2_LISTEN_PORT);

	if (hostname) {
		hen = gethostbyname2(hostname, AF_INET);
		if (hen == NULL) {
			if (inet_pton(AF_INET, hostname, &lsin.sin_addr) != 1) {
				fprintf(stderr,
					"Cannot resolve %s\n", hostname);
				return -1;
			}
		} else {
			bcopy(hen->h_addr, &lsin.sin_addr, hen->h_length);
		}
	}
	if (connect(fd, (struct sockaddr *)&lsin, sizeof(lsin)) < 0) {
		close(fd);
		fprintf(stderr, "debug: connect failed: %s\n",
			strerror(errno));
		return -1;
	}
	return (fd);
}
