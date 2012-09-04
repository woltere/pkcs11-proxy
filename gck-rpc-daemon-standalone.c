/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-daemon-standalone.c - A sample daemon.

   Copyright (C) 2008, Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "pkcs11/pkcs11.h"

#include "gck-rpc-layer.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <pthread.h>

#ifdef __MINGW32__
# include <winsock2.h>
#endif

#define SOCKET_PATH "tcp://127.0.0.1"

#include "seccomp-bpf.h"
#include "syscall-reporter.h"

static int install_syscall_filter(void)
{
	struct sock_filter filter[] = {
	        /* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
		ALLOW_SYSCALL(sigreturn),
#endif
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
                ALLOW_SYSCALL(futex),
                ALLOW_SYSCALL(brk),
                ALLOW_SYSCALL(open),
                ALLOW_SYSCALL(fstat64),
                ALLOW_SYSCALL(mmap2),
                ALLOW_SYSCALL(mprotect),
                ALLOW_SYSCALL(close),
                ALLOW_SYSCALL(access),
                ALLOW_SYSCALL(munmap),
                ALLOW_SYSCALL(time),
                ALLOW_SYSCALL(_llseek),
                ALLOW_SYSCALL(stat64),
                ALLOW_SYSCALL(fcntl64),
                ALLOW_SYSCALL(mlock),
                ALLOW_SYSCALL(munlock),
		KILL_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if (errno == EINVAL)
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	return 1;
}

#if 0
/* Sample configuration for loading NSS remotely */
static CK_C_INITIALIZE_ARGS p11_init_args = {
	NULL,
	NULL,
	NULL,
	NULL,
	CKF_OS_LOCKING_OK,
	"init-string = configdir='/tmp' certPrefix='' keyPrefix='' secmod='/tmp/secmod.db' flags="
};
#endif

static int is_running = 1;

static int usage(void)
{
	fprintf(stderr, "usage: pkcs11-daemon pkcs11-module [<socket>|\"-\"]\n\tUsing \"-\" results in a single-thread inetd-type daemon\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	CK_C_GetFunctionList func_get_list;
	CK_FUNCTION_LIST_PTR funcs;
	void *module;
	const char *path;
	fd_set read_fds;
	int sock, ret;
	CK_RV rv;


        if (install_syscall_reporter())
                return 1;
        if (install_syscall_filter())
        	return 1;

	/* The module to load is the argument */
	if (argc != 2 && argc != 3)
		usage();

	/* Load the library */
	module = dlopen(argv[1], RTLD_NOW);
	if (!module) {
		fprintf(stderr, "couldn't open library: %s: %s\n", argv[1],
			dlerror());
		exit(1);
	}

	/* Lookup the appropriate function in library */
	func_get_list =
	    (CK_C_GetFunctionList) dlsym(module, "C_GetFunctionList");
	if (!func_get_list) {
		fprintf(stderr,
			"couldn't find C_GetFunctionList in library: %s: %s\n",
			argv[1], dlerror());
		exit(1);
	}

	/* Get the function list */
	rv = (func_get_list) (&funcs);
	if (rv != CKR_OK || !funcs) {
		fprintf(stderr,
			"couldn't get function list from C_GetFunctionList"
			"in libary: %s: 0x%08x\n",
			argv[1], (int)rv);
		exit(1);
	}

	/* RPC layer expects initialized module */
	rv = (funcs->C_Initialize) (NULL /* &p11_init_args */);
	if (rv != CKR_OK) {
		fprintf(stderr, "couldn't initialize module: %s: 0x%08x\n",
			argv[1], (int)rv);
		exit(1);
	}

	path = getenv("PKCS11_DAEMON_SOCKET");
	if (!path && argc == 3)
           path = argv[2];
        if (!path)
	   path = SOCKET_PATH;

        if (strcmp(path,"-") == 0) {
           gck_rpc_layer_inetd();
        } else {
	   sock = gck_rpc_layer_initialize(path, funcs);
	   if (sock == -1)
		   exit(1);

	   is_running = 1;
	   while (is_running) {
		FD_ZERO(&read_fds);
		FD_SET(sock, &read_fds);
		ret = select(sock + 1, &read_fds, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "error watching socket: %s\n",
				strerror(errno));
			exit(1);
		}

		if (FD_ISSET(sock, &read_fds))
			gck_rpc_layer_accept();
	   }

	   gck_rpc_layer_uninitialize();
        }

	rv = (funcs->C_Finalize) (NULL);
	if (rv != CKR_OK)
		fprintf(stderr, "couldn't finalize module: %s: 0x%08x\n",
			argv[1], (int)rv);

	dlclose(module);

	return 0;
}
