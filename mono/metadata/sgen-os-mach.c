/*
 * sgen-os-mach.c: Mach-OS support.
 *
 * Author:
 *	Paolo Molaro (lupus@ximian.com)
 *	Mark Probst (mprobst@novell.com)
 * 	Geoff Norton (gnorton@novell.com)
 *
 * Copyright 2010 Novell, Inc (http://www.novell.com)
 * Copyright (C) 2012 Xamarin Inc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License 2.0 as published by the Free Software Foundation;
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License 2.0 along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "config.h"
#ifdef HAVE_SGEN_GC


#include <glib.h>
#include "sgen/sgen-gc.h"
#include "sgen/sgen-archdep.h"
#include "sgen/sgen-protocol.h"
#include "sgen/sgen-thread-pool.h"
#include "metadata/object-internals.h"
#include "metadata/gc-internal.h"

#if defined(__MACH__)
#include "utils/mach-support.h"
#endif

#if defined (PLATFORM_MACOSX)
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <pthread.h>
#endif

#if defined(__MACH__) && MONO_MACH_ARCH_SUPPORTED
gboolean
sgen_resume_thread (SgenThreadInfo *info)
{
	return thread_resume (info->client_info.info.native_handle) == KERN_SUCCESS;
}

gboolean
sgen_suspend_thread (SgenThreadInfo *info)
{
	mach_msg_type_number_t num_state;
	thread_state_t state;
	kern_return_t ret;
	ucontext_t ctx;
	mcontext_t mctx;

	gpointer stack_start;

	state = (thread_state_t) alloca (mono_mach_arch_get_thread_state_size ());
	mctx = (mcontext_t) alloca (mono_mach_arch_get_mcontext_size ());

	ret = thread_suspend (info->client_info.info.native_handle);
	if (ret != KERN_SUCCESS)
		return FALSE;

	ret = mono_mach_arch_get_thread_state (info->client_info.info.native_handle, state, &num_state);
	if (ret != KERN_SUCCESS)
		return FALSE;

	mono_mach_arch_thread_state_to_mcontext (state, mctx);
	ctx.uc_mcontext = mctx;

	info->client_info.stopped_domain = mono_thread_info_tls_get (info, TLS_KEY_DOMAIN);
	info->client_info.stopped_ip = (gpointer) mono_mach_arch_get_ip (state);
	info->client_info.stack_start = NULL;
	stack_start = (char*) mono_mach_arch_get_sp (state) - REDZONE_SIZE;
	/* If stack_start is not within the limits, then don't set it in info and we will be restarted. */
	if (stack_start >= info->client_info.stack_start_limit && stack_start <= info->client_info.stack_end) {
		info->client_info.stack_start = stack_start;

#ifdef USE_MONO_CTX
		mono_sigctx_to_monoctx (&ctx, &info->client_info.ctx);
#else
		ARCH_COPY_SIGCTX_REGS (&info->client_info.regs, &ctx);
#endif
	} else {
		g_assert (!info->client_info.stack_start);
	}

	/* Notify the JIT */
	if (mono_gc_get_gc_callbacks ()->thread_suspend_func)
		mono_gc_get_gc_callbacks ()->thread_suspend_func (info->client_info.runtime_data, &ctx, NULL);

	SGEN_LOG (2, "thread %p stopped at %p stack_start=%p", (void*)(gsize)info->client_info.info.native_handle, info->client_info.stopped_ip, info->client_info.stack_start);
	binary_protocol_thread_suspend ((gpointer)mono_thread_info_get_tid (info), info->client_info.stopped_ip);

	return TRUE;
}

void
sgen_wait_for_suspend_ack (int count)
{
    /* mach thread_resume is synchronous so we dont need to wait for them */
}

/* LOCKING: assumes the GC lock is held */
int
sgen_thread_handshake (BOOL suspend)
{
	SgenThreadInfo *cur_thread = mono_thread_info_current ();
	kern_return_t ret;
	SgenThreadInfo *info;

	int count = 0;

	cur_thread->client_info.suspend_done = TRUE;
	FOREACH_THREAD_SAFE (info) {
		if (info == cur_thread || sgen_thread_pool_is_thread_pool_thread (mono_thread_info_get_tid (info)))
			continue;

		info->client_info.suspend_done = FALSE;
		if (info->client_info.gc_disabled)
			continue;

		if (suspend) {
			if (!sgen_suspend_thread (info))
				continue;
		} else {
			ret = thread_resume (info->client_info.info.native_handle);
			if (ret != KERN_SUCCESS)
				continue;
		}
		count ++;
	} END_FOREACH_THREAD_SAFE
	return count;
}

#if defined (PLATFORM_MACOSX)

#if defined(__x86_64__)

#define MACH_HEADER_TYPE struct mach_header_64
#define NLIST_TYPE struct nlist_64
#define OFFSET_TYPE uint64_t

#elif (defined(i386) || defined(__i386__))

#define MACH_HEADER_TYPE struct mach_header
#define NLIST_TYPE struct nlist
#define OFFSET_TYPE uint32_t

#endif

const char *OAExcludeMachThreadID_function_name = "___OAExcludeMachThreadID";
static void (*OAExcludeMachThreadID) (pthread_t, int) = NULL;

static OFFSET_TYPE
offset_for_symbol (struct symtab_command *symtab, uint8_t *data, const char *symbol_name)
{
	NLIST_TYPE *nlist = (NLIST_TYPE *)(data + symtab->symoff);
	char *strtab = (char *) (data + symtab->stroff);

	for (int i = 0; i < symtab->nsyms; ++i, nlist++) {
		const char *name = nlist->n_un.n_strx ? strtab + nlist->n_un.n_strx : NULL;
		if (name != NULL && strcmp(symbol_name, name) == 0) {
			OFFSET_TYPE offset = nlist->n_value;
			return offset;
		}
	}

	return 0;
}

static void
mono_sgen_dylib_loaded (const struct mach_header *header, intptr_t slide)
{
	Dl_info image_info;
	int result = dladdr(header, &image_info);
	if (result == 0)
		return;

	const char *image_name = image_info.dli_fname;
	if (strstr(image_name, "liboainject.dylib") == NULL)
		return;

	struct load_command *cmd = (struct load_command*)((char *) header + sizeof(MACH_HEADER_TYPE));

	for (int commandIndex = 0; commandIndex < header->ncmds; commandIndex++) {
		if (cmd->cmd == LC_SYMTAB) {
			OFFSET_TYPE offset = offset_for_symbol((struct symtab_command *) cmd, (uint8_t *) header, OAExcludeMachThreadID_function_name);
			if (offset != 0) {
				OAExcludeMachThreadID = (void (*)(pthread_t, int)) (slide + offset);
			}

			return;
		}

		cmd = (struct load_command *) ((char *) cmd + cmd->cmdsize);
	}
}

static void
mono_sgen_dylib_unloaded (const struct mach_header *header, intptr_t slide)
{
	Dl_info image_info;
	int result = dladdr(header, &image_info);
	if (result == 0)
		return;

	const char *image_name = image_info.dli_fname;
	if (strstr(image_name, "liboainject.dylib") == NULL)
		return;

	OAExcludeMachThreadID = NULL;
}

void
sgen_os_init (void)
{
	_dyld_register_func_for_add_image (&mono_sgen_dylib_loaded);
	_dyld_register_func_for_remove_image (&mono_sgen_dylib_unloaded);
}

void
sgen_os_world_stopped (void)
{
	if (OAExcludeMachThreadID != NULL)
		OAExcludeMachThreadID(pthread_self(), 1);
}

void
sgen_os_world_restarting (void)
{
	if (OAExcludeMachThreadID != NULL)
		OAExcludeMachThreadID(pthread_self(), 0);
}

#else

void
sgen_os_init (void)
{
}

void
sgen_os_world_stopped (void)
{
}

void
sgen_os_world_restarting (void)
{
}

#endif

int
mono_gc_get_suspend_signal (void)
{
	return -1;
}

int
mono_gc_get_restart_signal (void)
{
	return -1;
}
#endif
#endif
