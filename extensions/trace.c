/*
 * trace extension module for crash
 *
 * Copyright (C) 2009, 2010 FUJITSU LIMITED
 * Author: Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */

#define _GNU_SOURCE
#include "defs.h"
#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>

static int verbose = 0;

static int nr_cpu_ids;

/*
 * lockless ring_buffer and old non-lockless ring_buffer are both supported.
 */
static int lockless_ring_buffer;

#define koffset(struct, member) struct##_##member##_offset

static int koffset(trace_array, buffer);
static int koffset(tracer, name);

static int koffset(ring_buffer, pages);
static int koffset(ring_buffer, flags);
static int koffset(ring_buffer, cpus);
static int koffset(ring_buffer, buffers);

static int koffset(ring_buffer_per_cpu, cpu);
static int koffset(ring_buffer_per_cpu, pages);
static int koffset(ring_buffer_per_cpu, head_page);
static int koffset(ring_buffer_per_cpu, tail_page);
static int koffset(ring_buffer_per_cpu, commit_page);
static int koffset(ring_buffer_per_cpu, reader_page);
static int koffset(ring_buffer_per_cpu, overrun);
static int koffset(ring_buffer_per_cpu, entries);

static int koffset(buffer_page, read);
static int koffset(buffer_page, list);
static int koffset(buffer_page, page);

static int koffset(list_head, next);

static int koffset(ftrace_event_call, list);

static int koffset(ftrace_event_field, link);
static int koffset(ftrace_event_field, name);
static int koffset(ftrace_event_field, type);
static int koffset(ftrace_event_field, offset);
static int koffset(ftrace_event_field, size);
static int koffset(ftrace_event_field, is_signed);

static int koffset(POINTER_SYM, POINTER) = 0;

struct ring_buffer_per_cpu {
	ulong kaddr;

	ulong head_page;
	ulong tail_page;
	ulong commit_page;
	ulong reader_page;
	ulong real_head_page;

	int head_page_index;
	ulong *pages;

	ulong *linear_pages;
	int nr_linear_pages;

	ulong overrun;
	ulong entries;
};

static ulong global_trace;
static ulong global_ring_buffer;
static unsigned global_pages;
static struct ring_buffer_per_cpu *global_buffers;

static ulong max_tr_trace;
static ulong max_tr_ring_buffer;
static unsigned max_tr_pages;
static struct ring_buffer_per_cpu *max_tr_buffers;

static ulong ftrace_events;
static ulong current_trace;
static const char *current_tracer_name;

static void ftrace_destroy_event_types(void);
static int ftrace_init_event_types(void);
static int ftrace_show_init(void);
static void ftrace_show_destroy(void);

/* at = ((struct *)ptr)->member */
#define read_value(at, ptr, struct, member)				\
	do {								\
		if (!readmem(ptr + koffset(struct, member), KVADDR,	\
				&at, sizeof(at), #struct "'s " #member,	\
				RETURN_ON_ERROR))			\
			goto out_fail;\
	} while (0)

/* Remove the "const" qualifiers for ptr */
#define free(ptr) free((void *)(ptr))

static int write_and_check(int fd, void *data, size_t size)
{
	size_t tot = 0;
	size_t w;

	do {
		w = write(fd, data, size - tot);
		tot += w;

		if (w <= 0)
			return -1;
	} while (tot != size);

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int init_offsets(void)
{
#define init_offset(struct, member) do {				\
		koffset(struct, member) = MEMBER_OFFSET(#struct, #member);\
		if (koffset(struct, member) < 0) {			\
			fprintf(fp, "failed to init the offset, struct:"\
				#struct ", member:" #member);		\
			return -1;					\
		}							\
	} while (0)


	init_offset(trace_array, buffer);
	init_offset(tracer, name);

	init_offset(ring_buffer, pages);
	init_offset(ring_buffer, flags);
	init_offset(ring_buffer, cpus);
	init_offset(ring_buffer, buffers);

	if (MEMBER_SIZE("ring_buffer_per_cpu", "pages") == sizeof(ulong)) {
		lockless_ring_buffer = 1;
		if (verbose)
			fprintf(fp, "lockless\n");
	}

	init_offset(ring_buffer_per_cpu, cpu);
	init_offset(ring_buffer_per_cpu, pages);
	init_offset(ring_buffer_per_cpu, head_page);
	init_offset(ring_buffer_per_cpu, tail_page);
	init_offset(ring_buffer_per_cpu, commit_page);
	init_offset(ring_buffer_per_cpu, reader_page);
	init_offset(ring_buffer_per_cpu, overrun);
	init_offset(ring_buffer_per_cpu, entries);

	init_offset(buffer_page, read);
	init_offset(buffer_page, list);
	init_offset(buffer_page, page);

	init_offset(list_head, next);

	init_offset(ftrace_event_call, list);

	init_offset(ftrace_event_field, link);
	init_offset(ftrace_event_field, name);
	init_offset(ftrace_event_field, type);
	init_offset(ftrace_event_field, offset);
	init_offset(ftrace_event_field, size);
	init_offset(ftrace_event_field, is_signed);

	return 0;
#undef init_offset
}

static void print_offsets(void)
{
	if (!verbose)
		return;

#define print_offset(struct, member) fprintf(fp,			\
	"koffset(" #struct ", " #member ") = %d\n", koffset(struct, member))

	print_offset(trace_array, buffer);
	print_offset(tracer, name);

	print_offset(ring_buffer, pages);
	print_offset(ring_buffer, flags);
	print_offset(ring_buffer, cpus);
	print_offset(ring_buffer, buffers);

	print_offset(ring_buffer_per_cpu, cpu);
	print_offset(ring_buffer_per_cpu, pages);
	print_offset(ring_buffer_per_cpu, head_page);
	print_offset(ring_buffer_per_cpu, tail_page);
	print_offset(ring_buffer_per_cpu, commit_page);
	print_offset(ring_buffer_per_cpu, reader_page);
	print_offset(ring_buffer_per_cpu, overrun);
	print_offset(ring_buffer_per_cpu, entries);

	print_offset(buffer_page, read);
	print_offset(buffer_page, list);
	print_offset(buffer_page, page);

	print_offset(list_head, next);

	print_offset(ftrace_event_call, list);

	print_offset(ftrace_event_field, link);
	print_offset(ftrace_event_field, name);
	print_offset(ftrace_event_field, type);
	print_offset(ftrace_event_field, offset);
	print_offset(ftrace_event_field, size);
	print_offset(ftrace_event_field, is_signed);
#undef print_offset
}

static int ftrace_init_pages(struct ring_buffer_per_cpu *cpu_buffer,
		unsigned nr_pages)
{
	unsigned j = 0, count = 0;
	ulong head, page;
	ulong real_head_page = cpu_buffer->head_page;

	cpu_buffer->pages = calloc(sizeof(ulong), nr_pages);
	if (cpu_buffer->pages == NULL)
		return -1;

	cpu_buffer->linear_pages = calloc(sizeof(ulong), nr_pages + 1);
	if (cpu_buffer->linear_pages == NULL) {
		free(cpu_buffer->pages);
		return -1;
	}

	if (lockless_ring_buffer) {
		read_value(head, cpu_buffer->kaddr, ring_buffer_per_cpu, pages);
		cpu_buffer->pages[j++] = head - koffset(buffer_page, list);
	} else
		head = cpu_buffer->kaddr + koffset(ring_buffer_per_cpu, pages);

	page = head;
	for (;;) {
		read_value(page, page, list_head, next);
		if (page & 3) {
			/* lockless_ring_buffer */
			page &= ~3;
			real_head_page = page - koffset(buffer_page, list);
		}

		if (j == nr_pages)
			break;

		if (page == head) {
			error(INFO, "Num of pages is less than %d\n", nr_pages);
			goto out_fail;
		}

		cpu_buffer->pages[j++] = page - koffset(buffer_page, list);
	}

	if (page != head) {
		error(INFO, "Num of pages is larger than %d\n", nr_pages);
		goto out_fail;
	}

	/* find head page and head_page_index */

	cpu_buffer->real_head_page = real_head_page;
	cpu_buffer->head_page_index = -1;

	for (j = 0; j < nr_pages; j++) {
		if (cpu_buffer->pages[j] == real_head_page) {
			cpu_buffer->head_page_index = j;
			break;
		}
	}

	if (cpu_buffer->head_page_index == -1) {
		error(INFO, "error for resolve head_page_index\n");
		goto out_fail;
	}

	/* Setup linear pages */

	cpu_buffer->linear_pages[count++] = cpu_buffer->reader_page;

	if (cpu_buffer->reader_page == cpu_buffer->commit_page)
		goto done;

	j = cpu_buffer->head_page_index;
	for (;;) {
		cpu_buffer->linear_pages[count++] = cpu_buffer->pages[j];

		if (cpu_buffer->pages[j] == cpu_buffer->commit_page)
			break;

		j++;
		if (j == nr_pages)
			j = 0;

		if (j == cpu_buffer->head_page_index) {
			/* cpu_buffer->commit_page may be corrupted */
			break;
		}
	}

done:
	cpu_buffer->nr_linear_pages = count;

	return 0;

out_fail:
	free(cpu_buffer->pages);
	free(cpu_buffer->linear_pages);
	return -1;
}

static void ftrace_destroy_buffers(struct ring_buffer_per_cpu *buffers)
{
	int i;

	for (i = 0; i < nr_cpu_ids; i++) {
		if (!buffers[i].kaddr)
			continue;

		free(buffers[i].pages);
		free(buffers[i].linear_pages);
	}
}

static int ftrace_init_buffers(struct ring_buffer_per_cpu *buffers,
		ulong ring_buffer, unsigned pages)
{
	int i;
	ulong buffers_array;

	read_value(buffers_array, ring_buffer, ring_buffer, buffers);

	for (i = 0; i < nr_cpu_ids; i++) {
		if (!readmem(buffers_array + sizeof(ulong) * i, KVADDR,
				&buffers[i].kaddr, sizeof(ulong),
				"ring_buffer's cpu buffer", RETURN_ON_ERROR))
			goto out_fail;

		if (!buffers[i].kaddr)
			continue;

#define buffer_read_value(member) read_value(buffers[i].member,		\
			buffers[i].kaddr, ring_buffer_per_cpu, member)

		buffer_read_value(head_page);
		buffer_read_value(tail_page);
		buffer_read_value(commit_page);
		buffer_read_value(reader_page);
		buffer_read_value(overrun);
		buffer_read_value(entries);
#undef buffer_read_value

		if (ftrace_init_pages(buffers + i, pages) < 0)
			goto out_fail;

		if (verbose) {
			fprintf(fp, "overrun=%lu\n", buffers[i].overrun);
			fprintf(fp, "entries=%lu\n", buffers[i].entries);
		}
	}

	return 0;

out_fail:
	ftrace_destroy_buffers(buffers);
	return -1;
}

static int ftrace_int_global_trace(void)
{
	read_value(global_ring_buffer, global_trace, trace_array, buffer);
	read_value(global_pages, global_ring_buffer, ring_buffer, pages);

	global_buffers = calloc(sizeof(*global_buffers), nr_cpu_ids);
	if (global_buffers == NULL)
		goto out_fail;

	if (ftrace_init_buffers(global_buffers, global_ring_buffer,
			global_pages) < 0)
		goto out_fail;

	return 0;

out_fail:
	free(global_buffers);
	return -1;
}

static int ftrace_int_max_tr_trace(void)
{
	read_value(max_tr_ring_buffer, max_tr_trace, trace_array, buffer);

	if (!max_tr_ring_buffer)
		return 0;

	read_value(max_tr_pages, max_tr_ring_buffer, ring_buffer, pages);

	max_tr_buffers = calloc(sizeof(*max_tr_buffers), nr_cpu_ids);
	if (max_tr_buffers == NULL)
		goto out_fail;

	if (ftrace_init_buffers(max_tr_buffers, max_tr_ring_buffer,
			max_tr_pages) < 0)
		goto out_fail;

	return 0;

out_fail:
	free(max_tr_buffers);
	max_tr_ring_buffer = 0;
	return -1;
}

static int ftrace_init_current_tracer(void)
{
	ulong addr;
	char tmp[128];

	/* Get current tracer name */
	read_value(addr, current_trace, POINTER_SYM, POINTER);
	read_value(addr, addr, tracer, name);
	read_string(addr, tmp, 128);

	current_tracer_name = strdup(tmp);
	if (current_tracer_name == NULL)
		goto out_fail;

	return 0;

out_fail:
	return -1;
}

static int ftrace_init(void)
{
        struct syment *sym_global_trace;
	struct syment *sym_max_tr_trace;
	struct syment *sym_ftrace_events;
	struct syment *sym_current_trace;

	sym_global_trace = symbol_search("global_trace");
	sym_max_tr_trace = symbol_search("max_tr");
	sym_ftrace_events = symbol_search("ftrace_events");
	sym_current_trace = symbol_search("current_trace");

	if (sym_global_trace == NULL || sym_max_tr_trace == NULL
			|| sym_ftrace_events == NULL
			|| sym_current_trace == NULL)
		return -1;

	global_trace = sym_global_trace->value;
	max_tr_trace = sym_max_tr_trace->value;
	ftrace_events = sym_ftrace_events->value;
	current_trace = sym_current_trace->value;

	if (!try_get_symbol_data("nr_cpu_ids", sizeof(int), &nr_cpu_ids))
		nr_cpu_ids = 1;

	if (init_offsets() < 0)
		return -1;
	print_offsets();

	if (ftrace_int_global_trace() < 0)
		goto out_0;

	ftrace_int_max_tr_trace();

	if (ftrace_init_event_types() < 0)
		goto out_1;

	if (ftrace_init_current_tracer() < 0)
		goto out_2;

	if (ftrace_show_init() < 0)
		goto out_3;

	return 0;

out_3:
	free(current_tracer_name);
out_2:
	ftrace_destroy_event_types();
out_1:
	if (max_tr_ring_buffer) {
		ftrace_destroy_buffers(max_tr_buffers);
		free(max_tr_buffers);
	}
	ftrace_destroy_buffers(global_buffers);
	free(global_buffers);
out_0:
	return -1;
}

static void ftrace_destroy(void)
{
	ftrace_show_destroy();
	free(current_tracer_name);
	ftrace_destroy_event_types();

	if (max_tr_ring_buffer) {
		ftrace_destroy_buffers(max_tr_buffers);
		free(max_tr_buffers);
	}

	ftrace_destroy_buffers(global_buffers);
	free(global_buffers);
}

static int ftrace_dump_page(int fd, ulong page, void *page_tmp)
{
	ulong raw_page;

	read_value(raw_page, page, buffer_page, page);

	if (!readmem(raw_page, KVADDR, page_tmp, PAGESIZE(), "get page context",
			RETURN_ON_ERROR))
		goto out_fail;

	if (write_and_check(fd, page_tmp, PAGESIZE()))
		return -1;

	return 0;

out_fail:
	return -1;
}

static
void ftrace_dump_buffer(int fd, struct ring_buffer_per_cpu *cpu_buffer,
		unsigned pages, void *page_tmp)
{
	int i;

	for (i = 0; i < cpu_buffer->nr_linear_pages; i++) {
		if (ftrace_dump_page(fd, cpu_buffer->linear_pages[i],
				page_tmp) < 0)
			break;
	}
}

static int try_mkdir(const char *pathname, mode_t mode)
{
	int ret;

	ret = mkdir(pathname, mode);
	if (ret < 0) {
		if (errno == EEXIST)
			return 0;

		error(INFO, "mkdir failed\n");
		return -1;
	}

	return 0;
}

static int ftrace_dump_buffers(const char *per_cpu_path)
{
	int i;
	void *page_tmp;
	char path[PATH_MAX];
	int fd;

	page_tmp = malloc(PAGESIZE());
	if (page_tmp == NULL)
		return -1;

	for (i = 0; i < nr_cpu_ids; i++) {
		struct ring_buffer_per_cpu *cpu_buffer = &global_buffers[i];

		if (!cpu_buffer->kaddr)
			continue;

		snprintf(path, sizeof(path), "%s/cpu%d", per_cpu_path, i);
		if (try_mkdir(path, 0755) < 0)
			goto out_fail;

		snprintf(path, sizeof(path), "%s/cpu%d/trace_pipe_raw",
				per_cpu_path, i);
		fd = open(path, O_WRONLY | O_CREAT, 0644);
		if (fd < 0)
			goto out_fail;

		ftrace_dump_buffer(fd, cpu_buffer, global_pages, page_tmp);
		close(fd);
	}

	free(page_tmp);
	return 0;

out_fail:
	free(page_tmp);
	return -1;
}

typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;

#define MAX_CACHE_ID	256

struct ftrace_field;
typedef u64 (*access_op)(struct ftrace_field *aop, void *data);
static void ftrace_field_access_init(struct ftrace_field *f);

struct ftrace_field {
	const char *name;
	const char *type;
	access_op op;
	int offset;
	int size;
	int is_signed;
};

struct event_type;
struct format_context;
typedef void (*event_printer)(struct event_type *t, struct format_context *fc);

 /* SIGH, we cann't get "print fmt" from core-file */

struct event_type {
	struct event_type *next;
	const char *system;
	const char *name;
	int plugin;
	event_printer printer;
	const char *print_fmt;
	int id;
	int nfields;
	struct ftrace_field *fields;
};

static struct event_type *event_type_cache[MAX_CACHE_ID];
static struct event_type **event_types;
static int nr_event_types;

/*
 * TODO: implement event_generic_print_fmt_print() when the print fmt
 * in tracing/events/$SYSTEM/$TRACE/format becomes a will-defined
 * language.
 */
static void event_generic_print_fmt_print(struct event_type *t,
		struct format_context *fc);
static void event_default_print(struct event_type *t,
		struct format_context *fc);

static
int ftrace_get_event_type_fields(ulong call, ulong *fields)
{
	static int inited;
	static int fields_offset;

	if (!inited) {
		inited = 1;
		fields_offset = MEMBER_OFFSET("ftrace_event_call", "fields");
	}

	if (fields_offset < 0)
		return -1;

	*fields = call + fields_offset;

	return 0;
}

static int ftrace_init_event_type(ulong call, struct event_type *aevent_type)
{
	ulong fields_addr, pos;

	int nfields = 0, max_fields = 16;
	struct ftrace_field *fields = NULL;

	if (ftrace_get_event_type_fields(call, &fields_addr) < 0)
		return -1;
	read_value(pos, fields_addr, list_head, next);

	if (pos == 0) {
		if (verbose)
			fprintf(fp, "no field %lu\n", call);
		return 0;
	}

	fields = malloc(sizeof(*fields) * max_fields);
	if (fields == NULL)
		return -1;

	while (pos != fields_addr) {
		ulong field;
		ulong name_addr, type_addr;
		char field_name[128], field_type[128];
		int offset, size, is_signed;

		field = pos - koffset(ftrace_event_field, link);

		/* Read a field from the core */
		read_value(name_addr, field, ftrace_event_field, name);
		read_value(type_addr, field, ftrace_event_field, type);
		read_value(offset, field, ftrace_event_field, offset);
		read_value(size, field, ftrace_event_field, size);
		read_value(is_signed, field, ftrace_event_field, is_signed);

		if (!read_string(name_addr, field_name, 128))
			goto out_fail;
		if (!read_string(type_addr, field_type, 128))
			goto out_fail;

		/* Enlarge fields array when need */
		if (nfields >= max_fields) {
			void *tmp;

			max_fields = nfields * 2;
			tmp = realloc(fields, sizeof(*fields) * max_fields);
			if (tmp == NULL)
				goto out_fail;

			fields = tmp;
		}

		/* Set up and Add a field */
		fields[nfields].offset = offset;
		fields[nfields].size = size;
		fields[nfields].is_signed = is_signed;

		fields[nfields].name = strdup(field_name);
		if (fields[nfields].name == NULL)
			goto out_fail;

		fields[nfields].type = strdup(field_type);
		if (fields[nfields].type == NULL) {
			free(fields[nfields].name);
			goto out_fail;
		}

		ftrace_field_access_init(&fields[nfields]);
		nfields++;

		/* Advance to the next field */
		read_value(pos, pos, list_head, next);
	}

	aevent_type->nfields = nfields;
	aevent_type->fields = fields;

	return 0;

out_fail:
	for (nfields--; nfields >= 0; nfields--) {
		free(fields[nfields].name);
		free(fields[nfields].type);
	}

	free(fields);
	return -1;
}

static void ftrace_destroy_event_types(void)
{
	int i, j;

	for (i = 0; i < nr_event_types; i++) {
		for (j = 0; j < event_types[i]->nfields; j++) {
			free(event_types[i]->fields[j].name);
			free(event_types[i]->fields[j].type);
		}

		free(event_types[i]->fields);
		free(event_types[i]->system);
		free(event_types[i]->name);
		free(event_types[i]->print_fmt);
		free(event_types[i]);
	}

	free(event_types);
}

static
int ftrace_get_event_type_name(ulong call, char *name, int len)
{
	static int inited;
	static int name_offset;

	ulong name_addr;

	if (!inited) {
		inited = 1;
		name_offset = MEMBER_OFFSET("ftrace_event_call", "name");
	}

	if (name_offset < 0)
		return -1;

	if (!readmem(call + name_offset, KVADDR, &name_addr, sizeof(name_addr),
			"read ftrace_event_call name_addr", RETURN_ON_ERROR))
		return -1;

	if (!read_string(name_addr, name, len))
		return -1;

	return 0;
}

static
int ftrace_get_event_type_system(ulong call, char *system, int len)
{
	static int inited;
	static int sys_offset;

	ulong sys_addr;

	if (!inited) {
		inited = 1;
		sys_offset = MEMBER_OFFSET("ftrace_event_call", "system");
	}

	if (sys_offset < 0)
		return -1;

	if (!readmem(call + sys_offset, KVADDR, &sys_addr, sizeof(sys_addr),
			"read ftrace_event_call sys_addr", RETURN_ON_ERROR))
		return -1;

	if (!read_string(sys_addr, system, len))
		return -1;

	return 0;
}

static
int ftrace_get_event_type_print_fmt(ulong call, char *print_fmt, int len)
{
	static int inited;
	static int fmt_offset;

	ulong fmt_addr;

	if (!inited) {
		inited = 1;
		fmt_offset = MEMBER_OFFSET("ftrace_event_call", "print_fmt");
	}

	if (fmt_offset < 0)
		return -1;

	if (!readmem(call + fmt_offset, KVADDR, &fmt_addr, sizeof(fmt_addr),
			"read ftrace_event_call fmt_addr", RETURN_ON_ERROR))
		return -1;

	if (!read_string(fmt_addr, print_fmt, len))
		return -1;

	return 0;
}

static
int ftrace_get_event_type_id(ulong call, int *id)
{
	static int inited;
	static int id_offset;

	if (!inited) {
		inited = 1;
		id_offset = MEMBER_OFFSET("ftrace_event_call", "id");
	}

	if (id_offset < 0)
		return -1;

	if (!readmem(call + id_offset, KVADDR, id, sizeof(*id),
			"read ftrace_event_call id", RETURN_ON_ERROR))
		return -1;

	return 0;
}

static int ftrace_init_event_types(void)
{
	ulong event;
	struct event_type *aevent_type;
	int max_types = 128;

	event_types = malloc(sizeof(*event_types) * max_types);
	if (event_types == NULL)
		return -1;

	read_value(event, ftrace_events, list_head, next);
	while (event != ftrace_events) {
		ulong call;
		char name[128], system[128], print_fmt[4096];
		int id;

		call = event - koffset(ftrace_event_call, list);

		/* Read a event type from the core */
		if (ftrace_get_event_type_id(call, &id) < 0 ||
		    ftrace_get_event_type_name(call, name, 128) < 0 ||
		    ftrace_get_event_type_system(call, system, 128) < 0 ||
		    ftrace_get_event_type_print_fmt(call, print_fmt, 4096) < 0)
			goto out_fail;

		/* Enlarge event types array when need */
		if (nr_event_types >= max_types) {
			void *tmp;

			max_types = 2 * nr_event_types;
			tmp = realloc(event_types,
					sizeof(*event_types) * max_types);
			if (tmp == NULL)
				goto out_fail;

			event_types = tmp;
		}

		/* Create a event type */
		aevent_type = malloc(sizeof(*aevent_type));
		if (aevent_type == NULL)
			goto out_fail;

		aevent_type->system = strdup(system);
		aevent_type->name = strdup(name);
		aevent_type->print_fmt = strdup(print_fmt);
		aevent_type->id = id;
		aevent_type->nfields = 0;
		aevent_type->fields = NULL;

		if (aevent_type->system == NULL || aevent_type->name == NULL)
			goto out_fail_free_aevent_type;

		if (ftrace_init_event_type(call, aevent_type) < 0)
			goto out_fail_free_aevent_type;

		if (!strcmp("ftrace", aevent_type->system))
			aevent_type->plugin = 1;
		else
			aevent_type->plugin = 0;
		aevent_type->printer = event_default_print;

		/* Add a event type */
		event_types[nr_event_types++] = aevent_type;
		if ((unsigned)id < MAX_CACHE_ID)
			event_type_cache[id] = aevent_type;

		/* Advance to the next event type */
		read_value(event, event, list_head, next);
	}

	return 0;

out_fail_free_aevent_type:
	free(aevent_type->system);
	free(aevent_type->name);
	free(aevent_type->print_fmt);
	free(aevent_type);
out_fail:
	ftrace_destroy_event_types();
	return -1;
}

static
struct ftrace_field *find_event_field(struct event_type *t, const char *name)
{
	int i;
	struct ftrace_field *f;

	for (i = 0; i < t->nfields; i++) {
		f = &t->fields[i];
		if (!strcmp(name, f->name))
			return f;
	}

	return NULL;
}

static struct event_type *find_event_type(int id)
{
	int i;

	if ((unsigned int)id < MAX_CACHE_ID)
		return event_type_cache[id];

	for (i = 0; i < nr_event_types; i++) {
		if (event_types[i]->id == id)
			return event_types[i];
	}

	return NULL;
}

static
struct event_type *find_event_type_by_name(const char *system, const char *name)
{
	int i;

	for (i = 0; i < nr_event_types; i++) {
		if (system && strcmp(system, event_types[i]->system))
			continue;
		if (!strcmp(name, event_types[i]->name))
			return event_types[i];
	}

	return NULL;
}

static int ftrace_dump_event_type(struct event_type *t, const char *path)
{
	char format_path[PATH_MAX];
	FILE *out;
	int i;
	int common_field_count = 5;

	snprintf(format_path, sizeof(format_path), "%s/format", path);
	out = fopen(format_path, "w");
	if (out == NULL)
		return -1;

	fprintf(out, "name: %s\n", t->name);
	fprintf(out, "ID: %d\n", t->id);
	fprintf(out, "format:\n");

	for (i = t->nfields - 1; i >= 0; i--) {
		/*
		 * Smartly shows the array type(except dynamic array).
		 * Normal:
		 *	field:TYPE VAR
		 * If TYPE := TYPE[LEN], it is shown:
		 *	field:TYPE VAR[LEN]
		 */
		struct ftrace_field *field = &t->fields[i];
		const char *array_descriptor = strchr(field->type, '[');

		if (!strncmp(field->type, "__data_loc", 10))
			array_descriptor = NULL;

		if (!array_descriptor) {
			fprintf(out, "\tfield:%s %s;\toffset:%u;"
					"\tsize:%u;\tsigned:%d;\n",
					field->type, field->name, field->offset,
					field->size, !!field->is_signed);
		} else {
			fprintf(out, "\tfield:%.*s %s%s;\toffset:%u;"
					"\tsize:%u;\tsigned:%d;\n",
					(int)(array_descriptor - field->type),
					field->type, field->name,
					array_descriptor, field->offset,
					field->size, !!field->is_signed);
		}

		if (--common_field_count == 0)
			fprintf(out, "\n");
	}

	fprintf(out, "\nprint fmt: %s\n", t->print_fmt);

	fclose(out);

	return 0;
}

static int ftrace_dump_event_types(const char *events_path)
{
	int i;

	for (i = 0; i < nr_event_types; i++) {
		char path[PATH_MAX];
		struct event_type *t = event_types[i];

		snprintf(path, sizeof(path), "%s/%s", events_path, t->system);
		if (try_mkdir(path, 0755) < 0)
			return -1;

		snprintf(path, sizeof(path), "%s/%s/%s", events_path,
			t->system, t->name);
		if (try_mkdir(path, 0755) < 0)
			return -1;

		if (ftrace_dump_event_type(t, path) < 0)
			return -1;
	}

	return 0;
}

struct ring_buffer_per_cpu_stream {
	struct ring_buffer_per_cpu *cpu_buffer;
	void *curr_page;
	int curr_page_indx;

	uint64_t ts;
	uint32_t *offset;
	uint32_t *commit;
};

static
int ring_buffer_per_cpu_stream_init(struct ring_buffer_per_cpu *cpu_buffer,
		unsigned pages, struct ring_buffer_per_cpu_stream *s)
{
	s->cpu_buffer = cpu_buffer;
	s->curr_page = malloc(PAGESIZE());
	if (s->curr_page == NULL)
		return -1;

	s->curr_page_indx = -1;
	return 0;
}

static
void ring_buffer_per_cpu_stream_destroy(struct ring_buffer_per_cpu_stream *s)
{
	free(s->curr_page);
}

struct ftrace_event {
	uint64_t ts;
	int length;
	void *data;
};

struct event {
	u32 type_len:5, time_delta:27;
};

#define RINGBUF_TYPE_PADDING		29
#define RINGBUF_TYPE_TIME_EXTEND	30
#define RINGBUF_TYPE_TIME_STAMP		31
#define RINGBUF_TYPE_DATA		0 ... 28

#define sizeof_local_t (sizeof(ulong))
#define PAGE_HEADER_LEN (8 + sizeof_local_t)

static
int ring_buffer_per_cpu_stream_get_page(struct ring_buffer_per_cpu_stream *s)
{
	ulong raw_page;

	read_value(raw_page, s->cpu_buffer->linear_pages[s->curr_page_indx],
			buffer_page, page);

	if (!readmem(raw_page, KVADDR, s->curr_page, PAGESIZE(),
			"get page context", RETURN_ON_ERROR))
		return -1;

	s->ts = *(u64 *)s->curr_page;
	s->offset = s->curr_page + PAGE_HEADER_LEN;
	s->commit = s->offset + *(ulong *)(s->curr_page + 8) / 4;

	return 0;

out_fail:
	return -1;
}

static
int ring_buffer_per_cpu_stream_pop_event(struct ring_buffer_per_cpu_stream *s,
		struct ftrace_event *res)
{
	struct event *event;

	res->data = NULL;

	if (s->curr_page_indx >= s->cpu_buffer->nr_linear_pages)
		return -1;

again:
	if ((s->curr_page_indx == -1) || (s->offset >= s->commit)) {
		s->curr_page_indx++;

		if (s->curr_page_indx == s->cpu_buffer->nr_linear_pages)
			return -1;

		if (ring_buffer_per_cpu_stream_get_page(s) < 0) {
			s->curr_page_indx = s->cpu_buffer->nr_linear_pages;
			return -1;
		}

		if (s->offset >= s->commit)
			goto again;
	}

	event = (void *)s->offset;

	switch (event->type_len) {
	case RINGBUF_TYPE_PADDING:
		if (event->time_delta)
			s->offset += 1 + ((*(s->offset + 1) + 3) / 4);
		else
			s->offset = s->commit;
		goto again;

	case RINGBUF_TYPE_TIME_EXTEND:
		s->ts +=event->time_delta;
		s->ts += ((u64)*(s->offset + 1)) << 27;
		s->offset += 2;
		goto again;

	case RINGBUF_TYPE_TIME_STAMP:
		/* FIXME: not implemented */
		s->offset += 4;
		goto again;

	case RINGBUF_TYPE_DATA:
		if (!event->type_len) {
			res->data = s->offset + 2;
			res->length = *(s->offset + 1) - 4;

			s->offset += 1 + ((*(s->offset + 1) + 3) / 4);
		} else {
			res->data = s->offset + 1;
			res->length = event->type_len * 4;

			s->offset += 1 + event->type_len;
		}

		if (s->offset > s->commit) {
			fprintf(fp, "corrupt\n");
			res->data = NULL;
			goto again;
		}

		s->ts += event->time_delta;
		res->ts = s->ts;

		return 0;

	default:;
	}

	return -1;
}

struct ring_buffer_stream {
	struct ring_buffer_per_cpu_stream *ss;
	struct ftrace_event *es;
	u64 ts;
	int popped_cpu;
	int pushed;
};

static void __rbs_destroy(struct ring_buffer_stream *s, int *cpulist, int nr)
{
	int cpu;

	for (cpu = 0; cpu < nr; cpu++) {
		if (!s->ss[cpu].cpu_buffer)
			continue;

		ring_buffer_per_cpu_stream_destroy(s->ss + cpu);
	}

	free(s->ss);
	free(s->es);
}

static
int ring_buffer_stream_init(struct ring_buffer_stream *s, int *cpulist)
{
	int cpu;

	s->ss = malloc(sizeof(*s->ss) * nr_cpu_ids);
	if (s->ss == NULL)
		return -1;

	s->es = malloc(sizeof(*s->es) * nr_cpu_ids);
	if (s->es == NULL) {
		free(s->ss);
		return -1;
	}

	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		s->ss[cpu].cpu_buffer = NULL;
		s->es[cpu].data = NULL;

		if (!global_buffers[cpu].kaddr)
			continue;

		if (cpulist && !cpulist[cpu])
			continue;

		if (ring_buffer_per_cpu_stream_init(global_buffers + cpu,
				global_pages, s->ss + cpu) < 0) {
			__rbs_destroy(s, cpulist, cpu);
			return -1;
		}
	}

	s->ts = 0;
	s->popped_cpu = nr_cpu_ids;
	s->pushed = 0;

	return 0;
}

static
void ring_buffer_stream_destroy(struct ring_buffer_stream *s, int *cpulist)
{
	__rbs_destroy(s, cpulist, nr_cpu_ids);
}

/* make current event be returned again at next pop */
static void ring_buffer_stream_push_current_event(struct ring_buffer_stream *s)
{
	if ((s->popped_cpu < 0) || (s->popped_cpu == nr_cpu_ids))
		return;

	s->pushed = 1;
}

/* return the cpu# of this event */
static int ring_buffer_stream_pop_event(struct ring_buffer_stream *s,
		struct ftrace_event *res)
{
	int cpu, min_cpu = -1;
	u64 ts, min_ts;

	res->data = NULL;

	if (s->popped_cpu < 0)
		return -1;

	if (s->popped_cpu == nr_cpu_ids) {
		for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
			if (!s->ss[cpu].cpu_buffer)
				continue;

			ring_buffer_per_cpu_stream_pop_event(s->ss + cpu,
					s->es + cpu);

			if (s->es[cpu].data == NULL)
				continue;

			/*
			 * We do not have start point of time,
			 * determine the min_ts with heuristic way.
			 */
			ts = s->es[cpu].ts;
			if (min_cpu < 0 || (s64)(ts - min_ts) < 0) {
				min_ts = ts;
				min_cpu = cpu;
			}
		}

		s->pushed = 0;
		goto done;
	}

	if (s->pushed) {
		s->pushed = 0;
		*res = s->es[s->popped_cpu];
		return s->popped_cpu;
	}

	ring_buffer_per_cpu_stream_pop_event(&s->ss[s->popped_cpu],
			&s->es[s->popped_cpu]);

	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		if (s->es[cpu].data == NULL)
			continue;

		/* we have start point of time(s->ts) */
		ts = s->es[cpu].ts - s->ts;
		if (min_cpu < 0 || ts < min_ts) {
			min_ts = ts;
			min_cpu = cpu;
		}
	}

done:
	s->popped_cpu = min_cpu;

	if (min_cpu < 0)
		return -1;

	s->ts = s->es[min_cpu].ts;
	*res = s->es[min_cpu];

	return min_cpu;
}

static u64 access_error(struct ftrace_field *f, void *data)
{
	return 0;
}

static u64 access_8(struct ftrace_field *f, void *data)
{
	return *(int8_t *)(data + f->offset);
}

static u64 access_16(struct ftrace_field *f, void *data)
{
	return *(int16_t *)(data + f->offset);
}

static u64 access_32(struct ftrace_field *f, void *data)
{
	return *(int32_t *)(data + f->offset);
}

static u64 access_64(struct ftrace_field *f, void *data)
{
	return *(int64_t *)(data + f->offset);
}

static u64 access_string_local(struct ftrace_field *f, void *data)
{
	int offset;

	if (f->size == 2)
		offset = *(int16_t *)(data + f->offset);
	else
		offset = *(int32_t *)(data + f->offset) & 0xFFFF;

	return (long)(data + offset);
}

static u64 access_string(struct ftrace_field *f, void *data)
{
	return (long)(data + f->offset);
}

static u64 access_other_local(struct ftrace_field *f, void *data)
{
	return access_string_local(f, data);
}

static u64 access_other(struct ftrace_field *f, void *data)
{
	return (long)(data + f->offset);
}

static void ftrace_field_access_init(struct ftrace_field *f)
{
	/* guess whether it is string array */
	if (!strncmp(f->type, "__data_loc", sizeof("__data_loc") - 1)) {
		if (f->size != 2 && f->size != 4) {
			/* kernel side may be changed, need fix here */
			f->op = access_error;
		} else if (strstr(f->type, "char")) {
			f->op = access_string_local;
		} else {
			f->op = access_other_local;
		}
	} else if (strchr(f->type, '[')) {
		if (strstr(f->type, "char"))
			f->op = access_string;
		else
			f->op = access_other;
	} else {
		switch (f->size) {
		case 1: f->op = access_8; break;
		case 2: f->op = access_16; break;
		case 4: f->op = access_32; break;
		case 8: f->op = access_64; break;
		default: f->op = access_other; break;
		}
	}
}

static void show_basic_info(void)
{
	fprintf(fp, "current tracer is %s\n", current_tracer_name);
}

static int dump_saved_cmdlines(const char *dump_tracing_dir)
{
	char path[PATH_MAX];
	FILE *out;
	int i;
	struct task_context *tc;

	snprintf(path, sizeof(path), "%s/saved_cmdlines", dump_tracing_dir);
	out = fopen(path, "w");
	if (out == NULL)
		return -1;

	tc = FIRST_CONTEXT();
        for (i = 0; i < RUNNING_TASKS(); i++)
		fprintf(out, "%d %s\n", (int)tc[i].pid, tc[i].comm);

	fclose(out);
	return 0;
}

static int dump_kallsyms(const char *dump_tracing_dir)
{
	char path[PATH_MAX];
	FILE *out;
	int i;
	struct syment *sp;

	snprintf(path, sizeof(path), "%s/kallsyms", dump_tracing_dir);
	out = fopen(path, "w");
	if (out == NULL)
		return -1;

	for (sp = st->symtable; sp < st->symend; sp++)
		fprintf(out, "%lx %c %s\n", sp->value, sp->type, sp->name);

	for (i = 0; i < st->mods_installed; i++) {
		struct load_module *lm = &st->load_modules[i];

		for (sp = lm->mod_symtable; sp <= lm->mod_symend; sp++) {
			if (!strncmp(sp->name, "_MODULE_", strlen("_MODULE_")))
				continue;

			fprintf(out, "%lx %c %s\t[%s]\n", sp->value, sp->type,
					sp->name, lm->mod_name);
		}
	}

	fclose(out);
	return 0;
}

static int trace_cmd_data_output(int fd);

static void ftrace_dump(int argc, char *argv[])
{
	int c;
	int dump_meta_data = 0;
	int dump_symbols = 0;
	char *dump_tracing_dir;
	char path[PATH_MAX];
	int ret;

        while ((c = getopt(argc, argv, "smt")) != EOF) {
                switch(c)
		{
		case 's':
			dump_symbols = 1;
			break;
		case 'm':
			dump_meta_data = 1;
			break;
		case 't':
			if (dump_symbols || dump_meta_data || argc - optind > 1)
				cmd_usage(pc->curcmd, SYNOPSIS);
			else {
				char *trace_dat;
				int fd;

				if (argc - optind == 0)
					trace_dat = "trace.dat";
				else if (argc - optind == 1)
					trace_dat = argv[optind];
				fd = open(trace_dat, O_WRONLY | O_CREAT
						| O_TRUNC, 0644);
				trace_cmd_data_output(fd);
				close(fd);
			}
			return;
		default:
			cmd_usage(pc->curcmd, SYNOPSIS);
			return;
		}
	}

	if (argc - optind == 0) {
		dump_tracing_dir = "dump_tracing_dir";
	} else if (argc - optind == 1) {
		dump_tracing_dir = argv[optind];
	} else {
		cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}

	ret = mkdir(dump_tracing_dir, 0755);
	if (ret < 0) {
		if (errno == EEXIST)
			error(INFO, "mkdir: %s exists\n", dump_tracing_dir);
		return;
	}

	snprintf(path, sizeof(path), "%s/per_cpu", dump_tracing_dir);
	if (try_mkdir(path, 0755) < 0)
		return;

	if (ftrace_dump_buffers(path) < 0)
		return;

	if (dump_meta_data) {
		/* Dump event types */
		snprintf(path, sizeof(path), "%s/events", dump_tracing_dir);
		if (try_mkdir(path, 0755) < 0)
			return;

		if (ftrace_dump_event_types(path) < 0)
			return;

		/* Dump pids with corresponding cmdlines */
		if (dump_saved_cmdlines(dump_tracing_dir) < 0)
			return;
	}

	if (dump_symbols) {
		/* Dump all symbols of the kernel */
		dump_kallsyms(dump_tracing_dir);
	}
}

static char show_event_buf[4096];
static int show_event_pos;

#define INVALID_ACCESS_FIELD 1
static jmp_buf show_event_env;

struct format_context {
	struct ring_buffer_stream stream;
	struct ftrace_event event;
	int cpu;
};

static struct format_context format_context;

/* !!!! @event_type and @field_name should be const for every call */
#define access_field(event_type, data, field_name)			\
({									\
	static struct ftrace_field *__access_field##_field;		\
									\
	if (__access_field##_field == NULL) {				\
		__access_field##_field = find_event_field(event_type,	\
				field_name);				\
	}								\
									\
	if (__access_field##_field == NULL) {				\
		event_type->printer = event_default_print;		\
		ring_buffer_stream_push_current_event(&format_context.stream);\
		longjmp(show_event_env, INVALID_ACCESS_FIELD);		\
	}								\
									\
	__access_field##_field->op(__access_field##_field, data);	\
})

static int ftrace_event_get_id(void *data)
{
	return access_field(event_types[0], data, "common_type");
}

static int ftrace_event_get_pid(void *data)
{
	return access_field(event_types[0], data, "common_pid");
}

#define event_printf(fmt, args...)					\
do {									\
	show_event_pos += snprintf(show_event_buf + show_event_pos,	\
			sizeof(show_event_buf) - show_event_pos,	\
			fmt, ##args);					\
} while (0)


static void event_field_print(struct ftrace_field *f, void *data)
{
	u64 value = f->op(f, data);

	if (f->op == access_error) {
		event_printf("<Error>");
	} else if (f->op == access_8) {
		if (f->is_signed)
			event_printf("%d", (int8_t)value);
		else
			event_printf("%u", (uint8_t)value);
	} else if (f->op == access_16) {
		if (f->is_signed)
			event_printf("%d", (int16_t)value);
		else
			event_printf("%u", (uint16_t)value);
	} else if (f->op == access_32) {
		if (f->is_signed)
			event_printf("%d", (int32_t)value);
		else
			event_printf("%u", (uint32_t)value);
	} else if (f->op == access_64) {
		if (f->is_signed)
			event_printf("%lld", (long long)value);
		else
			event_printf("%llu", (unsigned long long)value);
	} else if (f->op == access_string_local) {
		int size = 0;

		if (f->size == 4)
			size = *(int32_t *)(data + f->offset) >> 16;

		if (size)
			event_printf("%.*s", size, (char *)(long)value);
		else
			event_printf("%s", (char *)(long)value);
	} else if (f->op == access_string) {
		event_printf("%.*s", f->size, (char *)(long)value);
	} else if (f->op == access_other) {
		/* TODO */
	} else if (f->op == access_other_local) {
		/* TODO */
	} else {
		/* TODO */
	}
}

static void get_comm_from_pid(int pid, char *comm)
{
	int li, hi;
	struct task_context *tc;

	if (pid == 0) {
		strcpy(comm, "<swapper>");
		return;
	}

	tc = FIRST_CONTEXT();

	li = 0;
	hi = RUNNING_TASKS();
	while (li < hi) {
		int mid = (li + hi) / 2;

		if (tc[mid].pid > pid)
			hi = mid;
		else if (tc[mid].pid < pid)
			li = mid + 1;
		else {
			strcpy(comm, tc[mid].comm);
			return;
		}
	}

	strcpy(comm, "<...>");
}

static void event_context_print(struct event_type *t, struct format_context *fc)
{
	u64 time = fc->event.ts / 1000;
	ulong sec = time / 1000000;
	ulong usec = time % 1000000;
	int pid = ftrace_event_get_pid(fc->event.data);
	char comm[20];

	get_comm_from_pid(pid, comm);
	event_printf("%16s-%-5d [%03d] %5lu.%06lu: ",
			comm, pid, fc->cpu, sec, usec);
}

static int gopt_context_info;
static int gopt_sym_offset;
static int gopt_sym_addr;

static int gopt_graph_print_duration;
static int gopt_graph_print_overhead;
static int gopt_graph_print_abstime;
static int gopt_graph_print_cpu;
static int gopt_graph_print_proc;
static int gopt_graph_print_overrun;

static void set_all_flags_default(void)
{
	gopt_context_info = 1;
	gopt_sym_offset = 0;
	gopt_sym_addr = 0;

	gopt_graph_print_duration = 1;
	gopt_graph_print_overhead = 1;
	gopt_graph_print_abstime = 0;
	gopt_graph_print_cpu = 1;
	gopt_graph_print_proc = 0;
	gopt_graph_print_overrun = 0;
}

static void set_clear_flag(const char *flag_name, int set)
{
	if (!strcmp(flag_name, "context_info"))
		gopt_context_info = set;
	else if (!strcmp(flag_name, "sym_offset"))
		gopt_sym_offset = set;
	else if (!strcmp(flag_name, "sym_addr"))
		gopt_sym_addr = set;
	else if (!strcmp(flag_name, "graph_print_duration"))
		gopt_graph_print_duration = set;
	else if (!strcmp(flag_name, "graph_print_overhead"))
		gopt_graph_print_overhead = set;
	else if (!strcmp(flag_name, "graph_print_abstime"))
		gopt_graph_print_abstime = set;
	else if (!strcmp(flag_name, "graph_print_cpu"))
		gopt_graph_print_cpu = set;
	else if (!strcmp(flag_name, "graph_print_proc"))
		gopt_graph_print_proc = set;
	else if (!strcmp(flag_name, "graph_print_overrun"))
		gopt_graph_print_overrun = set;
	/* invalid flage_name is omitted. */
}

static int tracer_no_event_context;

static void ftrace_show_function_graph_init(void);
static void ftrace_show_function_init(void);
static void ftrace_show_trace_event_init(void);

static int ftrace_show_init(void)
{
	/* ftrace_event_get_id(), ftrace_event_get_pid() should not failed. */
	if (find_event_field(event_types[0], "common_type") == NULL)
		return -1;

	if (find_event_field(event_types[0], "common_pid") == NULL)
		return -1;

	ftrace_show_function_init();
	ftrace_show_function_graph_init();
	ftrace_show_trace_event_init();

	return 0;
}

void show_event(struct format_context *fc)
{
	struct event_type *etype;
	int id;

	id = ftrace_event_get_id(fc->event.data);
	etype = find_event_type(id);

	if (etype == NULL) {
		event_printf("<Unknown event type>\n");
		return;
	}

	if (!tracer_no_event_context && gopt_context_info)
		event_context_print(etype, fc);
	if (!etype->plugin)
		event_printf("%s: ", etype->name);
	etype->printer(etype, fc);
}

static int parse_cpulist(int *cpulist, const char *cpulist_str, int len)
{
	unsigned a, b;
	const char *s = cpulist_str;

	memset(cpulist, 0, sizeof(int) * len);

	do {
		if (!isdigit(*s))
			return -1;
		b = a = strtoul(s, (char **)&s, 10);
		if (*s == '-') {
			s++;
			if (!isdigit(*s))
				return -1;
			b = strtoul(s, (char **)&s, 10);
		}
		if (!(a <= b))
			return -1;
		if (b >= len)
			return -1;
		while (a <= b) {
			cpulist[a] = 1;
			a++;
		}
		if (*s == ',')
			s++;
	} while (*s != '\0' && *s != '\n');

	return 0;
}

static void ftrace_show_function_graph_start(void);

static void ftrace_show(int argc, char *argv[])
{
	int c;
	int *cpulist = NULL;

	set_all_flags_default();
	ftrace_show_function_graph_start();

        while ((c = getopt(argc, argv, "f:c:")) != EOF) {
                switch(c)
		{
		case 'f':
			if (optarg[0] == 'n' && optarg[1] == 'o')
				set_clear_flag(optarg + 2, 0);
			else
				set_clear_flag(optarg, 1);
			break;
		case 'c':
			if (cpulist)
				goto err_arg;

			cpulist = malloc(sizeof(int) * nr_cpu_ids);
			if (cpulist == NULL) {
				error(INFO, "malloc() fail\n");
				return;
			}

			if (parse_cpulist(cpulist, optarg, nr_cpu_ids) < 0)
				goto err_arg;
			break;
		default:
			goto err_arg;
		}
	}

	if (argc - optind != 0) {
err_arg:
		cmd_usage(pc->curcmd, SYNOPSIS);
		free(cpulist);
		return;
	}

	ring_buffer_stream_init(&format_context.stream, cpulist);

	/* Ignore setjmp()'s return value, no special things to do. */
	setjmp(show_event_env);

	for (;;) {
		show_event_pos = 0;
		format_context.cpu = ring_buffer_stream_pop_event(
				&format_context.stream, &format_context.event);
		if (format_context.cpu < 0)
			break;

		show_event(&format_context);
		fprintf(fp, "%s", show_event_buf);
	}

	ring_buffer_stream_destroy(&format_context.stream, cpulist);
	free(cpulist);
}

static void cmd_ftrace(void)
{
	if (argcnt == 1)
		show_basic_info();
	else if (!strcmp(args[1], "dump"))
		ftrace_dump(argcnt - 1, args + 1);
	else if (!strcmp(args[1], "show"))
		ftrace_show(argcnt - 1, args + 1);
	else
		cmd_usage(pc->curcmd, SYNOPSIS);
}

static void event_default_print(struct event_type *t, struct format_context *fc)
{
	int i;

	/* Skip the common types */
	for (i = t->nfields - 6; i >= 0; i--) {
		struct ftrace_field *f;

		f = &t->fields[i];
		event_printf("%s=", f->name);
		event_field_print(f, fc->event.data);
		if (i)
			event_printf(", ");
	}

	event_printf("\n");
}

static void sym_print(ulong sym, int opt_offset)
{
	if (!sym) {
		event_printf("0");
	} else {
		ulong offset;
		struct syment *se;

		se = value_search(sym, &offset);
		if (se) {
			event_printf("%s", se->name);
			if (opt_offset)
				event_printf("+%lu", offset);
		}
	}
}

static void event_fn_print(struct event_type *t, struct format_context *fc)
{
	unsigned long ip = access_field(t, fc->event.data, "ip");
	unsigned long parent_ip = access_field(t, fc->event.data, "parent_ip");

	sym_print(ip, gopt_sym_offset);
	if (gopt_sym_addr)
		event_printf("<%lx>", ip);

	event_printf(" <-");

	sym_print(parent_ip, gopt_sym_offset);
	if (gopt_sym_addr)
		event_printf("<%lx>", parent_ip);

	event_printf("\n");
}

static void ftrace_show_function_init(void)
{
	struct event_type *t = find_event_type_by_name("ftrace", "function");

	if (t)
		t->printer = event_fn_print;
}

#if 0
/* simple */
static void event_fn_entry_print(struct event_type *t, struct format_context *fc)
{
	ulong func = access_field(t, fc->event.data, "graph_ent.func");
	int depth = access_field(t, fc->event.data, "graph_ent.depth");

	event_printf("%*s", depth, " ");
	sym_print(func, gopt_sym_offset);
	if (gopt_sym_addr)
		event_printf("<%lx>", func);
	event_printf("() {");
}

static void event_fn_return_print(struct event_type *t, struct format_context *fc)
{
	ulong func = access_field(t, fc->event.data, "ret.func");
	u64 calltime = access_field(t, fc->event.data, "ret.calltime");
	u64 rettime = access_field(t, fc->event.data, "ret.rettime");
	int depth = access_field(t, fc->event.data, "ret.depth");

	event_printf("%*s} %lluns", depth, " ",
			(unsigned long long)(rettime - calltime));
}

static void ftrace_show_function_graph_init(void)
{
	struct event_type *t1 = find_event_type_by_name(
			"ftrace", "funcgraph_entry");
	struct event_type *t2 = find_event_type_by_name(
			"ftrace", "funcgraph_exit");

	if (t1 == NULL || t2 == NULL)
		return;

	t1->printer = event_fn_entry_print;
	t2->printer = event_fn_return_print;
}
#endif


#define TRACE_GRAPH_PROCINFO_LENGTH	14
#define TRACE_GRAPH_INDENT		2

static int max_bytes_for_cpu;
static int *cpus_prev_pid;

static int function_graph_entry_id;
static int function_graph_return_id;
static struct event_type *function_graph_entry_type;
static struct event_type *function_graph_return_type;

static void ftrace_show_function_graph_start(void)
{
	int i;

	if (cpus_prev_pid == NULL)
		return;

	for (i = 0; i < nr_cpu_ids; i++)
		cpus_prev_pid[i] = -1;
}

static void fn_graph_proc_print(int pid)
{
	int pid_strlen, comm_strlen;
	char pid_str[20];
	char comm[20] = "<...>";

	pid_strlen = sprintf(pid_str, "%d", pid);
	comm_strlen = TRACE_GRAPH_PROCINFO_LENGTH - 1 - pid_strlen;

	get_comm_from_pid(pid, comm);
	event_printf("%*.*s-%s", comm_strlen, comm_strlen, comm, pid_str);
}

/* If the pid changed since the last trace, output this event */
static void fn_graph_proc_switch_print(int pid, int cpu)
{
	int prev_pid = cpus_prev_pid[cpu];

	cpus_prev_pid[cpu] = pid;
	if ((prev_pid == pid) || (prev_pid == -1))
		return;

/*
 * Context-switch trace line:

 ------------------------------------------
 | 1)  migration/0--1  =>  sshd-1755
 ------------------------------------------

 */

	event_printf(" ------------------------------------------\n");
	event_printf(" %*d) ", max_bytes_for_cpu, cpu);
	fn_graph_proc_print(prev_pid);
	event_printf(" => ");
	fn_graph_proc_print(pid);
	event_printf("\n ------------------------------------------\n\n");
}

/* Signal a overhead of time execution to the output */
static void fn_graph_overhead_print(unsigned long long duration)
{
	const char *s = "  ";

	/* If duration disappear, we don't need anything */
	if (!gopt_graph_print_duration)
		return;

	/* duration == -1 is for non nested entry or return */
	if ((duration != -1) && gopt_graph_print_overhead) {
		/* Duration exceeded 100 msecs */
		if (duration > 100000ULL)
			s = "! ";
		/* Duration exceeded 10 msecs */
		else if (duration > 10000ULL)
			s = "+ ";
	}

	event_printf(s);
}

static void fn_graph_abstime_print(u64 ts)
{
	u64 time = ts / 1000;
	unsigned long sec = time / 1000000;
	unsigned long usec = time % 1000000;

	event_printf("%5lu.%06lu |  ", sec, usec);
}

static void fn_graph_irq_print(int type)
{
	/* TODO: implement it. */
}

static void fn_graph_duration_print(unsigned long long duration)
{
	/* log10(ULONG_MAX) + '\0' */
	char msecs_str[21];
	char nsecs_str[5];
	int len;
	unsigned long nsecs_rem = duration % 1000;

	duration = duration / 1000;
	len = sprintf(msecs_str, "%lu", (unsigned long) duration);

	/* Print msecs */
	event_printf("%s", msecs_str);

	/* Print nsecs (we don't want to exceed 7 numbers) */
	if (len < 7) {
		snprintf(nsecs_str, 8 - len, "%03lu", nsecs_rem);
		event_printf(".%s", nsecs_str);

		len += strlen(nsecs_str);
	}

	if (len > 7)
		len = 7;

	event_printf(" us %*s|  ", 7 - len, "");
}

/* Case of a leaf function on its call entry */
static void fn_graph_entry_leaf_print(void *entry_data, void *exit_data)
{
	struct event_type *t = function_graph_return_type;

	u64 calltime = access_field(t, exit_data, "ret.calltime");
	u64 rettime = access_field(t, exit_data, "ret.rettime");
	u64 duration = rettime - calltime;
	int depth = access_field(t, exit_data, "ret.depth");
	ulong func = access_field(t, exit_data, "ret.func");

	fn_graph_overhead_print(duration);
	if (gopt_graph_print_duration)
		fn_graph_duration_print(duration);

	event_printf("%*s", depth * TRACE_GRAPH_INDENT, "");
	sym_print(func, 0);
	event_printf("();\n");
}

static void fn_graph_entry_nested_print(struct event_type *t, void *data)
{
	int depth = access_field(t, data, "graph_ent.depth");
	ulong func = access_field(t, data, "graph_ent.func");

	fn_graph_overhead_print(-1);

	/* No time */
	if (gopt_graph_print_duration)
		event_printf("            |  ");

	event_printf("%*s", depth * TRACE_GRAPH_INDENT, "");
	sym_print(func, 0);
	event_printf("() {\n");
}

static void fn_graph_prologue_print(int cpu, u64 ts, int pid, int type)
{
	fn_graph_proc_switch_print(pid, cpu);

	if (type)
		fn_graph_irq_print(type);

	if (gopt_graph_print_abstime)
		fn_graph_abstime_print(ts);

	if (gopt_graph_print_cpu)
		 event_printf(" %*d) ", max_bytes_for_cpu, cpu);

	if (gopt_graph_print_proc) {
		fn_graph_proc_print(pid);
		event_printf(" | ");
	}
}

static void *get_return_for_leaf(struct event_type *t,
		struct format_context *fc, void *curr_data)
{
	int cpu;
	struct ftrace_event next;
	ulong entry_func, exit_func;

	cpu = ring_buffer_stream_pop_event(&fc->stream, &next);

	if (cpu < 0)
		goto not_leaf;

	if (ftrace_event_get_id(next.data) != function_graph_return_id)
		goto not_leaf;

	if (ftrace_event_get_pid(curr_data) != ftrace_event_get_pid(next.data))
		goto not_leaf;

	entry_func = access_field(t, curr_data, "graph_ent.func");
	exit_func = access_field(function_graph_return_type, next.data,
			"ret.func");

	if (entry_func != exit_func)
		goto not_leaf;

	return next.data;

not_leaf:
	ring_buffer_stream_push_current_event(&fc->stream);
	return NULL;
}

static
void event_fn_entry_print(struct event_type *t, struct format_context *fc)
{
	void *leaf_ret_data = NULL, *curr_data = fc->event.data, *data;
	int pid = ftrace_event_get_pid(curr_data);

	fn_graph_prologue_print(fc->cpu, fc->event.ts, pid, 1);

	data = alloca(fc->event.length);
	if (data) {
		memcpy(data, fc->event.data, fc->event.length);
		curr_data = data;
		leaf_ret_data = get_return_for_leaf(t, fc, curr_data);
	}

	if (leaf_ret_data)
		return fn_graph_entry_leaf_print(curr_data, leaf_ret_data);
	else
		return fn_graph_entry_nested_print(t, curr_data);
}

static
void event_fn_return_print(struct event_type *t, struct format_context *fc)
{
	void *data = fc->event.data;
	int pid = ftrace_event_get_pid(data);

	u64 calltime = access_field(t, data, "ret.calltime");
	u64 rettime = access_field(t, data, "ret.rettime");
	u64 duration = rettime - calltime;
	int depth = access_field(t, data, "ret.depth");

	fn_graph_prologue_print(fc->cpu, fc->event.ts, pid, 0);
	fn_graph_overhead_print(duration);

	if (gopt_graph_print_duration)
		fn_graph_duration_print(duration);

	event_printf("%*s}\n", depth * TRACE_GRAPH_INDENT, "");

	if (gopt_graph_print_overrun) {
		unsigned long overrun = access_field(t, data, "ret.overrun");
		event_printf(" (Overruns: %lu)\n", overrun);
	}

	fn_graph_irq_print(0);
}

static void ftrace_show_function_graph_init(void)
{
	if (strcmp(current_tracer_name, "function_graph"))
		return;

	function_graph_entry_type = find_event_type_by_name(
			"ftrace", "funcgraph_entry");
	function_graph_return_type = find_event_type_by_name(
			"ftrace", "funcgraph_exit");

	if (!function_graph_entry_type || !function_graph_return_type)
		return;

	/*
	 * Because of get_return_for_leaf(), the exception handling
	 * of access_field() is not work for function_graph. So we need
	 * to ensure access_field() will not failed for these fields.
	 *
	 * I know these will not failed. I just ensure it.
	 */

	if (!find_event_field(function_graph_entry_type, "graph_ent.func"))
		return;

	if (!find_event_field(function_graph_entry_type, "graph_ent.depth"))
		return;

	if (!find_event_field(function_graph_return_type, "ret.func"))
		return;

	if (!find_event_field(function_graph_return_type, "ret.calltime"))
		return;

	if (!find_event_field(function_graph_return_type, "ret.rettime"))
		return;

	if (!find_event_field(function_graph_return_type, "ret.overrun"))
		return;

	if (!find_event_field(function_graph_return_type, "ret.depth"))
		return;

	cpus_prev_pid = malloc(sizeof(int) * nr_cpu_ids);
	if (!cpus_prev_pid)
		return;

	max_bytes_for_cpu = snprintf(NULL, 0, "%d", nr_cpu_ids - 1);

	function_graph_entry_id = function_graph_entry_type->id;
	function_graph_return_id = function_graph_return_type->id;

	/* OK, set the printer for function_graph. */
	tracer_no_event_context = 1;
	function_graph_entry_type->printer = event_fn_entry_print;
	function_graph_return_type->printer = event_fn_return_print;
}

static void event_sched_kthread_stop_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"));
}

static void event_sched_kthread_stop_ret_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("ret %d\n", (int)access_field(t, fc->event.data, "ret"));
}

static void event_sched_wait_task_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d [%d]\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"),
			(int)access_field(t, fc->event.data, "prio"));
}

static void event_sched_wakeup_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d [%d] success=%d\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"),
			(int)access_field(t, fc->event.data, "prio"),
			(int)access_field(t, fc->event.data, "success"));
}

static void event_sched_wakeup_new_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d [%d] success=%d\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"),
			(int)access_field(t, fc->event.data, "prio"),
			(int)access_field(t, fc->event.data, "success"));
}

static void event_sched_switch_print(struct event_type *t,
		struct format_context *fc)
{
	char *prev_comm = (char *)(long)access_field(t, fc->event.data,
			"prev_comm");
	int prev_pid = access_field(t, fc->event.data, "prev_pid");
	int prev_prio = access_field(t, fc->event.data, "prev_prio");

	int prev_state = access_field(t, fc->event.data, "prev_state");

	char *next_comm = (char *)(long)access_field(t, fc->event.data,
			"next_comm");
	int next_pid = access_field(t, fc->event.data, "next_pid");
	int next_prio = access_field(t, fc->event.data, "next_prio");

	event_printf("task %s:%d [%d] (", prev_comm, prev_pid, prev_prio);

	if (prev_state == 0) {
		event_printf("R");
	} else {
		if (prev_state & 1)
			event_printf("S");
		if (prev_state & 2)
			event_printf("D");
		if (prev_state & 4)
			event_printf("T");
		if (prev_state & 8)
			event_printf("t");
		if (prev_state & 16)
			event_printf("Z");
		if (prev_state & 32)
			event_printf("X");
		if (prev_state & 64)
			event_printf("x");
		if (prev_state & 128)
			event_printf("W");
	}

	event_printf(") ==> %s:%d [%d]\n", next_comm, next_pid, next_prio);
}

static void event_sched_migrate_task_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d [%d] from: %d  to: %d\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"),
			(int)access_field(t, fc->event.data, "prio"),
			(int)access_field(t, fc->event.data, "orig_cpu"),
			(int)access_field(t, fc->event.data, "dest_cpu"));
}

static void event_sched_process_free_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d [%d]\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"),
			(int)access_field(t, fc->event.data, "prio"));
}

static void event_sched_process_exit_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d [%d]\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"),
			(int)access_field(t, fc->event.data, "prio"));
}

static void event_sched_process_wait_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("task %s:%d [%d]\n",
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"),
			(int)access_field(t, fc->event.data, "prio"));
}

static void event_sched_process_fork_print(struct event_type *t,
		struct format_context *fc)
{
	char *parent_comm = (char *)(long)access_field(t, fc->event.data,
			"parent_comm");
	int parent_pid = access_field(t, fc->event.data, "parent_pid");

	char *child_comm = (char *)(long)access_field(t, fc->event.data,
			"child_comm");
	int child_pid = access_field(t, fc->event.data, "child_pid");

	event_printf("parent %s:%d  child %s:%d\n", parent_comm, parent_pid,
			child_comm, child_pid);
}

static void event_sched_signal_send_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("sig: %d  task %s:%d\n",
			(int)access_field(t, fc->event.data, "sig"),
			(char *)(long)access_field(t, fc->event.data, "comm"),
			(int)access_field(t, fc->event.data, "pid"));
}

static void event_kmalloc_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("call_site=%lx ptr=%p bytes_req=%zu bytes_alloc=%zu "
			"gfp_flags=%lx\n",
			(long)access_field(t, fc->event.data, "call_site"),
			(void *)(long)access_field(t, fc->event.data, "ptr"),
			(size_t)access_field(t, fc->event.data, "bytes_req"),
			(size_t)access_field(t, fc->event.data, "bytes_alloc"),
			(long)access_field(t, fc->event.data, "gfp_flags"));
}

static void event_kmem_cache_alloc_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("call_site=%lx ptr=%p bytes_req=%zu bytes_alloc=%zu "
			"gfp_flags=%lx\n",
			(long)access_field(t, fc->event.data, "call_site"),
			(void *)(long)access_field(t, fc->event.data, "ptr"),
			(size_t)access_field(t, fc->event.data, "bytes_req"),
			(size_t)access_field(t, fc->event.data, "bytes_alloc"),
			(long)access_field(t, fc->event.data, "gfp_flags"));
}

static void event_kmalloc_node_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("call_site=%lx ptr=%p bytes_req=%zu bytes_alloc=%zu "
			"gfp_flags=%lx node=%d\n",
			(long)access_field(t, fc->event.data, "call_site"),
			(void *)(long)access_field(t, fc->event.data, "ptr"),
			(size_t)access_field(t, fc->event.data, "bytes_req"),
			(size_t)access_field(t, fc->event.data, "bytes_alloc"),
			(long)access_field(t, fc->event.data, "gfp_flags"),
			(int)access_field(t, fc->event.data, "node"));
}

static void event_kmem_cache_alloc_node_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("call_site=%lx ptr=%p bytes_req=%zu bytes_alloc=%zu "
			"gfp_flags=%lx node=%d\n",
			(long)access_field(t, fc->event.data, "call_site"),
			(void *)(long)access_field(t, fc->event.data, "ptr"),
			(size_t)access_field(t, fc->event.data, "bytes_req"),
			(size_t)access_field(t, fc->event.data, "bytes_alloc"),
			(long)access_field(t, fc->event.data, "gfp_flags"),
			(int)access_field(t, fc->event.data, "node"));
}

static void event_kfree_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("call_site=%lx ptr=%p\n",
			(long)access_field(t, fc->event.data, "call_site"),
			(void *)(long)access_field(t, fc->event.data, "ptr"));
}

static void event_kmem_cache_free_print(struct event_type *t,
		struct format_context *fc)
{
	event_printf("call_site=%lx ptr=%p\n",
			(long)access_field(t, fc->event.data, "call_site"),
			(void *)(long)access_field(t, fc->event.data, "ptr"));
}

static void event_workqueue_insertion_print(struct event_type *t,
		struct format_context *fc)
{
	char *thread_comm = (char *)(long)access_field(t, fc->event.data,
			"thread_comm");
	int thread_pid = access_field(t, fc->event.data, "thread_pid");
	ulong func = access_field(t, fc->event.data, "func");

	event_printf("thread=%s:%d func=", thread_comm, thread_pid);
	sym_print(func, 1);
	event_printf("\n");
}

static void event_workqueue_execution_print(struct event_type *t,
		struct format_context *fc)
{
	char *thread_comm = (char *)(long)access_field(t, fc->event.data,
			"thread_comm");
	int thread_pid = access_field(t, fc->event.data, "thread_pid");
	ulong func = access_field(t, fc->event.data, "func");

	event_printf("thread=%s:%d func=", thread_comm, thread_pid);
	sym_print(func, 1);
	event_printf("\n");
}

static void event_workqueue_creation_print(struct event_type *t,
		struct format_context *fc)
{
	char *thread_comm = (char *)(long)access_field(t, fc->event.data,
			"thread_comm");
	int thread_pid = access_field(t, fc->event.data, "thread_pid");
	int cpu = access_field(t, fc->event.data, "cpu");

	event_printf("thread=%s:%d cpu=%d\n", thread_comm, thread_pid, cpu);
}

static void event_workqueue_destruction_print(struct event_type *t,
		struct format_context *fc)
{
	char *thread_comm = (char *)(long)access_field(t, fc->event.data,
			"thread_comm");
	int thread_pid = access_field(t, fc->event.data, "thread_pid");

	event_printf("thread=%s:%d\n", thread_comm, thread_pid);
}

static void ftrace_show_trace_event_init(void)
{
#define init_trace_event(system, name)					\
do {									\
	struct event_type *t = find_event_type_by_name(#system, #name);	\
	if (t)								\
		t->printer = event_ ## name ## _print;			\
} while (0)

	init_trace_event(sched, sched_kthread_stop);
	init_trace_event(sched, sched_kthread_stop_ret);
	init_trace_event(sched, sched_wait_task);
	init_trace_event(sched, sched_wakeup);
	init_trace_event(sched, sched_wakeup_new);
	init_trace_event(sched, sched_switch);
	init_trace_event(sched, sched_migrate_task);
	init_trace_event(sched, sched_process_free);
	init_trace_event(sched, sched_process_exit);
	init_trace_event(sched, sched_process_wait);
	init_trace_event(sched, sched_process_fork);
	init_trace_event(sched, sched_signal_send);

	init_trace_event(kmem, kmalloc);
	init_trace_event(kmem, kmem_cache_alloc);
	init_trace_event(kmem, kmalloc_node);
	init_trace_event(kmem, kmem_cache_alloc_node);
	init_trace_event(kmem, kfree);
	init_trace_event(kmem, kmem_cache_free);

	init_trace_event(workqueue, workqueue_insertion);
	init_trace_event(workqueue, workqueue_execution);
	init_trace_event(workqueue, workqueue_creation);
	init_trace_event(workqueue, workqueue_destruction);
#undef init_trace_event
}

static void ftrace_show_destroy(void)
{
	free(cpus_prev_pid);
}

static char *help_ftrace[] = {
"trace",
"show or dump the tracing info",
"[ <show [-c <cpulist>] [-f [no]<flagname>]> | <dump [-sm] <dest-dir>> ]",
"trace",
"    shows the current tracer and other informations.",
"",
"trace show [ -c <cpulist> ] [ -f [no]<flagename> ]",
"    shows all events with readability text(sorted by timestamp)",
"    -c: only shows specified CPUs' events.",
"        ex. trace show -c 1,2    - only shows cpu#1 and cpu#2 's events.",
"            trace show -c 0,2-7  - only shows cpu#0, cpu#2...cpu#7's events.",
"    -f: set or clear a flag",
"        available flags            default",
"        context_info               true",
"        sym_offset                 false",
"        sym_addr                   false",
"        graph_print_duration       true",
"        graph_print_overhead       true",
"        graph_print_abstime        false",
"        graph_print_cpu            true",
"        graph_print_proc           false",
"        graph_print_overrun        false",
"",
"trace dump [-sm] <dest-dir>",
"    dump ring_buffers to dest-dir. Then you can parse it",
"    by other tracing tools. The dirs and files are generated",
"    the same as debugfs/tracing.",
"    -m: also dump metadata of ftrace.",
"    -s: also dump symbols of the kernel <not implemented>.",
"trace dump -t [output-file-name]",
"   dump ring_buffers and all meta data to a file that can",
"   be parsed by trace-cmd. Default output file name is \"trace.dat\".",
NULL
};

static struct command_table_entry command_table[] = {
	{ "trace", cmd_ftrace, help_ftrace, 0 },
	{ NULL, 0, 0, 0 }
};

static int ftrace_initialized;

int _init(void)
{
	if (ftrace_init() < 0)
		return 0;

	ftrace_initialized = 1;
	register_extension(command_table);

	return 1;
}

int _fini(void)
{
	if (ftrace_initialized)
		ftrace_destroy();

	return 1;
}

#define TRACE_CMD_FILE_VERSION_STRING "6"

static inline int host_bigendian(void)
{
	unsigned char str[] = { 0x1, 0x2, 0x3, 0x4 };
	unsigned int *ptr;

	ptr = (unsigned int *)str;
	return *ptr == 0x01020304;
}

static char *tmp_file_buf;
static unsigned long long tmp_file_pos;
static unsigned long long tmp_file_size;
static int tmp_file_error;

static int init_tmp_file(void)
{
	tmp_file_buf = malloc(4096);
	if (tmp_file_buf == NULL)
		return -1;

	tmp_file_pos = 0;
	tmp_file_size = 4096;
	tmp_file_error = 0;

	return 0;
}

static void destory_tmp_file(void)
{
	free(tmp_file_buf);
}

#define tmp_fprintf(fmt...)						\
do {									\
	char *__buf = tmp_file_buf;					\
	unsigned long long __pos;					\
									\
	if (tmp_file_error)						\
		break;							\
	__pos = tmp_file_pos;						\
	__pos += snprintf(__buf + __pos, tmp_file_size - __pos, fmt);	\
	if (__pos > tmp_file_size) {					\
		tmp_file_size = __pos + tmp_file_size;			\
		__buf = realloc(__buf, tmp_file_size);			\
		if (!__buf) {						\
			tmp_file_error = 1;				\
			break;						\
		}							\
		tmp_file_buf = __buf;					\
		__pos = tmp_file_pos;					\
		__pos += snprintf(__buf + __pos, tmp_file_size - __pos, fmt);\
	}								\
	tmp_file_pos = __pos;						\
} while (0)

static int tmp_file_record_size4(int fd)
{
	unsigned int size = tmp_file_pos;

	if (tmp_file_error)
		return -1;
	if (write_and_check(fd, &size, 4))
		return -1;
	return 0;
}

static int tmp_file_record_size8(int fd)
{
	if (tmp_file_error)
		return -1;
	if (write_and_check(fd, &tmp_file_pos, 8))
		return -1;
	return 0;
}

static int tmp_file_flush(int fd)
{
	if (tmp_file_error)
		return -1;
	if (write_and_check(fd, tmp_file_buf, tmp_file_pos))
		return -1;
	tmp_file_pos = 0;
	return 0;
}

static int save_initial_data(int fd)
{
	int page_size;
	char buf[20];

	if (write_and_check(fd, "\027\010\104tracing", 10))
		return -1;

	if (write_and_check(fd, TRACE_CMD_FILE_VERSION_STRING,
				strlen(TRACE_CMD_FILE_VERSION_STRING) + 1))
		return -1;

	/* Crash ensure core file endian and the host endian are the same */
	if (host_bigendian())
		buf[0] = 1;
	else
		buf[0] = 0;

	if (write_and_check(fd, buf, 1))
		return -1;

	/* save size of long (this may not be what the kernel is) */
	buf[0] = sizeof(long);
	if (write_and_check(fd, buf, 1))
		return -1;

	page_size = PAGESIZE();
	if (write_and_check(fd, &page_size, 4))
		return -1;

	return 0;
}

static int save_header_files(int fd)
{
	/* save header_page */
	if (write_and_check(fd, "header_page", 12))
		return -1;

	tmp_fprintf("\tfield: u64 timestamp;\toffset:0;\tsize:8;\tsigned:0;\n");

	tmp_fprintf("\tfield: local_t commit;\toffset:8;\tsize:%u;\t"
			"signed:1;\n", (unsigned int)sizeof(long));

	tmp_fprintf("\tfield: int overwrite;\toffset:8;\tsize:%u;\tsigned:1;\n",
			(unsigned int)sizeof(long));

	tmp_fprintf("\tfield: char data;\toffset:%u;\tsize:%u;\tsigned:1;\n",
			(unsigned int)(8 + sizeof(long)),
			(unsigned int)(PAGESIZE() - 8 - sizeof(long)));

	if (tmp_file_record_size8(fd))
		return -1;
	if (tmp_file_flush(fd))
		return -1;

	/* save header_event */
	if (write_and_check(fd, "header_event", 13))
		return -1;

	tmp_fprintf(
			"# compressed entry header\n"
			"\ttype_len    :    5 bits\n"
			"\ttime_delta  :   27 bits\n"
			"\tarray       :   32 bits\n"
			"\n"
			"\tpadding     : type == 29\n"
			"\ttime_extend : type == 30\n"
			"\tdata max type_len  == 28\n"
	);

	if (tmp_file_record_size8(fd))
		return -1;
	if (tmp_file_flush(fd))
		return -1;

	return 0;
}

static int save_event_file(int fd, struct event_type *t)
{
	int i;
	int common_field_count = 5;

	tmp_fprintf("name: %s\n", t->name);
	tmp_fprintf("ID: %d\n", t->id);
	tmp_fprintf("format:\n");

	for (i = t->nfields - 1; i >= 0; i--) {
		/*
		 * Smartly shows the array type(except dynamic array).
		 * Normal:
		 *	field:TYPE VAR
		 * If TYPE := TYPE[LEN], it is shown:
		 *	field:TYPE VAR[LEN]
		 */
		struct ftrace_field *field = &t->fields[i];
		const char *array_descriptor = strchr(field->type, '[');

		if (!strncmp(field->type, "__data_loc", 10))
			array_descriptor = NULL;

		if (!array_descriptor) {
			tmp_fprintf("\tfield:%s %s;\toffset:%u;"
					"\tsize:%u;\tsigned:%d;\n",
					field->type, field->name, field->offset,
					field->size, !!field->is_signed);
		} else {
			tmp_fprintf("\tfield:%.*s %s%s;\toffset:%u;"
					"\tsize:%u;\tsigned:%d;\n",
					(int)(array_descriptor - field->type),
					field->type, field->name,
					array_descriptor, field->offset,
					field->size, !!field->is_signed);
		}

		if (--common_field_count == 0)
			tmp_fprintf("\n");
	}

	tmp_fprintf("\nprint fmt: %s\n", t->print_fmt);

	if (tmp_file_record_size8(fd))
		return -1;
	return tmp_file_flush(fd);
}

static int save_system_files(int fd, int *system_ids, int system_id)
{
	int i, total = 0;

	for (i = 0; i < nr_event_types; i++) {
		if (system_ids[i] == system_id)
			total++;
	}

	if (write_and_check(fd, &total, 4))
		return -1;

	for (i = 0; i < nr_event_types; i++) {
		if (system_ids[i] != system_id)
			continue;

		if (save_event_file(fd, event_types[i]))
			return -1;
	}

	return 0;
}

static int save_events_files(int fd)
{
	int system_id = 1, *system_ids;
	const char *system = "ftrace";
	int i;
	int nr_systems;

	system_ids = calloc(sizeof(*system_ids), nr_event_types);
	if (system_ids == NULL)
		return -1;

	for (;;) {
		for (i = 0; i < nr_event_types; i++) {
			if (system_ids[i])
				continue;
			if (!system) {
				system = event_types[i]->system;
				system_ids[i] = system_id;
				continue;
			}
			if (!strcmp(event_types[i]->system, system))
				system_ids[i] = system_id;
		}
		if (!system)
			break;
		system_id++;
		system = NULL;
	}

	/* ftrace events */
	if (save_system_files(fd, system_ids, 1))
		goto fail;

	/* other systems events */
	nr_systems = system_id - 2;
	if (write_and_check(fd, &nr_systems, 4))
		goto fail;
	for (system_id = 2; system_id < nr_systems + 2; system_id++) {
		for (i = 0; i < nr_event_types; i++) {
			if (system_ids[i] == system_id)
				break;
		}
		if (write_and_check(fd, (void *)event_types[i]->system,
				strlen(event_types[i]->system) + 1))
			goto fail;
		if (save_system_files(fd, system_ids, system_id))
			goto fail;
	}

	free(system_ids);
	return 0;

fail:
	free(system_ids);
	return -1;
}

static int save_proc_kallsyms(int fd)
{
	int i;
	struct syment *sp;

	for (sp = st->symtable; sp < st->symend; sp++)
		tmp_fprintf("%lx %c %s\n", sp->value, sp->type, sp->name);

	for (i = 0; i < st->mods_installed; i++) {
		struct load_module *lm = &st->load_modules[i];

		for (sp = lm->mod_symtable; sp <= lm->mod_symend; sp++) {
			if (!strncmp(sp->name, "_MODULE_", strlen("_MODULE_")))
				continue;

			tmp_fprintf("%lx %c %s\t[%s]\n", sp->value, sp->type,
					sp->name, lm->mod_name);
		}
	}

	if (tmp_file_record_size4(fd))
		return -1;
	return tmp_file_flush(fd);
}

static int save_ftrace_printk(int fd)
{
	struct syment *s, *e;
	long bprintk_fmt_s, bprintk_fmt_e;
	char string[4096];
	long *address;
	size_t i, count;

	s = symbol_search("__start___trace_bprintk_fmt");
	e = symbol_search("__stop___trace_bprintk_fmt");
	if (s == NULL || e == NULL)
		return -1;

	bprintk_fmt_s = s->value;
	bprintk_fmt_e = e->value;
	count = (bprintk_fmt_e - bprintk_fmt_s) / sizeof(long);

	if (count == 0) {
		unsigned int size = 0;
		return write_and_check(fd, &size, 4);
	}

	address = malloc(count * sizeof(long));
	if (address == NULL)
		return -1;

	if (!readmem(bprintk_fmt_s, KVADDR, address, count * sizeof(long),
			"get printk address", RETURN_ON_ERROR)) {
		free(address);
		return -1;
	}

	for (i = 0; i < count; i++) {
		size_t len = read_string(address[i], string, sizeof(string));
		if (!len) {
			free(address);
			return -1;
		}

		tmp_fprintf("0x%lx : \"", address[i]);

		for (i = 0; string[i]; i++) {
			switch (string[i]) {
			case '\n':
				tmp_fprintf("\\n");
				break;
			case '\t':
				tmp_fprintf("\\t");
				break;
			case '\\':
				tmp_fprintf("\\\\");
				break;
			case '"':
				tmp_fprintf("\\\"");
				break;
			default:
				tmp_fprintf("%c", string[i]);
			}
		}
		tmp_fprintf("\"\n");
	}

	free(address);

	if (tmp_file_record_size4(fd))
		return -1;
	return tmp_file_flush(fd);
}

static int save_ftrace_cmdlines(int fd)
{
	int i;
	struct task_context *tc = FIRST_CONTEXT();

	for (i = 0; i < RUNNING_TASKS(); i++)
		tmp_fprintf("%d %s\n", (int)tc[i].pid, tc[i].comm);

	if (tmp_file_record_size8(fd))
		return -1;
	return tmp_file_flush(fd);
}

static int save_res_data(int fd, int nr_cpu_buffers)
{
	unsigned short option = 0;

	if (write_and_check(fd, &nr_cpu_buffers, 4))
		return -1;

	if (write_and_check(fd, "options  ", 10))
		return -1;

	if (write_and_check(fd, &option, 2))
		return -1;

	if (write_and_check(fd, "flyrecord", 10))
		return -1;

	return 0;
}

static int save_record_data(int fd, int nr_cpu_buffers)
{
	int i, j;
	unsigned long long offset, buffer_offset;
	void *page_tmp;

	offset = lseek(fd, 0, SEEK_CUR);
	offset += nr_cpu_buffers * 16;
	offset = (offset + (PAGESIZE() - 1)) & ~(PAGESIZE() - 1);
	buffer_offset = offset;

	for (i = 0; i < nr_cpu_ids; i++) {
		struct ring_buffer_per_cpu *cpu_buffer = &global_buffers[i];
		unsigned long long buffer_size;

		if (!cpu_buffer->kaddr)
			continue;

		buffer_size = PAGESIZE() * cpu_buffer->nr_linear_pages;
		if (write_and_check(fd, &buffer_offset, 8))
			return -1;
		if (write_and_check(fd, &buffer_size, 8))
			return -1;
		buffer_offset += buffer_size;
	}

	page_tmp = malloc(PAGESIZE());
	if (page_tmp == NULL)
		return -1;

	lseek(fd, offset, SEEK_SET);
	for (i = 0; i < nr_cpu_ids; i++) {
		struct ring_buffer_per_cpu *cpu_buffer = &global_buffers[i];

		if (!cpu_buffer->kaddr)
			continue;

		for (j = 0; j < cpu_buffer->nr_linear_pages; j++) {
			if (ftrace_dump_page(fd, cpu_buffer->linear_pages[j],
					page_tmp) < 0) {
				free(page_tmp);
				return -1;
			}
		}
	}

	free(page_tmp);

	return 0;
}

static int __trace_cmd_data_output(int fd)
{
	int i;
	int nr_cpu_buffers = 0;

	for (i = 0; i < nr_cpu_ids; i++) {
		struct ring_buffer_per_cpu *cpu_buffer = &global_buffers[i];

		if (!cpu_buffer->kaddr)
			continue;

		nr_cpu_buffers++;
	}

	if (save_initial_data(fd))
		return -1;
	if (save_header_files(fd))
		return -1;
	if (save_events_files(fd)) /* ftrace events and other systems events */
		return -1;
	if (save_proc_kallsyms(fd))
		return -1;
	if (save_ftrace_printk(fd))
		return -1;
	if (save_ftrace_cmdlines(fd))
		return -1;
	if (save_res_data(fd, nr_cpu_buffers))
		return -1;
	if (save_record_data(fd, nr_cpu_buffers))
		return -1;

	return 0;
}

static int trace_cmd_data_output(int fd)
{
	int ret;

	if (init_tmp_file())
		return -1;

	ret = __trace_cmd_data_output(fd);
	destory_tmp_file();

	return ret;
}
