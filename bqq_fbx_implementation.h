
#ifndef BQQ_FBX_IMPLEMENTED
#define BQQ_FBX_IMPLEMENTED

#include "bqq_fbx.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

// Minimum allocation size in bytes
#ifndef BFBX_MIN_ALLOCATION_SIZE
#define BFBX_MIN_ALLOCATION_SIZE 0x10000
#endif


// -- Common types

typedef struct bfbx_ctx_s bfbx_ctx;
typedef struct bfbx_append_chunk_s bfbx_append_chunk;

typedef struct {
	uint32_t length;  // < Length in bytes
	const char *data; // < Non-null-terminated pointer to the file buffer
} bfbx_fstring;

typedef struct {
	bfbx_append_chunk *first; // < First chunk in the list
	bfbx_append_chunk *last;  // < Last chunk in the list (actively appended to)
	uint32_t count;           // < Total number of items in the list
} bfbx_append_list;

// -- Memory arena

typedef struct {
	char *chunk;   // < Current memory chunk, starts with pointer to next
	uint32_t pos;  // < Current allocation offset
	uint32_t size; // < Size of the current chunk
} bfbx_arena;

static void *bfbx_alloc(bfbx_arena *arena, uint32_t size)
{
	if (size == 0) {
		return NULL;
	}

	size = (size + 7) & ~7; // Align all allocations to 8 bytes
	if (arena->pos + size <= arena->size) {
		uint32_t pos = arena->pos;
		arena->pos = pos + size;
		return arena->chunk + pos;
	} else {
		uint32_t next_size = arena->size * 2;
		if (next_size < BFBX_MIN_ALLOCATION_SIZE) next_size = BFBX_MIN_ALLOCATION_SIZE;
		if (next_size < size + 8) next_size = size + 8;
		char *chunk = (char*)malloc(next_size);
		if (!chunk) {
			return NULL;
		}
		*(void**)chunk = arena->chunk;
		arena->chunk = chunk;
		arena->pos = 8 + size;
		arena->size = next_size;
		return chunk + 8;
	}
}

static void bfbx_free_chunk(void *arena_chunk)
{
	while (arena_chunk) {
		void *next = *(void**)arena_chunk;
		free(arena_chunk);
		arena_chunk = next;
	}
}

// -- Document property map

typedef struct {
	bfbx_fstring type;
} bfbx_dprop_info;

typedef int (*bfbx_prop_parse_fn)(bfbx_ctx *bc, void *dst, const bfbx_dprop_info *info);

// Static description of a property
typedef struct {
	const char *name;             // < Name of the FBX property
	size_t field_offset;          // < Offset of the C++ struct field
	bfbx_prop_parse_fn parse_fn;  // < Parse callback function
} bfbx_dprop_desc;

typedef struct {
	uint16_t name_length; // < Length of the property name in bytes
	uint16_t prop_index;  // < Index in `props`
} bfbx_dprop_map_entry;

typedef struct {
	const bfbx_dprop_desc *props; // < List of property descriptions
	uint32_t num_props;           // < Amount of `props`

	bfbx_dprop_map_entry *map; // < Mapping from `bfbx_dprop_hash()` to `props`
	uint32_t map_size;         // < Number of elements in `index_map`, power of two
} bfbx_dprop_map;

typedef struct {
	void *default_value;     // < Default values, memcpy'd to new instances
	bfbx_dprop_map prop_map; // < FBX Property mapping
	uint32_t size;           // < Size in bytes
} bfbx_object_type;

// -- File context
// This is the main context structure passed to every function

struct bfbx_ctx_s {
	// Input file
	const char *data; // < Memory block containing the whole file
	uint32_t pos;     // < Current byte position into the buffer
	uint32_t size;    // < Size of the file in bytes
	uint32_t version; // < File version number

	// Error handling
	int failed;           // < Loading the file failed in some way
	int warnings;         // < Number of non-fatal warnings with the file
	bqq_fbx_error *error; // < Pointer to an user supplied error struct

	// Memory allocation
	bfbx_arena temp_arena;   // < Temporary allocations, thrown away when done
	bfbx_arena result_arena; // < Output allocations, freed when user is done

	// Scene contents
	bfbx_append_list all_objects;

	// Type-specific properties
	bfbx_object_type object_types[bqq_fbx_num_types];
};

#define bfbx_append(bc, list, type) (type*)bfbx_append_size((bc), (list), sizeof(type))

// -- File parse result data types.
// The data structures contain pointers to the file buffer memory.

typedef enum {
	bfbx_array_encoding_none = 0,
	bfbx_array_encoding_deflate = 1,
} bfbx_array_encoding;

typedef struct {
	uint32_t length;              // < Number of elements in the array
	bfbx_array_encoding encoding; // < Array data compression
	uint32_t compressed_bytes;    // < Compressed data size in bytes
	const void *compressed_data;  // < Data pointer in the file buffer (potentially compressed)
} bfbx_farray;

typedef struct {
	uint32_t end_offset;  // < File byte offset past this and any nested records
	uint32_t prop_count;  // < Number of properties in the value tuple
	uint32_t prop_bytes;  // < Size of the property tuple in bytes
	bfbx_fstring name;    // < Name of the node
} bfbx_fnode;

typedef enum {
	bfbx_prop_s16,
	bfbx_prop_s32,
	bfbx_prop_s64,
	bfbx_prop_f32,
	bfbx_prop_f64,
	bfbx_prop_bool,

	bfbx_prop_string,
	bfbx_prop_binary,

	bfbx_prop_array_s32,
	bfbx_prop_array_s64,
	bfbx_prop_array_f32,
	bfbx_prop_array_f64,
	bfbx_prop_array_bool,
} bfbx_prop_type;

typedef struct {
	bfbx_prop_type type;
	union {
		uint16_t s16;
		uint32_t s32;
		uint64_t s64;
		float f32;
		double f64;
		int bool_;
		bfbx_fstring string;
		bfbx_fstring binary;
		bfbx_farray array;
	} value;
} bfbx_fprop;

// -- Utility

#define bfbx_arraycount(arr) (sizeof(arr) / sizeof(*(arr)))

const char *bfbx_prop_type_str(bfbx_prop_type type)
{
	switch (type) {
	case bfbx_prop_s16: return "s16 (Y)";
	case bfbx_prop_s32: return "s32 (I)";
	case bfbx_prop_s64: return "s64 (L)";
	case bfbx_prop_f32: return "f32 (F)";
	case bfbx_prop_f64: return "f64 (D)";
	case bfbx_prop_bool: return "bool (C)";
	case bfbx_prop_string: return "string (S)";
	case bfbx_prop_binary: return "binary (R)";
	case bfbx_prop_array_s32: return "s32 array (i)";
	case bfbx_prop_array_s64: return "s64 array (l)";
	case bfbx_prop_array_f32: return "f32 array (f)";
	case bfbx_prop_array_f64: return "f64 array (d)";
	case bfbx_prop_array_bool: return "bool array (b)";
	default: return "???";
	}
}

static void bfbx_errorf_v(bqq_fbx_error *error, const char *fmt, va_list args)
{
	if (error) {
		vsnprintf(error->description, sizeof(error->description), fmt, args);
	}
}

static void bfbx_errorf(bqq_fbx_error *error, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	bfbx_errorf_v(error, fmt, args);
	va_end(args);
}

static void *bfbx_read_file(const char *filename, uint32_t *out_size, bqq_fbx_error *error)
{
	size_t size, read_size;
	void *data;
	FILE *file = fopen(filename, "rb");
	if (!file) {
		bfbx_errorf(error, "Failed to open file '%s'", filename);
		return NULL;
	}

	if (fseek(file, 0, SEEK_END)) {
		bfbx_errorf(error, "Failed to seek to file end '%s'", filename);
		fclose(file);
		return NULL;
	}

	size = ftell(file);
	if (size > UINT32_MAX) {
		bfbx_errorf(error, "File is too big (%.2fGB) FBX supports up to 4GB '%s'",
			(double)size / 1e9, filename);
		return NULL;
	}

	data = malloc(size);
	if (!data) {
		bfbx_errorf(error, "Failed to allocate memory (%u bytes) for '%s'", (uint32_t)size, filename);
		fclose(file);
		return NULL;
	}

	if (fseek(file, 0, SEEK_SET)) {
		bfbx_errorf(error, "Failed to seek to file begin '%s'", filename);
		fclose(file);
		return NULL;
	}

	read_size = fread(data, 1, size, file);
	if (read_size != size) {
		bfbx_errorf(error, "Failed to read full file, got %u/%u bytes '%s'",
			(uint32_t)read_size, (uint32_t)size, filename);
		fclose(file);
		free(data);
		return NULL;
	}

	// NOTE: Does not really matter if closing the file fails
	fclose(file);

	*out_size = size;
	return data;
}

static void bfbx_error_at_v(bfbx_ctx *bc, uint32_t offset, const char *fmt, va_list args)
{
	if (bc->error && !bc->failed) {
		bc->error->byte_offset = offset;
		bfbx_errorf_v(bc->error, fmt, args);
	}
	bc->failed = 1;
}

static void bfbx_error_at(bfbx_ctx *bc, uint32_t offset, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	bfbx_error_at_v(bc, offset, fmt, args);
	va_end(args);
}

static void bfbx_error(bfbx_ctx *bc, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	bfbx_error_at_v(bc, bc->pos, fmt, args);
	va_end(args);
}

#if defined(_M_X64) || defined(_M_IX86)
	#define bfbx_read_u8(ptr) *(uint8_t*)(ptr)
	#define bfbx_read_u16(ptr) *(uint16_t*)(ptr)
	#define bfbx_read_u32(ptr) *(uint32_t*)(ptr)
	#define bfbx_read_u64(ptr) *(uint64_t*)(ptr)
	#define bfbx_read_s8(ptr) *(int8_t*)(ptr)
	#define bfbx_read_s16(ptr) *(int16_t*)(ptr)
	#define bfbx_read_s32(ptr) *(int32_t*)(ptr)
	#define bfbx_read_s64(ptr) *(int64_t*)(ptr)
	#define bfbx_read_f32(ptr) *(float*)(ptr)
	#define bfbx_read_f64(ptr) *(double*)(ptr)
#else
	#error "TODO: Unaligned loads"
#endif

static int bfbx_is_array(bfbx_prop_type type) {
	return type >= bfbx_prop_array_s32 && type <= bfbx_prop_array_bool;
}

static void *bfbx_alloc_temp(bfbx_ctx *bc, uint32_t size) {
	void *ptr = bfbx_alloc(&bc->temp_arena, size);
	if (!ptr) {
		bfbx_error(bc, "Failed to allocate %u bytes of temporary memory", size);
	}
	return ptr;
}

static void *bfbx_alloc_result(bfbx_ctx *bc, uint32_t size) {
	void *ptr = bfbx_alloc(&bc->result_arena, size);
	if (!ptr) {
		bfbx_error(bc, "Failed to allocate %u bytes of temporary memory", size);
	}
	return ptr;
}

#define bfbx_push_temp(bc, type) (type*)bfbx_alloc_temp((bc), sizeof(type))
#define bfbx_push_result(bc, type) (type*)bfbx_alloc_result((bc), sizeof(type))

static const char *bfbx_result_string(bfbx_ctx *bc, const bfbx_fstring *string)
{
	if (string->length == 0) return "";

	char *copy = (char*)bfbx_alloc_result(bc, string->length + 1);
	if (copy) {
		memcpy(copy, string->data, string->length);
		copy[string->length] = '\0';
	}
	return copy;
}

static uint32_t bfbx_to_pow2(uint32_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

static int bfbx_streq(const bfbx_fstring *str, const char *ref)
{
	uint32_t len = (uint32_t)strlen(ref);
	return str->length == len && !memcmp(str->data, ref, len);
}

struct bfbx_append_chunk_s {
	bfbx_append_chunk *next; // < Next chunk in a linked list

	uint32_t count;    // < Current number of objects in this chunk
	uint32_t capacity; // < Amount of objects following this struct
};

static void *bfbx_append_size(bfbx_ctx *bc, bfbx_append_list *list, uint32_t size)
{
	bfbx_append_chunk *chunk = list->last;
	list->count++;
	if (chunk != NULL && chunk->count < chunk->capacity) {
		uint32_t pos = chunk->count++;
		char *data = (char*)(chunk + 1);
		return data + size * pos;
	} else {
		uint32_t capacity = chunk ? chunk->capacity * 2 : 32;
		uint32_t alloc_size = sizeof(bfbx_append_chunk) + capacity * size;
		bfbx_append_chunk *new_chunk = (bfbx_append_chunk*)bfbx_alloc_temp(bc, alloc_size);
		if (!new_chunk) return NULL;
		new_chunk->count = 1;
		new_chunk->capacity = capacity;
		new_chunk->next = NULL;
		list->last = new_chunk;
		if (chunk) {
			chunk->next = new_chunk;
		} else {
			list->first = new_chunk;
		}
		return new_chunk + 1;
	}
}

// -- Binary parsing

static const char bfbx_magic_header[] = "Kaydara FBX Binary  ";

static int bfbx_skip_data(bfbx_ctx *bc, uint32_t bytes, const char *name)
{
	if (bc->pos > bc->size) {
		bfbx_error(bc, "Internal error: Read out of bounds for '%s'", name);
		return 0;
	}

	uint32_t space = bc->size - bc->pos;
	if (bytes <= space) {
		bc->pos += bytes;
		return 1;
	} else {
		bfbx_error(bc, "Not enough bytes for %s (%u required, %u left)", name, bytes, space);
		return 0;
	}
}

static int bfbx_parse_header(bfbx_ctx *bc)
{
	const char *base = bc->data + bc->pos;
	if (!bfbx_skip_data(bc, 27, "header")) {
		bfbx_error(bc, "Not enough bytes for the header");
		return 0;
	}

	// [0:20] Magic header. NOTE: `sizeof()` includes the NULL-byte which is
	// actually a part of the header!
	if (memcmp(base + 0, bfbx_magic_header, sizeof(bfbx_magic_header))) {
		bfbx_error(bc, "Invalid magic header");
		return 0;
	}

	// [23:27] Version number
	bc->version = bfbx_read_u32(base + 23);

	return 1;
}

static int bfbx_parse_node(bfbx_ctx *bc, bfbx_fnode *node)
{
	const char *base = bc->data + bc->pos;
	if (!bfbx_skip_data(bc, 13, "node header")) {
		return 0;
	}

	node->end_offset = bfbx_read_u32(base + 0);
	node->prop_count = bfbx_read_u32(base + 4);
	node->prop_bytes = bfbx_read_u32(base + 8);
	node->name.length = bfbx_read_u8(base + 12);
	node->name.data = base + 13;
	if (!bfbx_skip_data(bc, node->name.length, "node name")) {
		return 0;
	}
	if (node->end_offset > 0 && (node->end_offset < bc->pos || node->end_offset > bc->size)) {
		bfbx_error_at(bc, bc->pos - 13, "Node offset out of bounds, %u is not between [%u - %u]",
			node->end_offset, bc->pos, bc->size);
		return 0;
	}

	return 1;
}

static int bfbx_parse_child(bfbx_ctx *bc, const bfbx_fnode *parent, bfbx_fnode *child)
{
	if (!bfbx_parse_node(bc, child)) return 0;
	if (child->end_offset == 0) {
		if (bc->pos != parent->end_offset) {
			bfbx_error(bc, "Sync error: NULL node not at end");
		}
		return 0;
	} else if (bc->pos >= parent->end_offset) {
		bfbx_error(bc, "Sync error: Child nodes past end offset");
		return 0;
	} else {
		return 1;
	}
}

static int bfbx_parse_prop(bfbx_ctx *bc, bfbx_fprop *prop)
{
	const char *base = bc->data + bc->pos;
	if (bc->pos >= bc->size) {
		bfbx_error(bc, "Property at the end of the file");
		return 0;
	}

	uint32_t size = 0;
	uint32_t elem_size = 0;
	bfbx_prop_type type = bfbx_prop_s16;
	char type_ch = (char)bfbx_read_u8(base + 0);
	switch (type_ch) {
	case 'Y': type = bfbx_prop_s16; size = 2; break;
	case 'I': type = bfbx_prop_s32; size = 4; break;
	case 'L': type = bfbx_prop_s64; size = 8; break;
	case 'F': type = bfbx_prop_f32; size = 4; break;
	case 'D': type = bfbx_prop_f64; size = 8; break;
	case 'C': type = bfbx_prop_bool; size = 1; break;
	case 'S': type = bfbx_prop_string; size = 4; break;
	case 'R': type = bfbx_prop_binary; size = 4; break;
	case 'i': type = bfbx_prop_array_s32; size = 12; elem_size = 4; break;
	case 'l': type = bfbx_prop_array_s64; size = 12; elem_size = 8; break;
	case 'f': type = bfbx_prop_array_f32; size = 12; elem_size = 4; break;
	case 'd': type = bfbx_prop_array_f64; size = 12; elem_size = 8; break;
	case 'b': type = bfbx_prop_array_bool; size = 12; elem_size = 1; break;
	default:
		bfbx_error(bc, "Unsupported property type '%c'", type_ch);
		return 0;
	}
	prop->type = type;

	if (!bfbx_skip_data(bc, size + 1, "property value")) {
		return 0;
	}

	const char *ptr = base + 1;
	if (bfbx_is_array(type)) {
		bfbx_farray *array = &prop->value.array;
		array->length = bfbx_read_u32(ptr + 0);
		uint32_t encoding = bfbx_read_u32(ptr + 4);
		if (encoding > 1) {
			bfbx_error(bc, "Unsupported array encoding '%u'", encoding);
			return 0;
		}
		array->encoding = (bfbx_array_encoding)encoding;
		array->compressed_bytes = bfbx_read_u32(ptr + 8);
		array->compressed_data = ptr + 12;

		uint32_t skip_size;
		if (encoding == 0) {
			// Assume `compressed_bytes` is unreliable if not compressed
			skip_size = elem_size * array->length;
		} else if (encoding == 1) {
			skip_size = array->compressed_bytes;
		} else {
			bfbx_error(bc, "Internal error: Unhandled encoding '%u'", encoding);
			return 0;
		}

		if (!bfbx_skip_data(bc, skip_size, "array contents")) {
			return 0;
		}
	} else {
		switch (type) {
		case bfbx_prop_s16: prop->value.s16 = bfbx_read_s16(ptr); break;
		case bfbx_prop_s32: prop->value.s32 = bfbx_read_s32(ptr); break;
		case bfbx_prop_s64: prop->value.s64 = bfbx_read_s64(ptr); break;
		case bfbx_prop_f32: prop->value.f32 = bfbx_read_f32(ptr); break;
		case bfbx_prop_f64: prop->value.f64 = bfbx_read_f64(ptr); break;
		case bfbx_prop_bool: prop->value.bool_ = (int)bfbx_read_u8(ptr); break;
		case bfbx_prop_string:
			prop->value.string.length = bfbx_read_u32(ptr);
			prop->value.string.data = ptr + 4;
			if (!bfbx_skip_data(bc, prop->value.string.length, "string value")) {
				return 0;
			}
			break;
		case bfbx_prop_binary:
			prop->value.binary.length = bfbx_read_u32(ptr);
			prop->value.binary.data = ptr + 4;
			if (!bfbx_skip_data(bc, prop->value.binary.length, "binary value")) {
				return 0;
			}
			break;

		default:
			bfbx_error(bc, "Internal error: Unhandled type '%u'", type);
			return 0;
		}
	}

	return 1;
}

static int bfbx_skip_props(bfbx_ctx *bc, uint32_t amount)
{
	// TODO: Could special case this
	bfbx_fprop prop;
	for (uint32_t i = 0; i < amount; i++) {
		if (!bfbx_parse_prop(bc, &prop)) return 0;
	}
	return 1;
}

// -- Property converters

static int bfbx_prop_to_string(bfbx_ctx *bc, const bfbx_fprop *prop, bfbx_fstring *dst)
{
	switch (prop->type) {
	case bfbx_prop_string: *dst = prop->value.string; break;
	default:
		bfbx_error(bc, "Cannot convert %s to string", bfbx_prop_type_str(prop->type));
		return 0;
	}
	return 1;
}

static int bfbx_parse_to_string(bfbx_ctx *bc, bfbx_fstring *dst)
{
	bfbx_fprop p;
	return bfbx_parse_prop(bc, &p) && bfbx_prop_to_string(bc, &p, dst);
}

static int bfbx_prop_to_u64(bfbx_ctx *bc, const bfbx_fprop *prop, uint64_t *dst)
{
	switch (prop->type) {
	case bfbx_prop_s16: *dst = (uint64_t)prop->value.s16; break;
	case bfbx_prop_s32: *dst = (uint64_t)prop->value.s32; break;
	case bfbx_prop_s64: *dst = (uint64_t)prop->value.s64; break;
	default:
		bfbx_error(bc, "Cannot convert %s to uint64", bfbx_prop_type_str(prop->type));
		return 0;
	}
	return 1;
}

static int bfbx_parse_to_u64(bfbx_ctx *bc, uint64_t *dst)
{
	bfbx_fprop p;
	return bfbx_parse_prop(bc, &p) && bfbx_prop_to_u64(bc, &p, dst);
}

static int bfbx_prop_to_f64(bfbx_ctx *bc, const bfbx_fprop *prop, double *dst)
{
	switch (prop->type) {
	case bfbx_prop_s16: *dst = (double)prop->value.s16; break;
	case bfbx_prop_s32: *dst = (double)prop->value.s32; break;
	case bfbx_prop_s64: *dst = (double)prop->value.s64; break;
	case bfbx_prop_f32: *dst = (double)prop->value.f32; break;
	case bfbx_prop_f64: *dst = prop->value.f64; break;
	default:
		bfbx_error(bc, "Cannot convert %s to double", bfbx_prop_type_str(prop->type));
		return 0;
	}
	return 1;
}

static int bfbx_parse_to_f64(bfbx_ctx *bc, double *dst)
{
	bfbx_fprop p;
	return bfbx_parse_prop(bc, &p) && bfbx_prop_to_f64(bc, &p, dst);
}

// -- Document property parsers

static int bfbx_dp_f64(bfbx_ctx *bc, void *dst, const bfbx_dprop_info *info)
{
	double *d = (double*)dst;
	bfbx_fprop p;
	if (!bfbx_parse_prop(bc, &p)) return 0;
	if (!bfbx_prop_to_f64(bc, &p, &d[0])) return 0;
	return 1;
}

static int bfbx_dp_vec3(bfbx_ctx *bc, void *dst, const bfbx_dprop_info *info)
{
	double *d = (double*)dst;
	bfbx_fprop p;
	if (!bfbx_parse_prop(bc, &p)) return 0;
	if (!bfbx_prop_to_f64(bc, &p, &d[0])) return 0;
	if (!bfbx_parse_prop(bc, &p)) return 0;
	if (!bfbx_prop_to_f64(bc, &p, &d[1])) return 0;
	if (!bfbx_parse_prop(bc, &p)) return 0;
	if (!bfbx_prop_to_f64(bc, &p, &d[2])) return 0;
	return 1;
}

// -- Document property map

static uint32_t bfbx_dprop_hash(const char *name, uint32_t length)
{
	// TODO: Do something real here!
	return name[0] + length;
}

int bfbx_dprop_init_map(bfbx_ctx *bc, bfbx_dprop_map *map, const bfbx_dprop_desc *props, uint32_t count)
{
	map->props = props;
	map->num_props = count;

	map->map_size = bfbx_to_pow2(count * 4);
	uint32_t map_bytes = map->map_size * sizeof(bfbx_dprop_map_entry);
	if (!map_bytes) return 1;

	map->map = (bfbx_dprop_map_entry*)bfbx_alloc_temp(bc, map_bytes);
	if (!map->map) return 0;
	memset(map->map, 0, map_bytes);
	uint32_t mask = map->map_size - 1;
	for (uint32_t i = 0; i < count; i++) {
		size_t name_length = strlen(props[i].name);
		uint32_t index = bfbx_dprop_hash(props[i].name, (uint32_t)name_length) & mask;
		while (map->map[index].name_length != 0) {
			index = (index + 1) & mask;
		}
		map->map[index].name_length = (uint16_t)name_length;
		map->map[index].prop_index = (uint16_t)i;
	}
	return 1;
}

const bfbx_dprop_desc *bfbx_dprop_find(const bfbx_dprop_map *map, const bfbx_fstring *name)
{
	if (map->map_size == 0) return NULL;

	uint32_t mask = map->map_size - 1;
	uint32_t index = bfbx_dprop_hash(name->data, name->length) & mask;
	while (map->map[index].name_length != 0) {
		if (map->map[index].name_length == name->length) {
			const bfbx_dprop_desc *prop = &map->props[map->map[index].prop_index];
			if (!memcmp(prop->name, name->data, name->length)) {
				return prop;
			}
		}
		index = (index + 1) & mask;
	}
	return NULL;
}

// -- Object types

int bfbx_init_object_type(bfbx_ctx *bc, bqq_fbx_type type, const void *default_value, size_t size,
	const bfbx_dprop_desc *props, size_t count)
{
	bfbx_object_type *object_type = &bc->object_types[type];
	object_type->default_value = bfbx_alloc_temp(bc, size);
	object_type->size = size;
	if (!object_type->default_value) return 0;
	memcpy(object_type->default_value, default_value, size);
	if (!bfbx_dprop_init_map(bc, &object_type->prop_map, props, count)) return 0;
	return 1;
}

static const bfbx_dprop_desc bfbx_node_props[] = {
	{ "Lcl Translation", offsetof(bqq_fbx_node, local_translation), bfbx_dp_vec3 },
	{ "Lcl Rotation", offsetof(bqq_fbx_node, local_rotation), bfbx_dp_vec3 },
	{ "Lcl Scaling", offsetof(bqq_fbx_node, local_scaling), bfbx_dp_vec3 },
	{ "RotationOffset", offsetof(bqq_fbx_node, rotation_offset), bfbx_dp_vec3 },
	{ "RotationPivot", offsetof(bqq_fbx_node, rotation_pivot), bfbx_dp_vec3 },
	{ "ScalingOffset", offsetof(bqq_fbx_node, scaling_offset), bfbx_dp_vec3 },
	{ "ScalingPivot", offsetof(bqq_fbx_node, scaling_pivot), bfbx_dp_vec3 },
	{ "GeometricTranslation", offsetof(bqq_fbx_node, geometric_translation), bfbx_dp_vec3 },
	{ "GeometricRotation", offsetof(bqq_fbx_node, geometric_rotation), bfbx_dp_vec3 },
	{ "GeometricScaling", offsetof(bqq_fbx_node, geometric_scaling), bfbx_dp_vec3 },
};

static const bfbx_dprop_desc bfbx_light_props[] = {
	{ "Color", offsetof(bqq_fbx_light, color), bfbx_dp_vec3 },
	{ "Intensity", offsetof(bqq_fbx_light, intensity), bfbx_dp_f64 },
};

static const bfbx_dprop_desc bfbx_camera_props[] = {
	{ "AspectWidth", offsetof(bqq_fbx_camera, aspect_width), bfbx_dp_f64 },
	{ "AspectHeight", offsetof(bqq_fbx_camera, aspect_height), bfbx_dp_f64 },
};

int bfbx_init_object_types(bfbx_ctx *bc)
{
	int ok = 1;

	{
		bqq_fbx_unknown v;
		memset(&v, 0, sizeof(v));
		v.base.type = bqq_fbx_type_unknown;
		ok = ok && bfbx_init_object_type(bc, bqq_fbx_type_unknown,
			&v, sizeof(v), NULL, 0);
	}

	{
		bqq_fbx_node v;
		memset(&v, 0, sizeof(v));
		v.base.type = bqq_fbx_type_node;
		ok = ok && bfbx_init_object_type(bc, bqq_fbx_type_node,
			&v, sizeof(v), bfbx_node_props, bfbx_arraycount(bfbx_node_props));
	}

	{
		bqq_fbx_mesh v;
		memset(&v, 0, sizeof(v));
		v.base.type = bqq_fbx_type_mesh;
		ok = ok && bfbx_init_object_type(bc, bqq_fbx_type_mesh,
			&v, sizeof(v), NULL, 0);
	}

	{
		bqq_fbx_material v;
		memset(&v, 0, sizeof(v));
		v.base.type = bqq_fbx_type_material;
		ok = ok && bfbx_init_object_type(bc, bqq_fbx_type_material,
			&v, sizeof(v), NULL, 0);
	}

	{
		bqq_fbx_light v;
		memset(&v, 0, sizeof(v));
		v.base.type = bqq_fbx_type_light;
		ok = ok && bfbx_init_object_type(bc, bqq_fbx_type_light,
			&v, sizeof(v), bfbx_light_props, bfbx_arraycount(bfbx_light_props));
	}

	{
		bqq_fbx_camera v;
		memset(&v, 0, sizeof(v));
		v.base.type = bqq_fbx_type_camera;
		ok = ok && bfbx_init_object_type(bc, bqq_fbx_type_camera,
			&v, sizeof(v), bfbx_camera_props, bfbx_arraycount(bfbx_camera_props));
	}

	return ok;
}

// -- Document structure

static int bfbx_doc_properties70(bfbx_ctx *bc, bfbx_fnode *parent, void *dst, const bfbx_dprop_map *map)
{
	bfbx_fnode child;
	while (bfbx_parse_child(bc, parent, &child)) {
		if (bc->failed) return 0;

		if (child.prop_count < 4) {
			bfbx_error(bc, "Property has fewer than 4 parameters (%u)", child.prop_count);
			return 0;
		}

		bfbx_fstring name;
		if (!bfbx_parse_to_string(bc, &name)) return 0;

		const bfbx_dprop_desc *prop = bfbx_dprop_find(map, &name);
		if (!prop) {
			bc->pos = child.end_offset;
			continue;
		}

		bfbx_dprop_info info;
		if (!bfbx_parse_to_string(bc, &info.type)) return 0;
		if (!bfbx_skip_props(bc, 2)) return 0; // Skip flags

		char *field = (char*)dst + prop->field_offset;
		if (!prop->parse_fn(bc, field, &info)) {
			bfbx_error(bc, "Failed to parse property '%.*s'", &name.length, &name.data);
			return 0;
		}

		if (bc->pos != child.end_offset) {
			bfbx_error(bc, "Sync error: Property '%.*s' did not parse to end", &name.length, &name.data);
			return 0;
		}
	}

	return 1;
}

static int bfbx_doc_defaults70(bfbx_ctx *bc, uint32_t offset, bfbx_fnode *parent, bqq_fbx_type type)
{
	bc->pos = offset;
	bfbx_object_type *object_type = &bc->object_types[type];
	return bfbx_doc_properties70(bc, parent, object_type->default_value, &object_type->prop_map);
}

static int bfbx_doc_template(bfbx_ctx *bc, bfbx_fnode *parent, bfbx_fstring *type)
{
	bfbx_fnode child;
	while (bfbx_parse_child(bc, parent, &child)) {
		if (bc->failed) return 0;

		if (bfbx_streq(&child.name, "Properties70")) {
			uint32_t offset = bc->pos;

			if (bfbx_streq(type, "Model")) {
				if (!bfbx_doc_defaults70(bc, offset, &child, bqq_fbx_type_node)) return 0;
			} else if (bfbx_streq(type, "Geometry")) {
				if (!bfbx_doc_defaults70(bc, offset, &child, bqq_fbx_type_mesh)) return 0;
			} else if (bfbx_streq(type, "Material")) {
				if (!bfbx_doc_defaults70(bc, offset, &child, bqq_fbx_type_material)) return 0;
			} else if (bfbx_streq(type, "NodeAttribute")) {
				if (!bfbx_doc_defaults70(bc, offset, &child, bqq_fbx_type_camera)) return 0;
				if (!bfbx_doc_defaults70(bc, offset, &child, bqq_fbx_type_light)) return 0;
			} else {
				// No structs to copy template into
				bc->pos = child.end_offset;
			}

		} else {
			// Unknown child node, skip it
			bc->pos = child.end_offset;
		}
	}

	return 1;
}

static int bfbx_doc_definition(bfbx_ctx *bc, bfbx_fnode *def_node)
{
	if (bfbx_streq(&def_node->name, "ObjectType")) {
		if (def_node->prop_count < 1) {
			bfbx_error(bc, "Not enough properties for ObjectType");
			return 0;
		}

		bfbx_fstring name;
		if (!bfbx_parse_to_string(bc, &name)) return 0;

		bfbx_fnode child;
		while (bfbx_parse_child(bc, def_node, &child)) {
			if (bc->failed) return 0;

			if (bfbx_streq(&child.name, "PropertyTemplate")) {
				bfbx_skip_props(bc, child.prop_count);
				bfbx_doc_template(bc, &child, &name);
			} else {
				// Unknown child node, skip it
				bc->pos = child.end_offset;
			}
		}

	} else {
		// Ignore unknown definitions
		bc->pos = def_node->end_offset;
		return 1;
	}

	return 1;
}

static int bfbx_doc_section_definitions(bfbx_ctx *bc, bfbx_fnode *section)
{
	bfbx_fnode def_node;
	while (bfbx_parse_child(bc, section, &def_node)) {
		if (bc->failed) return 0;
		if (!bfbx_doc_definition(bc, &def_node)) return 0;
	}

	return 1;
}

static int bfbx_doc_object(bfbx_ctx *bc, bfbx_fnode *obj_node)
{
	if (obj_node->prop_count < 3) {
		bfbx_error(bc, "Object has too few properties (%u)", obj_node->prop_count);
		return 0;
	}

	uint64_t id;
	bfbx_fstring name, subtype;
	if (!bfbx_parse_to_u64(bc, &id)) return 0;
	if (!bfbx_parse_to_string(bc, &name)) return 0;
	if (!bfbx_parse_to_string(bc, &subtype)) return 0;
	if (!bfbx_skip_props(bc, obj_node->prop_count - 3)) return 0;

	bqq_fbx_type type = bqq_fbx_type_unknown;
	if (bfbx_streq(&obj_node->name, "Model")) {
		type = bqq_fbx_type_node;
	} else if (bfbx_streq(&obj_node->name, "Geometry")) {
		type = bqq_fbx_type_mesh;
	} else if (bfbx_streq(&obj_node->name, "Material")) {
		type = bqq_fbx_type_material;
	} else if (bfbx_streq(&obj_node->name, "NodeAttribute")) {
		if (bfbx_streq(&subtype, "Camera")) {
			type = bqq_fbx_type_camera;
		} else if (bfbx_streq(&subtype, "Light")) {
			type = bqq_fbx_type_light;
		}
	}

	bfbx_object_type *obj_type = &bc->object_types[type];

	bqq_fbx_base *base = (bqq_fbx_base*)bfbx_alloc_result(bc, obj_type->size);
	if (!base) return 0;
	memcpy(base, obj_type->default_value, obj_type->size);

	base->id = id;

	// Truncate name to \x00\x01 separating name and class
	for (uint32_t i = 0; i + 1 < name.length; i++) {
		if (name.data[i] == '\x00' && name.data[i + 1] == '\x01') {
			name.length = i;
			break;
		}
	}
	base->name = bfbx_result_string(bc, &name);

	bfbx_fnode child;
	while (bfbx_parse_child(bc, obj_node, &child)) {
		if (bc->failed) return 0;

		if (bfbx_streq(&child.name, "Properties70")) {
			bfbx_dprop_map *prop_map = &bc->object_types[type].prop_map;
			if (!bfbx_doc_properties70(bc, &child, base, prop_map)) return 0;
		} else {
			// Unknown child node, skip it
			bc->pos = child.end_offset;
		}
	}

	bqq_fbx_base **ptr = bfbx_append(bc, &bc->all_objects, bqq_fbx_base*);
	if (!ptr) return 0;
	*ptr = base;

	return 1;
}

static int bfbx_doc_section_objects(bfbx_ctx *bc, bfbx_fnode *section)
{
	bfbx_fnode obj_node;
	while (bfbx_parse_child(bc, section, &obj_node)) {
		if (bc->failed) return 0;
		if (!bfbx_doc_object(bc, &obj_node)) return 0;
	}

	return 1;
}

static int bfbx_doc_root(bfbx_ctx *bc)
{
	uint32_t begin_pos = bc->pos;
	bfbx_fnode section;

	// Assume sections are in optimistic order, otherwise have to do loops

	// 1. Definitions
	for (int attempt = 0; ; attempt++) {
		int found = 0;
		while (bfbx_parse_node(bc, &section)) {
			if (section.end_offset == 0) break;
			if (bc->failed) return 0;
			if (bfbx_streq(&section.name, "Definitions")) {
				if (!bfbx_doc_section_definitions(bc, &section)) return 0;
				found = 1;
				break;
			} else {
				bc->pos = section.end_offset;
			}
		}
		if (found) break;

		bc->pos = begin_pos;
		if (attempt > 0) {
			bfbx_error(bc, "No 'Definitions' section");
			return 0;
		}
	}

	// 2. Objects
	for (int attempt = 0; ; attempt++) {
		int found = 0;
		while (bfbx_parse_node(bc, &section)) {
			if (section.end_offset == 0) break;
			if (bc->failed) return 0;
			if (bfbx_streq(&section.name, "Objects")) {
				if (!bfbx_doc_section_objects(bc, &section)) return 0;
				found = 1;
				break;
			} else {
				bc->pos = section.end_offset;
			}
		}
		if (found) break;

		bc->pos = begin_pos;
		if (attempt > 0) {
			bfbx_error(bc, "No 'Connections' section");
			return 0;
		}
	}

	// 3. Connections
	for (int attempt = 0; ; attempt++) {
		int found = 0;
		while (bfbx_parse_node(bc, &section)) {
			if (section.end_offset == 0) break;
			if (bc->failed) return 0;
			if (bfbx_streq(&section.name, "Connections")) {
				found = 1;
				break;
			} else {
				bc->pos = section.end_offset;
			}
		}
		if (found) break;

		bc->pos = begin_pos;
		if (attempt > 0) {
			bfbx_error(bc, "No 'Connections' section");
			return 0;
		}
	}

	return 1;
}

typedef struct {
	bqq_fbx_scene scene;     // < Scene pointer to return
	char *result_allocation; // < Result allocation to free
} bfbx_scene;

// -- API

bqq_fbx_scene *bqq_fbx_parse_file(const char *filename, bqq_fbx_error *error)
{
	uint32_t size;
	void *data = bfbx_read_file(filename, &size, error);
	if (!data) return NULL;
	bqq_fbx_scene *scene = bqq_fbx_parse_memory(data, size, error);
	free(data);
	return scene;
}

bqq_fbx_scene *bqq_fbx_parse_memory(const void *data, size_t size, bqq_fbx_error *error)
{
	if (error) {
		memset(error, 0, sizeof(bqq_fbx_error));
	}

	if (size > UINT32_MAX) {
		bfbx_errorf(error, "Memory data is too big (%.2fGB) FBX supports up to 4GB",
			(double)size / 1e9);
		return NULL;
	}

	bfbx_ctx ctx, *bc = &ctx;
	memset(bc, 0, sizeof(bfbx_ctx));
	bc->error = error;
	bc->data = (const char*)data;
	bc->size = size;

	bfbx_scene *internal_scene = (bfbx_scene*)bfbx_alloc_result(bc, sizeof(bfbx_scene));
	bqq_fbx_scene *scene = NULL;
	if (!internal_scene) goto error;
	scene = &internal_scene->scene;
	memset(internal_scene, 0, sizeof(bfbx_scene));

	if (!bfbx_init_object_types(bc)) goto error;
	if (!bfbx_parse_header(bc)) goto error;
	if (!bfbx_doc_root(bc)) goto error;

	// Copy all objects
	{
		uint32_t num = bc->all_objects.count;
		bqq_fbx_base **dst = (bqq_fbx_base**)bfbx_alloc_result(bc, num * sizeof(bqq_fbx_base**));
		scene->num_objects = num;
		scene->objects = dst;
		for (bfbx_append_chunk *chunk = bc->all_objects.first; chunk; chunk = chunk->next) {
			bqq_fbx_base **src = (bqq_fbx_base**)(chunk + 1);
			for (uint32_t i = 0; i < chunk->count; i++) {
				*dst++ = src[i];
			}
		}
	}

	bfbx_free_chunk(bc->temp_arena.chunk);
	internal_scene->result_allocation = bc->result_arena.chunk;
	return scene;
error:
	bfbx_free_chunk(bc->temp_arena.chunk);
	bfbx_free_chunk(bc->result_arena.chunk);
	return NULL;
}

void bqq_fbx_free(bqq_fbx_scene *scene)
{
	if (!scene) return;

	bfbx_scene *internal_scene = (bfbx_scene*)scene;
	bfbx_free_chunk(internal_scene->result_allocation);
}

#endif
