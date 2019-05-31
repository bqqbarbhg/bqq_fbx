
#ifndef BQQ_FBX_IMPLEMENTED
#define BQQ_FBX_IMPLEMENTED

#include "bqq_fbx.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

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

typedef enum {
	bfbx_array_encoding_none = 0,
	bfbx_array_encoding_deflate = 1,
} bfbx_array_encoding;

// -- File context
// This is the main context structure passed to every function

typedef struct {
	const char *data; // < Memory block containing the whole file
	uint32_t pos;     // < Current byte position into the buffer
	uint32_t size;    // < Size of the file in bytes
	uint32_t version; // < File version number

	int failed;           // < Loading the file failed in some way
	bqq_fbx_error *error; // < Pointer to an user supplied error struct

} bfbx_ctx;

// -- File parse result data types.
// The data structures contain pointers to the file buffer memory.

typedef struct {
	uint32_t length;  // < Length in bytes
	const char *data; // < Non-null-terminated pointer to the file buffer
} bfbx_fstring;

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
		return NULL;
	}

	// NOTE: Does not really matter if closing the file fails
	fclose(file);

	*out_size = size;
	return data;
}

static void bfbx_error_at_v(bfbx_ctx *bc, uint32_t offset, const char *fmt, va_list args)
{
	bc->failed = 1;
	if (bc->error) {
		bc->error->byte_offset = offset;
		bfbx_errorf_v(bc->error, fmt, args);
	}
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

static int bfbx_parse_prop(bfbx_ctx *bc, bfbx_fprop *prop)
{
	const char *base = bc->data + bc->pos;
	if (bc->pos >= bc->size) {
		bfbx_error(bc, "Property at the end of the file");
		return 0;
	}

	uint32_t size = 0;
	uint32_t elem_size = 0;
	bfbx_prop_type type = 0;
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

#endif
