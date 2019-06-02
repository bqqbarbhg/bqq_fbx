
#ifndef BQQ_FBX_IMPLEMENTED
#define BQQ_FBX_IMPLEMENTED

#include "bqq_fbx.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

// Minimum allocation size in bytes
#ifndef BFBX_MIN_ALLOCATION_SIZE
#define BFBX_MIN_ALLOCATION_SIZE 0x10000 // 10KiB
#endif

// Huge allocation size in bytes
#ifndef BFBX_HUGE_ALLOCATION_SIZE
#define BFBX_HUGE_ALLOCATION_SIZE 0x1000000 // 1MiB
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

	if (size >= BFBX_HUGE_ALLOCATION_SIZE) {
		char *chunk = (char*)malloc(size + 8);
		if (!chunk) return NULL;
		if (arena->chunk) {
			// Previous allocations, link between current and previous chunks
			*(void**)chunk = *(void**)arena->chunk;
			*(void**)arena->chunk = chunk;
		} else {
			// First allocation, set as empty root chunk
			*(void**)chunk = NULL;
			arena->chunk = chunk;
		}
		return chunk + 8;
	}

	if (arena->pos + size <= arena->size) {
		uint32_t pos = arena->pos;
		arena->pos = pos + size;
		return arena->chunk + pos;
	} else {
		uint32_t next_size = arena->size * 2;
		if (next_size < BFBX_MIN_ALLOCATION_SIZE) next_size = BFBX_MIN_ALLOCATION_SIZE;
		if (next_size < size + 8) next_size = size + 8;
		char *chunk = (char*)malloc(next_size);
		if (!chunk) return NULL;
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

// Map from object ID to object pointers
typedef struct {
	uint32_t size;      // < Size of `map` in elements
	bqq_fbx_base **map; // < Mapping from `bfbx_object_hash()` to pointer
} bfbx_object_map;

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
	bfbx_arena temp_arena;     // < Temporary allocations, thrown away when done
	bfbx_arena result_arena;   // < Output allocations, freed when user is done
	void *decompress_buffer;   // < Temporary buffer for decompression
	uint32_t decompress_bytes; // < Size of `decompress_buffer` in bytes

	// Scene contents
	bqq_fbx_scene *scene;
	bfbx_append_list all_objects;
	bfbx_object_map object_map;

	// Type-specific properties
	bfbx_object_type object_types[bqq_fbx_num_types];
};

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

// -- Deflate implementation
// Pretty much based on Sean Barrett's `stb_image` deflate

// Lookup data: [0:13] extra mask [13:17] extra bits [17:32] base value
// Generated by `misc/deflate_lut.py`
static const uint32_t bfbxz_length_lut[] = {
	0x00060000, 0x00080000, 0x000a0000, 0x000c0000, 0x000e0000, 0x00100000, 0x00120000, 0x00140000, 
	0x00162001, 0x001a2001, 0x001e2001, 0x00222001, 0x00264003, 0x002e4003, 0x00364003, 0x003e4003, 
	0x00466007, 0x00566007, 0x00666007, 0x00766007, 0x0086800f, 0x00a6800f, 0x00c6800f, 0x00e6800f, 
	0x0106a01f, 0x0146a01f, 0x0186a01f, 0x01c6a01f, 0x02040000, 0x00000000, 0x00000000, 
};
static const uint32_t bfbxz_dist_lut[] = {
	0x00020000, 0x00040000, 0x00060000, 0x00080000, 0x000a2001, 0x000e2001, 0x00124003, 0x001a4003, 
	0x00226007, 0x00326007, 0x0042800f, 0x0062800f, 0x0082a01f, 0x00c2a01f, 0x0102c03f, 0x0182c03f, 
	0x0202e07f, 0x0302e07f, 0x040300ff, 0x060300ff, 0x080321ff, 0x0c0321ff, 0x100343ff, 0x180343ff, 
	0x200367ff, 0x300367ff, 0x40038fff, 0x60038fff, 0x8003bfff, 0xc003bfff, 
};

static const uint8_t bfbxz_code_length_swizzle[] = {
	16,17,18,0,8,7,9,6,10,5,11,4,123,13,2,14,1,15 };

#define BFBXZ_HUFF_MAX_BITS 16
#define BFBXZ_HUFF_MAX_VALUE 288
#define BFBXZ_HUFF_FAST_BITS 9
#define BFBXZ_HUFF_FAST_SIZE (1 << BFBXZ_HUFF_FAST_BITS)
#define BFBXZ_HUFF_FAST_MASK (BFBXZ_HUFF_FAST_SIZE - 1)

typedef struct {
	uint32_t num_symbols;

	uint16_t sorted_to_sym[BFBXZ_HUFF_MAX_VALUE]; // < Sorted symbol index to symbol
	uint16_t past_max_code[BFBXZ_HUFF_MAX_BITS];  // < One past maximum code value per bit length
	int16_t code_to_sorted[BFBXZ_HUFF_MAX_BITS];  // < Code to sorted symbol index per bit length
	uint16_t fast_sym[BFBXZ_HUFF_FAST_SIZE];      // < Fast symbol lookup [0:12] symbol [12:16] bits
} bfbxz_huff_tree;

typedef struct {
	const char *data;
	uint32_t pos;
	uint32_t size;

	uint32_t num_bits;
	uint32_t num_next_bits;
	uint64_t bits;
	uint64_t next_bits;

} bfbxz_stream;

typedef struct {
	bfbxz_stream stream;
	bfbxz_huff_tree huff_lit_length;
	bfbxz_huff_tree huff_dist;

	char *output;
	uint32_t output_pos;
	uint32_t output_size;

} bfbxz_context;

static uint64_t bfbxz_read_u64(bfbxz_stream *stream)
{
	// TODO: This works only with unaligned reads, needs some #ifdef
	if (stream->pos + 8 <= stream->size) {
		uint64_t val = *(uint64_t*)(stream->data + stream->pos);
		stream->pos += 8;
		return val;
	} else {
		uint64_t val = 0;
		uint32_t shift = 0;
		for (; stream->pos < stream->size; stream->pos++) {
			val |= (uint64_t)(uint8_t)stream->data[stream->pos];
			shift += 8;
		}
		return val;
	}
}

static void bfbxz_refill(bfbxz_stream *stream)
{
	uint32_t num_bits = stream->num_bits;
	uint32_t need_bits = 64 - num_bits;
	if (!need_bits) return;
	stream->bits |= stream->next_bits << num_bits;
	if (stream->num_next_bits >= need_bits) {
		stream->next_bits >>= need_bits;
		stream->num_next_bits -= need_bits;
	} else {
		uint32_t num_total_bits = num_bits + stream->num_next_bits;
		uint64_t read_bits = bfbxz_read_u64(stream);
		if (num_total_bits != 0) {
			stream->bits |= read_bits << num_total_bits;
			stream->next_bits = read_bits >> (64 - num_total_bits);
			stream->num_next_bits = num_total_bits;
		} else {
			stream->bits = read_bits;
			stream->next_bits = bfbxz_read_u64(stream);
			stream->num_next_bits = 64;
		}
	}
	stream->num_bits = 64;
}

static int bfbxz_huff_build(bfbxz_huff_tree *tree, uint8_t *sym_bits, uint32_t sym_count)
{
	if (sym_count > BFBXZ_HUFF_MAX_VALUE) return 0;
	tree->num_symbols = sym_count;

	uint32_t bits_counts[BFBXZ_HUFF_MAX_BITS];
	memset(bits_counts, 0, sizeof(bits_counts));
	for (uint32_t i = 0; i < sym_count; i++) {
		uint32_t bits = sym_bits[i];
		if (bits == 0 || bits > BFBXZ_HUFF_MAX_BITS) return 0; 
		bits_counts[bits]++;
	}

	uint32_t total_syms[BFBXZ_HUFF_MAX_BITS];
	uint32_t first_code[BFBXZ_HUFF_MAX_BITS];

	tree->code_to_sorted[0] = INT16_MAX;
	tree->past_max_code[0] = 0;
	total_syms[0] = 0;

	uint32_t code = 0;
	uint32_t prev_count = 0;
	for (uint32_t bits = 1; bits < BFBXZ_HUFF_MAX_BITS; bits++) {
		uint32_t count = bits_counts[bits];
		code = (code + prev_count) << 1;
		if (code > UINT16_MAX) return 0;
		first_code[bits] = code;
		tree->past_max_code[bits] = (uint16_t)(code + count);
		if (tree->past_max_code[bits] > 1 << bits) return 0;

		uint32_t prev_syms = total_syms[bits - 1];
		total_syms[bits] = prev_syms + count;

		if (count > 0) {
			tree->code_to_sorted[bits] = (int16_t)((int)prev_syms - (int)code);
		} else {
			tree->code_to_sorted[bits] = INT16_MAX;
		}
		prev_count = count;
	}

	memset(tree->fast_sym, 0, sizeof(tree->fast_sym));

	uint32_t bits_index[BFBXZ_HUFF_MAX_BITS];
	memset(bits_index, 0, sizeof(bits_index));
	memset(tree->sorted_to_sym, 0xff, sizeof(tree->sorted_to_sym));
	for (uint32_t i = 0; i < sym_count; i++) {
		uint32_t bits = sym_bits[i];
		uint32_t index = bits_index[bits]++;
		uint32_t sorted = total_syms[bits - 1] + index;
		tree->sorted_to_sym[sorted] = i;

		uint32_t code = first_code[bits] + index;
		uint32_t rev_code = 0;
		for (uint32_t bit = 0; bit < bits; bit++) {
			if (code & (1 << bit)) rev_code |= 1 << (bits - bit - 1);
		}

		uint16_t fast_sym = i | bits << 12;
		uint32_t hi_max = 1 << (BFBXZ_HUFF_FAST_BITS - bits);
		for (uint32_t hi = 0; hi < hi_max; hi++) {
			tree->fast_sym[rev_code | hi << bits] = fast_sym;
		}
	}

	return 1;
}

static inline uint32_t bfbxz_huff_decode_bits(const bfbxz_huff_tree *tree, uint64_t *bit_buffer, uint32_t *bits_read)
{
	uint32_t fast_sym_bits = tree->fast_sym[*bit_buffer & BFBXZ_HUFF_FAST_MASK];
	if (fast_sym_bits != 0) {
		uint32_t bits = fast_sym_bits >> 12;
		*bits_read += bits;
		*bit_buffer >>= bits;
		return fast_sym_bits & 0x3ff;
	}

	uint32_t code = 0;
	for (uint32_t bits = 1; bits < BFBXZ_HUFF_MAX_BITS; bits++) {
		code = code << 1 | (*bit_buffer & 1);
		*bit_buffer >>= 1;
		*bits_read += 1;
		if (code < tree->past_max_code[bits]) {
			uint32_t sorted = code + tree->code_to_sorted[bits];
			if (sorted >= tree->num_symbols) return ~0u;
			return tree->sorted_to_sym[sorted];
		}
	}

	return ~0u;
}

static uint32_t bfbxz_huff_decode(const bfbxz_huff_tree *tree, bfbxz_stream *stream)
{
	uint64_t bits = stream->bits;
	uint32_t bits_read = 0;
	uint32_t sym = bfbxz_huff_decode_bits(tree, &bits, &bits_read);
	stream->bits = bits;
	stream->num_bits -= bits_read;
	return sym;
}

static void bfbxz_init_static(bfbxz_context *zc)
{
	uint8_t lit_length_bits[288];
	memset(lit_length_bits +   0, 8, 144 -   0);
	memset(lit_length_bits + 144, 9, 256 - 144);
	memset(lit_length_bits + 256, 7, 280 - 256);
	memset(lit_length_bits + 280, 8, 288 - 280);
	bfbxz_huff_build(&zc->huff_lit_length, lit_length_bits, sizeof(lit_length_bits));

	uint8_t dist_bits[32];
	memset(dist_bits + 0, 5, 32 - 0);
	bfbxz_huff_build(&zc->huff_dist, dist_bits, sizeof(dist_bits));
}

static int bfbxz_init_dynamic_tree(bfbxz_context *zc, const bfbxz_huff_tree *huff_code_length,
	bfbxz_huff_tree *tree, uint32_t num_symbols)
{
	uint8_t code_lengths[BFBXZ_HUFF_MAX_VALUE];
	if (num_symbols > BFBXZ_HUFF_MAX_VALUE) return 0;

	uint32_t symbol_index = 0;
	uint8_t prev = 0;
	while (symbol_index < num_symbols) {
		bfbxz_refill(&zc->stream);
		uint32_t inst = bfbxz_huff_decode(huff_code_length, &zc->stream);
		if (inst <= 15) {
			prev = (uint8_t)inst;
			code_lengths[symbol_index++] = (uint8_t)inst;
		} else if (inst == 16) {
			uint32_t num = 3 + ((uint32_t)zc->stream.bits & 0x3);
			zc->stream.bits >>= 2;
			zc->stream.num_bits -= 2;
			if (symbol_index + num > num_symbols) return 0;
			memset(code_lengths + num_symbols, prev, num);
			num_symbols += num;
		} else if (inst == 17) {
			uint32_t num = 3 + ((uint32_t)zc->stream.bits & 0x7);
			zc->stream.bits >>= 3;
			zc->stream.num_bits -= 3;
			if (symbol_index + num > num_symbols) return 0;
			memset(code_lengths + num_symbols, 0, num);
			num_symbols += num;
			prev = 0;
		} else if (inst == 18) {
			uint32_t num = 11 + ((uint32_t)zc->stream.bits & 0x7f);
			zc->stream.bits >>= 7;
			zc->stream.num_bits -= 7;
			if (symbol_index + num > num_symbols) return 0;
			memset(code_lengths + num_symbols, 0, num);
			num_symbols += num;
			prev = 0;
		} else {
			return 0;
		}
	}

	return 1;
}

static int bfbxz_init_dynamic(bfbxz_context *zc)
{
	bfbxz_refill(&zc->stream);

	uint32_t bits = (uint32_t)zc->stream.bits;
	zc->stream.bits >>= 14;
	zc->stream.num_bits -= 14;

	uint32_t num_lit_lengths = 257 + (bits & 0x1f);
	uint32_t num_dists = 1 + (bits >> 5 & 0x1f);
	uint32_t num_code_lengths = 4 + (bits >> 9 & 0xf);
	if (num_lit_lengths > 288) return 0;
	if (num_dists > 32) return 0;
	if (num_code_lengths > 18) return 0;

	uint8_t code_lengths[18];
	for (uint32_t i = 0; i < num_code_lengths; i++) {
		bfbxz_refill(&zc->stream);
		code_lengths[bfbxz_code_length_swizzle[i + 0]] = (uint32_t)zc->stream.bits & 0x7;
		zc->stream.bits >>= 3;
		zc->stream.num_bits -= 3;
	}
	memset(code_lengths + num_code_lengths, 0, 32 - num_code_lengths);

	bfbxz_huff_tree huff_code_length;
	if (!bfbxz_huff_build(&huff_code_length, code_lengths, num_code_lengths)) {
		return 0;
	}
	if (!bfbxz_init_dynamic_tree(zc, &huff_code_length, &zc->huff_lit_length, num_lit_lengths)) {
		return 0;
	}
	if (!bfbxz_init_dynamic_tree(zc, &huff_code_length, &zc->huff_dist, num_dists)) {
		return 0;
	}

	return 1;
}

static int bfbxz_decompress_block(bfbxz_context *zc)
{
	char *out_begin = zc->output;
	char *out_ptr = out_begin + zc->output_pos;
	char *out_end = out_begin + zc->output_size;

	for (;;) {
		bfbxz_refill(&zc->stream); // 64 bits
		uint64_t bbuf = zc->stream.bits;
		uint32_t bread = 0;

		uint32_t lit_length;
		lit_length = bfbxz_huff_decode_bits(&zc->huff_lit_length, &bbuf, &bread); // 49 bits

		if (lit_length <= 255) {
			if (out_ptr == out_end) return 0;
			*out_ptr++ = (char)lit_length;
		} else if (lit_length - 257 <= 285 - 257) {
			uint32_t length, distance;

			// Length
			{
				uint32_t lut = bfbxz_length_lut[lit_length - 257];
				uint32_t base = lut >> 17;
				uint32_t offset = ((uint32_t)bbuf & lut & 0x1fff); // 34 bits
				uint32_t bits = (lut >> 13) & 0xf;
				bbuf >>= bits;
				bread += bits;
				length = base + offset;
			}

			// Distance
			{
				uint32_t dist = bfbxz_huff_decode_bits(&zc->huff_dist, &bbuf, &bread); // 19 bits
				if (dist >= 32) return 0;
				uint32_t lut = bfbxz_dist_lut[dist];
				uint32_t base = lut >> 17;
				uint32_t offset = ((uint32_t)bbuf & lut & 0x1fff); // 6 bits
				uint32_t bits = (lut >> 13) & 0xf;
				bbuf >>= bits;
				bread += bits;
				distance = base + offset;
			}

			if (distance > out_ptr - out_begin) return 0;
			if (length > out_end - out_ptr) return 0;

			// TODO: Do something better than per-byte copy
			const char *src = out_ptr - distance;
			char *end = out_ptr + length;
			while (out_ptr != end) {
				*out_ptr++ = *src++;
			}

		} else if (lit_length == 256) {
			zc->stream.bits = bbuf;
			zc->stream.num_bits -= bread;
			break;
		} else {
			return 0;
		}

		zc->stream.bits = bbuf;
		zc->stream.num_bits -= bread;
	}

	zc->output_pos = (uint32_t)(out_ptr - out_begin);
}

static int bfbxz_inflate(void *dst, uint32_t dst_size, const void *src, uint32_t src_size)
{
	bfbxz_context zcontext, *zc = &zcontext;
	zc->output = (char*)dst;
	zc->output_pos = 0;
	zc->output_size = dst_size;
	zc->stream.data = (const char*)src;
	zc->stream.size = src_size;
	zc->stream.pos = 0;
	zc->stream.num_bits = 0;
	zc->stream.num_next_bits = 0;
	zc->stream.bits = 0;
	zc->stream.next_bits = 0;

	// Zlib header
	{
		bfbxz_refill(&zc->stream);
		uint32_t bits = (uint32_t)zc->stream.bits;
		uint8_t cmf = (bits & 0xff);
		uint8_t flg = (bits >> 8);
		zc->stream.bits >>= 16;
		zc->stream.num_bits -= 16;

		if ((cmf & 0xf) != 0x8) return 0; // Unknown compression method
		if ((flg & 0x10) != 0) return 0; // Requires dictionary
		if ((cmf << 8 | flg) % 31 != 0) return 0; // Bad FCHECK
	}

	for (;;) {
		bfbxz_refill(&zc->stream);
		uint32_t header = (uint32_t)zc->stream.bits & 7;
		zc->stream.bits >>= 3;
		zc->stream.num_bits -= 3;

		uint32_t type = header >> 1;
		if (type == 0) {
			uint32_t bits_bytes = zc->stream.num_bits / 8;
			zc->stream.pos -= bits_bytes;
			zc->stream.bits = 0;
			zc->stream.num_bits = 0;

			const uint8_t *len_head = (const uint8_t*)(zc->stream.data + zc->stream.pos);
			uint16_t len = (uint16_t)len_head[0] | (uint16_t)len_head[1] << 8;
			uint16_t nlen = (uint16_t)len_head[2] | (uint16_t)len_head[3] << 8;
			if (len != (uint16_t)~nlen) return 0;
			if (zc->stream.pos + len > zc->stream.size) return 0;
			if (zc->output_pos + len > zc->output_size) return 0;

			const void *src = zc->stream.data + zc->stream.pos;
			void *dst = zc->output + zc->output_pos;
			memcpy(dst, src, len);

			zc->output_pos += len;
			zc->stream.pos += len;

		} else if (type <= 2) {
			if (type == 1) {
				bfbxz_init_static(zc);
			} else {
				if (!bfbxz_init_dynamic(zc)) return 0;
			}

			if (!bfbxz_decompress_block(zc)) return 0;

		} else {
			return 0;
		}

		if (header & 1) break;
	}

	return 1;
}

// -- Utility

#define bfbx_arraycount(arr) (sizeof(arr) / sizeof(*(arr)))

static const char *bfbx_prop_type_str(bfbx_prop_type type)
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

#define bfbx_push_temp(type, bc, num) (type*)bfbx_alloc_temp((bc), (num) * sizeof(type))
#define bfbx_push_result(type, bc, num) (type*)bfbx_alloc_result((bc), (num) * sizeof(type))

static const char *bfbx_result_string(bfbx_ctx *bc, const bfbx_fstring *string)
{
	if (string->length == 0) return "";

	char *copy = bfbx_push_result(char, bc, string->length + 1);
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

#define bfbx_append(bc, list, type) (type*)bfbx_append_size((bc), (list), sizeof(type))

static uint32_t bfbx_object_hash(uint64_t id)
{
	// TODO: Something better?
	uint64_t lo = (id & UINT64_C(0xffffffff)) * UINT64_C(2654435761);
	uint64_t hi = (id >> 32) * UINT64_C(2654435761);
	return (uint32_t)((lo + hi) >> 32);
}

static void bfbx_object_insert(bfbx_object_map *map, bqq_fbx_base *object)
{
	uint32_t mask = map->size - 1;
	uint32_t index = bfbx_object_hash(object->id) & mask;
	while (map->map[index] != NULL) {
		index = (index + 1) & mask;
	}
	map->map[index] = object;
}

static bqq_fbx_base *bfbx_object_find(const bfbx_object_map *map, uint64_t id)
{
	uint32_t mask = map->size - 1;
	uint32_t index = bfbx_object_hash(id) & mask;
	while (map->map[index] != NULL) {
		bqq_fbx_base *object = map->map[index];
		if (object->id == id) {
			return object;
		}
		index = (index + 1) & mask;
	}
	return NULL;
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

// NOTE: Only one returned pointer can be active at a time per context
static const void *bfbx_get_array_data(bfbx_ctx *bc, const bfbx_farray *array, bfbx_prop_type type)
{
	if (array->encoding == 0) {
		return array->compressed_data;
	} else if (array->encoding == 1) {
		uint32_t elem_size = 0;
		switch (type) {
		case bfbx_prop_array_s32: elem_size = 4; break;
		case bfbx_prop_array_s64: elem_size = 8; break;
		case bfbx_prop_array_f32: elem_size = 4; break;
		case bfbx_prop_array_f64: elem_size = 8; break;
		default:
			bfbx_error(bc, "Invalid array type %s", bfbx_prop_type_str(type));
			return 0;
		}
		uint32_t decompressed_size = array->length * elem_size;
		uint32_t round_size = bfbx_to_pow2(decompressed_size);
		if (bc->decompress_bytes < round_size) {
			bc->decompress_buffer = realloc(bc->decompress_buffer, round_size);
			bc->decompress_bytes = round_size;
		}

		if (!bfbxz_inflate(bc->decompress_buffer, decompressed_size,
			array->compressed_data, array->compressed_bytes)) {
			bfbx_error(bc, "Failed to decompress array");
			return NULL;
		}

		return bc->decompress_buffer;
	} else {
		bfbx_error(bc, "Unknown array encoding %u", array->encoding);
		return NULL;
	}
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
		bfbx_error(bc, "Cannot convert %s to u64", bfbx_prop_type_str(prop->type));
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
		bfbx_error(bc, "Cannot convert %s to f64", bfbx_prop_type_str(prop->type));
		return 0;
	}
	return 1;
}

static int bfbx_parse_to_f64(bfbx_ctx *bc, double *dst)
{
	bfbx_fprop p;
	return bfbx_parse_prop(bc, &p) && bfbx_prop_to_f64(bc, &p, dst);
}

static int bfbx_prop_to_array_f64(bfbx_ctx *bc, const bfbx_fprop *prop, double *dst)
{
	if (!bfbx_is_array(prop->type)) {
		bfbx_error(bc, "Cannot convert %s to f64 array", bfbx_prop_type_str(prop->type));
		return 0;
	}

	const bfbx_farray *array = &prop->value.array;
	const void *data = bfbx_get_array_data(bc, array, prop->type);
	if (!data) return 0;

	uint32_t num = array->length;

	switch (prop->type) {
	case bfbx_prop_array_s32: {
		for (const int32_t *src = (const int32_t*)data, *end = src + num; src != end; src++) {
			*dst++ = (double)*src;
		}
	} break;
	case bfbx_prop_array_s64: {
		for (const int64_t *src = (const int64_t*)data, *end = src + num; src != end; src++) {
			*dst++ = (double)*src;
		}
	} break;
	case bfbx_prop_array_f32: {
		for (const float *src = (const float*)data, *end = src + num; src != end; src++) {
			*dst++ = (double)*src;
		}
	} break;
	case bfbx_prop_array_f64: {
		memcpy(dst, data, num * sizeof(double));
	} break;
	default:
		bfbx_error(bc, "Cannot convert %s to f64 array", bfbx_prop_type_str(prop->type));
		return 0;
	}
	return 1;
}

static int bfbx_parse_to_array_f64(bfbx_ctx *bc, double *dst)
{
	bfbx_fprop p;
	return bfbx_parse_prop(bc, &p) && bfbx_prop_to_array_f64(bc, &p, dst);
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

static int bfbx_doc_object_mesh(bfbx_ctx *bc, bfbx_fnode *obj_node, bqq_fbx_base *object)
{
	bqq_fbx_mesh *mesh = (bqq_fbx_mesh*)object;

	bfbx_fnode child;
	while (bfbx_parse_child(bc, obj_node, &child)) {
		if (bc->failed) return 0;

		if (bfbx_streq(&child.name, "Properties70")) {
			bfbx_dprop_map *prop_map = &bc->object_types[object->type].prop_map;
			if (!bfbx_doc_properties70(bc, &child, object, prop_map)) return 0;
		} else if (bfbx_streq(&child.name, "Vertices")) {
			if (child.prop_count != 1) {
				bfbx_error(bc, "Invalid amount of properties for Vertices: %u", child.prop_count);
				return 0;
			}
			bfbx_fprop prop;
			if (!bfbx_parse_prop(bc, &prop)) return 0;
			if (!bfbx_is_array(prop.type)) {
				bfbx_error(bc, "Vertices is not an array");
				return 0;
			}

			uint32_t array_size = prop.value.array.length;
			if (array_size % 3 != 0) {
				bfbx_error(bc, "Vertices array is not divisble by 3: %u", array_size);
				return 0;
			}

			mesh->num_vertices = array_size / 3;
			mesh->vertex_positions = bfbx_push_result(bqq_fbx_vec3, bc, mesh->num_vertices);

			if (!bfbx_prop_to_array_f64(bc, &prop, (double*)mesh->vertex_positions)) return 0;

		} else {
			// Unknown child node, skip it
			bc->pos = child.end_offset;
		}
	}

	return 1;
}

static int bfbx_doc_object_generic(bfbx_ctx *bc, bfbx_fnode *obj_node, bqq_fbx_base *object)
{
	bfbx_fnode child;
	while (bfbx_parse_child(bc, obj_node, &child)) {
		if (bc->failed) return 0;

		if (bfbx_streq(&child.name, "Properties70")) {
			bfbx_dprop_map *prop_map = &bc->object_types[object->type].prop_map;
			if (!bfbx_doc_properties70(bc, &child, object, prop_map)) return 0;
		} else {
			// Unknown child node, skip it
			bc->pos = child.end_offset;
		}
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

	bqq_fbx_base *object = (bqq_fbx_base*)bfbx_alloc_result(bc, obj_type->size);
	if (!object) return 0;
	memcpy(object, obj_type->default_value, obj_type->size);

	object->id = id;

	// Truncate name to \x00\x01 separating name and class
	for (uint32_t i = 0; i + 1 < name.length; i++) {
		if (name.data[i] == '\x00' && name.data[i + 1] == '\x01') {
			name.length = i;
			break;
		}
	}
	object->name = bfbx_result_string(bc, &name);

	if (type == bqq_fbx_type_mesh) {
		bfbx_doc_object_mesh(bc, obj_node, object);
	} else {
		bfbx_doc_object_generic(bc, obj_node, object);
	}

	bqq_fbx_base **ptr = bfbx_append(bc, &bc->all_objects, bqq_fbx_base*);
	if (!ptr) return 0;
	*ptr = object;

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

static int bfbx_doc_connection(bfbx_ctx *bc, bfbx_fnode *node)
{
	if (node->prop_count != 3) {
		bfbx_error(bc, "Unexpected amount of properties for Connection");
		return 0;
	}

	bfbx_fstring type;
	if (!bfbx_parse_to_string(bc, &type)) return 0;
	if (bfbx_streq(&type, "OO")) {
		uint64_t child_id, parent_id;
		if (!bfbx_parse_to_u64(bc, &child_id)) return 0;
		if (!bfbx_parse_to_u64(bc, &parent_id)) return 0;

		bqq_fbx_base *child = bfbx_object_find(&bc->object_map, child_id);
		if (!child) {
			bfbx_error(bc, "Invalid child ID %" PRIu64, child_id);
			return 0;
		}

		bqq_fbx_base *parent = &bc->scene->root.base;
		if (parent_id != 0) {
			parent = bfbx_object_find(&bc->object_map, parent_id);
			if (!parent) {
				bfbx_error(bc, "Invalid parent ID %" PRIu64, parent_id);
				return 0;
			}
		}

		parent->num_children++;
		if (parent->type = bqq_fbx_type_node) {
			bqq_fbx_node *parent_node = (bqq_fbx_node*)parent;
			switch (child->type) {
			case bqq_fbx_type_node:
				bc->scene->num_nodes++;
				parent_node->num_nodes++;
				((bqq_fbx_node*)child)->parent = parent_node;
				break;
			case bqq_fbx_type_mesh:
				bc->scene->num_meshes++;
				parent_node->num_meshes++;
				((bqq_fbx_mesh*)child)->parent = parent_node;
				break;
			case bqq_fbx_type_material:
				bc->scene->num_materials++;
				parent_node->num_materials++;
				((bqq_fbx_material*)child)->parent = parent_node;
				break;
			case bqq_fbx_type_light:
				bc->scene->num_lights++;
				parent_node->num_lights++;
				((bqq_fbx_light*)child)->parent = parent_node;
				break;
			case bqq_fbx_type_camera:
				bc->scene->num_cameras++;
				parent_node->num_cameras++;
				((bqq_fbx_camera*)child)->parent = parent_node;
				break;
			}
		}

		child->parent = parent;

	} else {
		// Ignore unknown connection types
		bc->pos = node->end_offset;
	}

	return 1;
}

static int bfbx_doc_section_connections(bfbx_ctx *bc, bfbx_fnode *section)
{
	bfbx_fnode obj_node;
	while (bfbx_parse_child(bc, section, &obj_node)) {
		if (bc->failed) return 0;
		if (!bfbx_doc_connection(bc, &obj_node)) return 0;
	}

	return 1;
}

static int bfbx_doc_root(bfbx_ctx *bc)
{
	bqq_fbx_scene *scene = bc->scene;
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

	// Copy all objects and insert to map
	{
		uint32_t num = bc->all_objects.count;
		bqq_fbx_base **dst = bfbx_push_result(bqq_fbx_base*, bc, num);
		if (!dst) return 0;
		bc->scene->num_objects = num;
		bc->scene->objects = dst;

		uint32_t map_size = bfbx_to_pow2(num * 3);
		bc->object_map.size = map_size;
		bc->object_map.map = bfbx_push_temp(bqq_fbx_base*, bc, map_size);
		memset(bc->object_map.map, 0, map_size * sizeof(bqq_fbx_base**));
		uint32_t map_mask = map_size - 1;

		for (bfbx_append_chunk *chunk = bc->all_objects.first; chunk; chunk = chunk->next) {
			bqq_fbx_base **src = (bqq_fbx_base**)(chunk + 1);
			for (uint32_t i = 0; i < chunk->count; i++) {
				bqq_fbx_base *object = src[i];
				*dst++ = object;
				bfbx_object_insert(&bc->object_map, object);
			}
		}
	}

	// 3. Connections
	for (int attempt = 0; ; attempt++) {
		int found = 0;
		while (bfbx_parse_node(bc, &section)) {
			if (section.end_offset == 0) break;
			if (bc->failed) return 0;
			if (bfbx_streq(&section.name, "Connections")) {
				if (!bfbx_doc_section_connections(bc, &section)) return 0;
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

	// Resolve child pointers, allocate child arrays and reet counts
	for (uint32_t i = 0; i < bc->scene->num_objects; i++) {
		bqq_fbx_base *parent = bc->scene->objects[i];
		if (parent->num_children > 0) {
			parent->children = bfbx_push_result(bqq_fbx_base*, bc, parent->num_children);
			parent->num_children = 0;
		}

		if (parent->type == bqq_fbx_type_node) {
			bqq_fbx_node *node = (bqq_fbx_node*)parent;
			if (node->num_nodes > 0) {
				node->nodes = bfbx_push_result(bqq_fbx_node*, bc, node->num_nodes);
				node->num_nodes = 0;
			}
			if (node->num_meshes > 0) {
				node->meshes = bfbx_push_result(bqq_fbx_mesh*, bc, node->num_meshes);
				node->num_meshes = 0;
			}
			if (node->num_materials > 0) {
				node->materials = bfbx_push_result(bqq_fbx_material*, bc, node->num_materials);
				node->num_materials = 0;
			}
			if (node->num_lights > 0) {
				node->lights = bfbx_push_result(bqq_fbx_light*, bc, node->num_lights);
				node->num_lights = 0;
			}
			if (node->num_cameras > 0) {
				node->cameras = bfbx_push_result(bqq_fbx_camera*, bc, node->num_cameras);
				node->num_cameras = 0;
			}
		}
	}

	// Do the same for the global scene lists
	{
		if (scene->num_nodes > 0) {
			scene->nodes = bfbx_push_result(bqq_fbx_node*, bc, scene->num_nodes);
			scene->num_nodes = 0;
		}
		if (scene->num_meshes > 0) {
			scene->meshes = bfbx_push_result(bqq_fbx_mesh*, bc, scene->num_meshes);
			scene->num_meshes = 0;
		}
		if (scene->num_materials > 0) {
			scene->materials = bfbx_push_result(bqq_fbx_material*, bc, scene->num_materials);
			scene->num_materials = 0;
		}
		if (scene->num_lights > 0) {
			scene->lights = bfbx_push_result(bqq_fbx_light*, bc, scene->num_lights);
			scene->num_lights = 0;
		}
		if (scene->num_cameras > 0) {
			scene->cameras = bfbx_push_result(bqq_fbx_camera*, bc, scene->num_cameras);
			scene->num_cameras = 0;
		}
	}

	// Add to parent arrays and increment counts back
	for (uint32_t i = 0; i < bc->scene->num_objects; i++) {
		bqq_fbx_base *child = bc->scene->objects[i];
		bqq_fbx_base *parent = child->parent;
		if (!parent) continue;

		uint32_t index = parent->num_children++;
		parent->children[index] = child;

		if (parent->type == bqq_fbx_type_node) {
			bqq_fbx_node *node = (bqq_fbx_node*)parent;
			switch (child->type) {
			case bqq_fbx_type_node:
				node->nodes[node->num_nodes++] = (bqq_fbx_node*)child;
				scene->nodes[scene->num_nodes++] = (bqq_fbx_node*)child;
				break;
			case bqq_fbx_type_mesh:
				node->meshes[node->num_meshes++] = (bqq_fbx_mesh*)child;
				scene->meshes[scene->num_meshes++] = (bqq_fbx_mesh*)child;
				break;
			case bqq_fbx_type_material:
				node->materials[node->num_materials++] = (bqq_fbx_material*)child;
				scene->materials[scene->num_materials++] = (bqq_fbx_material*)child;
				break;
			case bqq_fbx_type_light:
				node->lights[node->num_lights++] = (bqq_fbx_light*)child;
				scene->lights[scene->num_lights++] = (bqq_fbx_light*)child;
				break;
			case bqq_fbx_type_camera:
				node->cameras[node->num_cameras++] = (bqq_fbx_camera*)child;
				scene->cameras[scene->num_cameras++] = (bqq_fbx_camera*)child;
				break;
			}
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
	bc->scene = scene;

	// Setup root
	{
		scene->root.base.name = "";

		bqq_fbx_base **ptr = bfbx_append(bc, &bc->all_objects, bqq_fbx_base*);
		if (!ptr) return 0;
		*ptr = &scene->root.base;
	}

	if (!bfbx_init_object_types(bc)) goto error;
	if (!bfbx_parse_header(bc)) goto error;
	if (!bfbx_doc_root(bc)) goto error;

	free(bc->decompress_buffer);
	bfbx_free_chunk(bc->temp_arena.chunk);
	internal_scene->result_allocation = bc->result_arena.chunk;
	return scene;
error:
	free(bc->decompress_buffer);
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
