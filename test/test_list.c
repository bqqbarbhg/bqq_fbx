#define _CRT_SECURE_NO_WARNINGS

#include "../bqq_fbx_implementation.h"
#include <stdio.h>
#include <inttypes.h>

#include <intrin.h>
#define bqq_assert(cond) do { if (!(cond)) __debugbreak(); } while (0)

static void indent(int amount)
{
	for (int i = 0; i < amount; i++) {
		putchar(' ');
	}
}

int main(int argc, char **argv)
{
	bqq_fbx_error error;
	bfbx_ctx ctx, *bc = &ctx;

	int write_offset = 0;

	error.byte_offset = 0;
	error.description[0] = '\0';

	ctx.data = bfbx_read_file("default.fbx", &ctx.size, &error);
	if (!ctx.data) goto error;

	ctx.pos = 0;
	ctx.version = 0;
	ctx.error = &error;

	if (!bfbx_parse_header(bc)) goto error;
	printf("FBX version %u\n", bc->version);

	uint32_t end_offset_stack[128];
	end_offset_stack[0] = ctx.size;

	int level = 0;
	while (level >= 0) {
		uint32_t start = bc->pos;

		if (start == 0x00664f) {
			level = level;
		}

		bfbx_fnode node;
		if (!bfbx_parse_node(bc, &node)) goto error;
		if (node.end_offset == 0) {
			level--;
			continue;
		}

		uint32_t prop_start = bc->pos;

		end_offset_stack[level] = node.end_offset;

		if (write_offset) {
			printf("[0x%06x] ", start);
		}

		indent(level);
		printf("%.*s:", node.name.length, node.name.data);

		for (uint32_t i = 0; i < node.prop_count; i++) {
			bfbx_fprop prop;
			if (!bfbx_parse_prop(bc, &prop)) goto error;

			switch (prop.type) {
			case bfbx_prop_s16: printf(" %" PRId16, prop.value.s16); break;
			case bfbx_prop_s32: printf(" %" PRId32, prop.value.s32); break;
			case bfbx_prop_s64: printf(" %" PRId64, prop.value.s64); break;
			case bfbx_prop_f32: printf(" %f", prop.value.f32); break;
			case bfbx_prop_f64: printf(" %f", prop.value.f64); break;
			case bfbx_prop_bool: printf(" %s", prop.value.bool_ ? "true" : "false"); break;
			case bfbx_prop_string: printf(" \"%.*s\"", prop.value.string.length, prop.value.string.data); break;
			case bfbx_prop_binary: printf(" b\"%.*s\"", prop.value.binary.length, prop.value.binary.data); break;
			case bfbx_prop_array_s32: printf(" [s32 x %u]", prop.value.array.length); break;
			case bfbx_prop_array_s64: printf(" [s64 x %u]", prop.value.array.length); break;
			case bfbx_prop_array_f32: printf(" [f32 x %u]", prop.value.array.length); break;
			case bfbx_prop_array_f64: printf(" [f64 x %u]", prop.value.array.length); break;
			case bfbx_prop_array_bool: printf(" [bool x %u]", prop.value.array.length); break;
			default: printf(" ???"); break;
			}
		}
		putchar('\n');

		if (bc->pos < node.end_offset)
			level++;

		bqq_assert(bc->pos == prop_start + node.prop_bytes);
	}

	getchar();
	return 0;
error:
	fprintf(stderr, "\n\nFBX error at 0x%06x: %s\n", error.byte_offset, error.description);
	getchar();
	return 1;
}
