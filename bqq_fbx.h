#pragma once

typedef struct {
	unsigned byte_offset;  // < Approximate byte offset into the file
	char description[256]; // < Null terminated error description
} bqq_fbx_error;
