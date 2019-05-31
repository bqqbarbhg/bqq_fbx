
#define _CRT_SECURE_NO_WARNINGS
#include "../bqq_fbx.h"

int main(int argc, char **argv) {
	bqq_fbx_error error;
	bqq_fbx_scene *scene = bqq_fbx_parse_file("default.fbx", &error);

	bqq_fbx_free(scene);
	return 0;
}

#include "../bqq_fbx_implementation.h"
