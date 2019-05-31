#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
	unsigned byte_offset;  // < Approximate byte offset into the file
	char description[256]; // < Null terminated error description
} bqq_fbx_error;

typedef enum {
	bqq_fbx_type_unknown,
	bqq_fbx_type_node,
	bqq_fbx_type_mesh,
	bqq_fbx_type_material,
	bqq_fbx_type_light,
	bqq_fbx_type_camera,

	bqq_fbx_num_types,
} bqq_fbx_type;

typedef struct bqq_fbx_base_s bqq_fbx_base;

typedef struct bqq_fbx_unknown_s bqq_fbx_unknown;
typedef struct bqq_fbx_node_s bqq_fbx_node;
typedef struct bqq_fbx_mesh_s bqq_fbx_mesh;
typedef struct bqq_fbx_material_s bqq_fbx_material;
typedef struct bqq_fbx_light_s bqq_fbx_light;
typedef struct bqq_fbx_camera_s bqq_fbx_camera;

struct bqq_fbx_base_s {
	uint64_t id;
	const char *name;
	bqq_fbx_type type;

	bqq_fbx_base *parent;

	uint32_t num_children;
	bqq_fbx_base **children;

};

struct bqq_fbx_unknown_s {
	bqq_fbx_base base; 
};

struct bqq_fbx_node_s {
	bqq_fbx_base base; 

	double local_translation[3]; // < Translation relative to parent node
	double local_rotation[3];    // < Euler angle rotation relative to parent node
	double local_scaling[3];     // < Scaling relative to parent node

	bqq_fbx_node *parent;

	uint32_t num_nodes;
	bqq_fbx_node **nodes;

	uint32_t num_meshes;
	bqq_fbx_mesh **meshes;

	uint32_t num_materials;
	bqq_fbx_material **materials;

	uint32_t num_lights;
	bqq_fbx_light **lights;

	uint32_t num_cameras;
	bqq_fbx_camera **cameras;

};

struct bqq_fbx_mesh_s {
	bqq_fbx_base base; 
	bqq_fbx_node *parent;

};

struct bqq_fbx_light_s {
	bqq_fbx_base base; 
	bqq_fbx_node *parent;

	double color[3];  // < Normalized RGB color
	double intensity; // < Intensity of the light (TODO: units?)
};

struct bqq_fbx_camera_s {
	bqq_fbx_base base; 
	bqq_fbx_node *parent;

	double aspect_width;
	double aspect_height;
};

struct bqq_fbx_material_s {
	bqq_fbx_base base; 
	bqq_fbx_node *parent;
};

typedef struct {
	const char *name;
	bqq_fbx_node root;

	uint32_t num_objects;
	bqq_fbx_base **objects;

} bqq_fbx_scene;

bqq_fbx_scene *bqq_fbx_parse_file(const char *filename, bqq_fbx_error *error);
bqq_fbx_scene *bqq_fbx_parse_memory(const void *data, size_t size, bqq_fbx_error *error);
void bqq_fbx_free(bqq_fbx_scene *scene);
