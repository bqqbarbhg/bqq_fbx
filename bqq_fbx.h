#ifndef BQQ_FBX_INCLUDED
#define BQQ_FBX_INCLUDED

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

typedef union {
	struct {
		double x, y;
	};
	double v[2];
} bqq_fbx_vec2;

typedef union {
	struct {
		double x, y, z;
	};
	double v[3];
} bqq_fbx_vec3;

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

	bqq_fbx_vec3 local_translation;
	bqq_fbx_vec3 local_rotation;
	bqq_fbx_vec3 local_scaling;

	bqq_fbx_vec3 rotation_offset;
	bqq_fbx_vec3 rotation_pivot;
	bqq_fbx_vec3 scaling_offset;
	bqq_fbx_vec3 scaling_pivot;

	bqq_fbx_vec3 geometric_translation;
	bqq_fbx_vec3 geometric_rotation;
	bqq_fbx_vec3 geometric_scaling;

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

typedef struct {
	uint32_t num_vertices;
	uint32_t *vertices;
} bqq_fbx_face;

typedef struct {
	uint32_t vertex[2];
} bqq_fbx_edge;

typedef struct {
	const char *name;
	bqq_fbx_vec2 *vertex_uvs;
} bqq_fbx_uv_map;

struct bqq_fbx_mesh_s {
	bqq_fbx_base base; 
	bqq_fbx_node *parent;

	// Per-face data
	uint32_t num_faces;
	bqq_fbx_face *faces;
	bqq_fbx_vec3 *face_normals;

	// Per-edge data
	uint32_t num_edges;
	bqq_fbx_edge *edges;

	// Per-vertex data
	uint32_t num_vertices;
	uint32_t num_uv_maps;
	bqq_fbx_vec3 *vertex_positions;
	bqq_fbx_vec3 *vertex_normals;
	uint32_t *vertex_materials;
	bqq_fbx_uv_map *uv_maps;
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
	bqq_fbx_node root;

	uint32_t num_objects;
	bqq_fbx_base **objects;

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

} bqq_fbx_scene;

bqq_fbx_scene *bqq_fbx_parse_file(const char *filename, bqq_fbx_error *error);
bqq_fbx_scene *bqq_fbx_parse_memory(const void *data, size_t size, bqq_fbx_error *error);
void bqq_fbx_free(bqq_fbx_scene *scene);

#endif
