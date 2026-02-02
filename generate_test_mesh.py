"""
generate_test_mesh.py
Generates test meshes (sphere, torus, cube) as OBJ files for local testing.
Usage: python generate_test_mesh.py --shape sphere --output test_model.obj
"""

import numpy as np
import argparse
import math


def generate_sphere(radius: float = 1.0, segments: int = 32, rings: int = 16) -> tuple[np.ndarray, np.ndarray]:
    vertices = []
    faces = []

    # Poles
    vertices.append([0.0, radius, 0.0])   # top pole — index 0
    vertices.append([0.0, -radius, 0.0])  # bottom pole — index 1

    # Ring vertices
    for r in range(1, rings):
        phi = math.pi * r / rings
        for s in range(segments):
            theta = 2.0 * math.pi * s / segments
            x = radius * math.sin(phi) * math.cos(theta)
            y = radius * math.cos(phi)
            z = radius * math.sin(phi) * math.sin(theta)
            vertices.append([x, y, z])

    # Top cap
    for s in range(segments):
        next_s = (s + 1) % segments
        faces.append([0, 2 + s, 2 + next_s])

    # Body quads → triangles
    for r in range(rings - 2):
        for s in range(segments):
            next_s = (s + 1) % segments
            i0 = 2 + r * segments + s
            i1 = 2 + r * segments + next_s
            i2 = 2 + (r + 1) * segments + next_s
            i3 = 2 + (r + 1) * segments + s
            faces.append([i0, i1, i2])
            faces.append([i0, i2, i3])

    # Bottom cap
    bottom_ring_start = 2 + (rings - 2) * segments
    for s in range(segments):
        next_s = (s + 1) % segments
        faces.append([1, bottom_ring_start + next_s, bottom_ring_start + s])

    return np.array(vertices, dtype=np.float64), np.array(faces, dtype=np.int64)


def generate_torus(major_radius: float = 2.0, minor_radius: float = 0.6, major_segments: int = 40, minor_segments: int = 20) -> tuple[np.ndarray, np.ndarray]:
    vertices = []
    faces = []

    for i in range(major_segments):
        theta = 2.0 * math.pi * i / major_segments
        for j in range(minor_segments):
            phi = 2.0 * math.pi * j / minor_segments
            x = (major_radius + minor_radius * math.cos(phi)) * math.cos(theta)
            y = minor_radius * math.sin(phi)
            z = (major_radius + minor_radius * math.cos(phi)) * math.sin(theta)
            vertices.append([x, y, z])

    for i in range(major_segments):
        next_i = (i + 1) % major_segments
        for j in range(minor_segments):
            next_j = (j + 1) % minor_segments
            i0 = i * minor_segments + j
            i1 = i * minor_segments + next_j
            i2 = next_i * minor_segments + next_j
            i3 = next_i * minor_segments + j
            faces.append([i0, i1, i2])
            faces.append([i0, i2, i3])

    return np.array(vertices, dtype=np.float64), np.array(faces, dtype=np.int64)


def generate_cube(size: float = 1.0, subdivisions: int = 4) -> tuple[np.ndarray, np.ndarray]:
    """Subdivided cube for a mesh with enough vertices for spectral analysis."""
    s = size / 2.0
    vertices = []
    faces = []

    def add_face(corners, subdiv):
        """Subdivide a quad face into a grid of triangles."""
        base = len(vertices)
        for i in range(subdiv + 1):
            for j in range(subdiv + 1):
                t = i / subdiv
                u = j / subdiv
                # Bilinear interpolation
                p = (
                    corners[0] * (1 - t) * (1 - u) +
                    corners[1] * t * (1 - u) +
                    corners[2] * t * u +
                    corners[3] * (1 - t) * u
                )
                vertices.append(p.tolist())
        for i in range(subdiv):
            for j in range(subdiv):
                i0 = base + i * (subdiv + 1) + j
                i1 = base + (i + 1) * (subdiv + 1) + j
                i2 = base + (i + 1) * (subdiv + 1) + (j + 1)
                i3 = base + i * (subdiv + 1) + (j + 1)
                faces.append([i0, i1, i2])
                faces.append([i0, i2, i3])

    # 6 faces of the cube
    face_defs = [
        [np.array([-s, -s, -s]), np.array([s, -s, -s]), np.array([s, s, -s]), np.array([-s, s, -s])],  # front
        [np.array([s, -s, s]),  np.array([-s, -s, s]),  np.array([-s, s, s]),  np.array([s, s, s])],    # back
        [np.array([-s, -s, s]),  np.array([s, -s, s]),  np.array([s, -s, -s]), np.array([-s, -s, -s])], # bottom
        [np.array([-s, s, -s]),  np.array([s, s, -s]),  np.array([s, s, s]),   np.array([-s, s, s])],   # top
        [np.array([-s, -s, -s]), np.array([-s, -s, s]), np.array([-s, s, s]),  np.array([-s, s, -s])],  # left
        [np.array([s, -s, s]),   np.array([s, -s, -s]), np.array([s, s, -s]),  np.array([s, s, s])],    # right
    ]

    for corners in face_defs:
        add_face(corners, subdivisions)

    return np.array(vertices, dtype=np.float64), np.array(faces, dtype=np.int64)


def save_obj(filepath: str, vertices: np.ndarray, faces: np.ndarray, comment: str = ""):
    with open(filepath, "w") as f:
        if comment:
            f.write(f"# {comment}\n")
        for v in vertices:
            f.write(f"v {v[0]:.10f} {v[1]:.10f} {v[2]:.10f}\n")
        for face in faces:
            f.write(f"f {face[0]+1} {face[1]+1} {face[2]+1}\n")


def main():
    parser = argparse.ArgumentParser(description="Generate test meshes for watermarking")
    parser.add_argument("--shape", choices=["sphere", "torus", "cube"], default="sphere", help="Mesh shape")
    parser.add_argument("--output", "-o", default="test_model.obj", help="Output OBJ file")
    args = parser.parse_args()

    if args.shape == "sphere":
        verts, faces = generate_sphere(radius=1.0, segments=48, rings=24)
        comment = "Test sphere — 48 segments, 24 rings"
    elif args.shape == "torus":
        verts, faces = generate_torus(major_radius=2.0, minor_radius=0.6, major_segments=48, minor_segments=24)
        comment = "Test torus — 48 major, 24 minor segments"
    elif args.shape == "cube":
        verts, faces = generate_cube(size=2.0, subdivisions=8)
        comment = "Test cube — 8 subdivisions per face"
    else:
        raise ValueError(f"Unknown shape: {args.shape}")

    save_obj(args.output, verts, faces, comment)
    print(f"Generated {args.shape}: {len(verts)} vertices, {len(faces)} faces → {args.output}")


if __name__ == "__main__":
    main()
