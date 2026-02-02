"""
icp_alignment.py
ICP registration and topology transfer for forensic verification.
"""

import numpy as np
from scipy.spatial import cKDTree


def compute_centroid(points: np.ndarray) -> np.ndarray:
    return np.mean(points, axis=0)


def compute_scale(points: np.ndarray) -> float:
    centroid = compute_centroid(points)
    diffs = points - centroid
    return float(np.sqrt(np.mean(np.sum(diffs ** 2, axis=1))))


def normalize_mesh(vertices: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
    centroid = compute_centroid(vertices)
    centered = vertices - centroid
    scale = compute_scale(centered)
    if scale < 1e-12:
        scale = 1.0
    normalized = centered / scale
    return normalized, centroid, scale


def anisotropic_normalize(vertices: np.ndarray) -> np.ndarray:
    """
    Undo non-uniform scaling without rotating the mesh.

    Non-uniform stretch (e.g. pulling a suitcase longer in Blender) changes
    the shape in a way that a single scalar normalisation cannot undo.  This
    function:
        1. Centres the mesh.
        2. Computes the covariance matrix → PCA axes + per-axis variances.
        3. Projects vertices into the PCA frame, scales each axis to unit
           variance, then projects *back* into the original frame.
        4. Applies a final uniform RMS normalisation.

    Because we project back (step 3), the net effect is pure scale correction
    with no rotation.  The watermark displacement directions (embedded along
    vertex normals in the original orientation) are preserved, so ICP and the
    matched-filter extraction still work correctly.
    """
    centroid = np.mean(vertices, axis=0)
    centered = vertices - centroid
    cov = np.cov(centered.T)
    eigenvalues, eigvecs = np.linalg.eigh(cov)          # ascending order
    stds = np.sqrt(np.maximum(eigenvalues, 1e-12))
    # Project → scale → back-project  (no net rotation)
    pca_coords = centered @ eigvecs                      # into PCA frame
    scaled     = pca_coords / stds                       # unit variance / axis
    corrected  = scaled @ eigvecs.T                      # back to original frame
    # Final uniform normalise
    rms = float(np.sqrt(np.mean(np.sum(corrected ** 2, axis=1))))
    if rms > 1e-12:
        corrected = corrected / rms
    return corrected


def adaptive_normalize(vertices: np.ndarray) -> np.ndarray:
    """
    Adaptive normalisation: anisotropic on asymmetric meshes, uniform on symmetric ones.

    Anisotropic normalisation undoes non-uniform stretch perfectly on meshes
    with well-separated PCA axes (boxes, suitcases, vehicles — anything with
    distinct length/width/height).  On near-spherical meshes where all axes
    are nearly equal, the per-axis scaling amplifies floating-point noise
    rather than correcting stretch, so we fall back to uniform normalisation.

    The decision boundary: ratio of smallest to largest PCA eigenvalue.
      > 0.7  →  near-symmetric  →  uniform normalise
      ≤ 0.7  →  asymmetric      →  anisotropic normalise
    """
    centroid = np.mean(vertices, axis=0)
    centered = vertices - centroid
    cov = np.cov(centered.T)
    eigenvalues = np.linalg.eigvalsh(cov)  # ascending
    symmetry_ratio = eigenvalues[0] / eigenvalues[2] if eigenvalues[2] > 1e-12 else 1.0

    if symmetry_ratio > 0.7:
        norm, _, _ = normalize_mesh(vertices)
        return norm
    else:
        return anisotropic_normalize(vertices)


def icp_align(source, target, max_iterations=100, tolerance=1e-6):
    src_norm, _, _ = normalize_mesh(source)
    tgt_norm, _, _ = normalize_mesh(target)
    aligned = src_norm.copy()
    prev_error = np.inf
    tree = cKDTree(tgt_norm)
    for _ in range(max_iterations):
        distances, indices = tree.query(aligned)
        matched_target = tgt_norm[indices]
        centroid_src = compute_centroid(aligned)
        centroid_tgt = compute_centroid(matched_target)
        src_centered = aligned - centroid_src
        tgt_centered = matched_target - centroid_tgt
        H = src_centered.T @ tgt_centered
        U, S, Vt = np.linalg.svd(H)
        d = np.linalg.det(Vt.T @ U.T)
        sign_matrix = np.diag([1, 1, np.sign(d)])
        R = Vt.T @ sign_matrix @ U.T
        aligned = (R @ src_centered.T).T + centroid_tgt
        mean_error = float(np.mean(distances))
        if abs(prev_error - mean_error) < tolerance:
            break
        prev_error = mean_error
    return aligned, R, prev_error


def resample_onto_target(source_vertices, target_vertices, target_faces):
    tree = cKDTree(source_vertices)
    _, indices = tree.query(target_vertices)
    return source_vertices[indices]


def compute_correlation(signature_a, signature_b):
    a = signature_a.flatten()
    b = signature_b.flatten()
    min_len = min(len(a), len(b))
    a, b = a[:min_len], b[:min_len]
    a_centered = a - np.mean(a)
    b_centered = b - np.mean(b)
    numerator = np.dot(a_centered, b_centered)
    denom = np.sqrt(np.dot(a_centered, a_centered) * np.dot(b_centered, b_centered))
    return 0.0 if denom < 1e-12 else float(numerator / denom)
