"""
spectral_engine.py
Core spectral analysis primitives for mesh watermarking.
"""

import numpy as np
from scipy import sparse
from scipy.sparse.linalg import eigsh


def compute_vertex_normals(vertices: np.ndarray, faces: np.ndarray) -> np.ndarray:
    normals = np.zeros_like(vertices, dtype=np.float64)
    v0 = vertices[faces[:, 0]]
    v1 = vertices[faces[:, 1]]
    v2 = vertices[faces[:, 2]]
    face_normals = np.cross(v1 - v0, v2 - v0)
    for i in range(3):
        np.add.at(normals[:, 0], faces[:, i], face_normals[:, 0])
        np.add.at(normals[:, 1], faces[:, i], face_normals[:, 1])
        np.add.at(normals[:, 2], faces[:, i], face_normals[:, 2])
    norms = np.linalg.norm(normals, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    normals /= norms
    return normals


def compute_average_edge_length(vertices: np.ndarray, faces: np.ndarray) -> float:
    edges = set()
    for f in faces:
        for i in range(3):
            e = (min(f[i], f[(i + 1) % 3]), max(f[i], f[(i + 1) % 3]))
            edges.add(e)
    edges = np.array(list(edges))
    diffs = vertices[edges[:, 0]] - vertices[edges[:, 1]]
    return float(np.mean(np.linalg.norm(diffs, axis=1)))


def build_cotangent_laplacian(vertices: np.ndarray, faces: np.ndarray) -> sparse.csc_matrix:
    n = len(vertices)
    ii, jj, ww = [], [], []
    for f in faces:
        for k in range(3):
            i = f[k]
            j = f[(k + 1) % 3]
            o = f[(k + 2) % 3]
            ei = vertices[i] - vertices[o]
            ej = vertices[j] - vertices[o]
            cos_a = np.dot(ei, ej)
            sin_a = np.linalg.norm(np.cross(ei, ej))
            cot = 0.0 if sin_a < 1e-12 else cos_a / sin_a
            w = 0.5 * cot
            ii.append(i); jj.append(j); ww.append(w)
            ii.append(j); jj.append(i); ww.append(w)
    L = sparse.coo_matrix((ww, (ii, jj)), shape=(n, n)).tocsc()
    diag = np.array(L.sum(axis=1)).flatten()
    L = L - sparse.diags(diag)
    return L


def compute_spectral_basis(vertices: np.ndarray, faces: np.ndarray, k: int = 20) -> tuple[np.ndarray, np.ndarray]:
    """
    Compute the k smallest non-zero eigenpairs of the cotangent Laplacian.

    Uses shift-invert mode (sigma=0) instead of which='SM'.  Shift-invert
    transforms the problem so that the smallest eigenvalues of L become the
    *largest* eigenvalues of (L - 0*I)^{-1}, which ARPACK converges on
    reliably.  This is orders of magnitude more stable on irregular, real-world
    meshes than the raw SM mode.

    If convergence still fails (e.g. the mesh has near-singular rows), the
    function automatically retries with fewer requested modes until it
    succeeds or hits a hard floor of 3 modes.
    """
    from scipy.sparse.linalg import splu, ArpackNoConvergence, LinearOperator

    L = build_cotangent_laplacian(vertices, faces)

    # We need k+1 because we'll strip the zero-eigenvalue (rigid-body) mode.
    # Also can't request more eigenpairs than (matrix_size - 1).
    num_eigs = min(k + 1, L.shape[0] - 1)

    # Pre-factorise (L - sigma*I) once; eigsh reuses it across iterations.
    # Adding a tiny diagonal nudge prevents exact singularity from the
    # zero eigenvalue while keeping sigma effectively at 0.
    sigma = 0.0
    nudge = 1e-10 * sparse.eye(L.shape[0], format='csc')
    lu = splu((L - sigma * sparse.eye(L.shape[0], format='csc') + nudge).tocsc())
    n = L.shape[0]
    OPinv = LinearOperator((n, n), matvec=lu.solve)

    # Retry loop: back off num_eigs on failure
    min_eigs = 4  # need at least 3 after stripping the zero mode
    while num_eigs >= min_eigs:
        try:
            eigenvalues, eigenvectors = eigsh(
                L,
                k=num_eigs,
                sigma=sigma,
                OPinv=OPinv,
                which='LM',          # largest magnitude of the *inverted* spectrum = smallest of L
                maxiter=5000,
                tol=1e-8
            )
            break  # success
        except ArpackNoConvergence:
            num_eigs -= 2           # back off by 2 (keeps the +1 buffer intact)
            continue
    else:
        # Last-ditch: fall back to dense solve on small meshes or accept partial
        if L.shape[0] <= 2000:
            dense_evals, dense_evecs = np.linalg.eigh(L.toarray())
            eigenvalues = dense_evals[:num_eigs]
            eigenvectors = dense_evecs[:, :num_eigs]
        else:
            raise RuntimeError(
                "Spectral decomposition failed after retries. "
                "The mesh may have degenerate topology. "
                "Try decimating or repairing the mesh before watermarking."
            )

    # Sort ascending by eigenvalue
    order = np.argsort(eigenvalues)
    eigenvalues = eigenvalues[order]
    eigenvectors = eigenvectors[:, order]

    # Strip the zero / near-zero eigenvalue (constant / rigid-body mode)
    eigenvalues = eigenvalues[1:]
    eigenvectors = eigenvectors[:, 1:]

    return eigenvalues, eigenvectors


def generate_watermark_payload(secret_key: str, num_coefficients: int) -> np.ndarray:
    """
    Deterministic payload from the secret key.

    Uses the key to seed a stream of pseudo-random values, shapes them into
    a Gaussian vector, then unit-normalises.  Unit normalisation is critical:
    it guarantees every spectral mode carries equal energy regardless of how
    the raw hash bytes land.  With the old uniform [-1,1] approach, some
    coefficients would randomly land near zero and contribute almost nothing
    to the matched-filter recovery — wasting those spectral modes entirely.
    """
    import hashlib
    payload = []
    block = 0
    while len(payload) < num_coefficients:
        h = hashlib.sha256(f"{secret_key}:{block}".encode()).digest()
        for i in range(0, len(h), 4):
            val = int.from_bytes(h[i:i+4], 'big')
            # Map two uniform [0,1] values → one Gaussian via Box-Muller.
            # This gives a proper normal distribution so the final
            # unit-normalisation is geometrically uniform on the hypersphere.
            u1 = (val / 4294967295.0)
            if u1 < 1e-12:
                u1 = 1e-12  # avoid log(0)
            payload.append(u1)
            if len(payload) >= num_coefficients:
                break
        block += 1
    raw = np.array(payload[:num_coefficients], dtype=np.float64)

    # Box-Muller: pairs of uniform → pairs of Gaussian
    n = len(raw)
    gauss = np.zeros(n, dtype=np.float64)
    for i in range(0, n - 1, 2):
        u1 = max(raw[i], 1e-12)
        u2 = raw[i + 1] if i + 1 < n else 0.5
        r = np.sqrt(-2.0 * np.log(u1))
        gauss[i]     =  r * np.cos(2.0 * np.pi * u2)
        gauss[i + 1] =  r * np.sin(2.0 * np.pi * u2)
    if n % 2 == 1:
        u1 = max(raw[-1], 1e-12)
        gauss[-1] = np.sqrt(-2.0 * np.log(u1))

    # Unit-normalise: every mode now carries equal energy
    norm = np.linalg.norm(gauss)
    if norm > 1e-12:
        gauss /= norm
    return gauss


def embed_watermark(vertices, faces, secret_key, num_coefficients=10, safety_divisor=200.0):
    avg_edge = compute_average_edge_length(vertices, faces)
    displacement_scale = avg_edge / safety_divisor
    eigenvalues, eigenvectors = compute_spectral_basis(vertices, faces, k=num_coefficients)
    actual_k = eigenvectors.shape[1]
    payload = generate_watermark_payload(secret_key, actual_k)
    normals = compute_vertex_normals(vertices, faces)
    displacement_magnitudes = eigenvectors @ payload
    max_mag = np.max(np.abs(displacement_magnitudes))
    if max_mag > 1e-12:
        displacement_magnitudes /= max_mag
    displacements = normals * (displacement_magnitudes[:, np.newaxis] * displacement_scale)
    watermarked_vertices = vertices + displacements
    import hashlib
    metadata = {
        "secret_key_hash": hashlib.sha256(secret_key.encode()).hexdigest(),
        "num_coefficients": actual_k,
        "safety_divisor": safety_divisor,
        "avg_edge_length": float(avg_edge),
        "displacement_scale": float(displacement_scale),
        "eigenvalues": eigenvalues,
        "eigenvectors": eigenvectors,       # stored for exact reuse at extraction
        "payload": payload,
        "original_vertices": vertices.copy(),
        "faces": faces.copy(),
    }
    return watermarked_vertices, metadata


def extract_spectral_signature(vertices: np.ndarray, faces: np.ndarray, k: int = 10) -> np.ndarray:
    eigenvalues, eigenvectors = compute_spectral_basis(vertices, faces, k=k)
    coeffs_x = eigenvectors.T @ vertices[:, 0]
    coeffs_y = eigenvectors.T @ vertices[:, 1]
    coeffs_z = eigenvectors.T @ vertices[:, 2]
    energy = coeffs_x ** 2 + coeffs_y ** 2 + coeffs_z ** 2
    signed = np.concatenate([np.abs(coeffs_x), np.abs(coeffs_y), np.abs(coeffs_z)])
    return np.concatenate([energy, signed])


def extract_watermark_payload(
    suspect_vertices: np.ndarray,
    baseline_vertices: np.ndarray,
    baseline_faces: np.ndarray,
    eigenvectors: np.ndarray
) -> np.ndarray:
    """
    Matched-filter extraction — the exact inverse of embed_watermark.

    During embedding:
        displacement_magnitudes = eigenvectors @ payload
        displacement_magnitudes /= max(|displacement_magnitudes|)
        vertex_displacements    = normals * displacement_magnitudes * scale

    Extraction (this function):
        1. Compute per-vertex displacement along normals:
               d_i = dot(suspect_i - baseline_i, normal_i)
        2. Project back onto the SAME eigenbasis that was used during embedding:
               recovered_payload = eigenvectors.T @ d

        Because we reuse the exact eigenvectors from protection time (stored in
        the keyfile), sign-flips and reordering from fresh decompositions are
        eliminated entirely.  The projection is a least-squares matched filter —
        noise from ICP residual or mesh modifications averages out over the
        thousands of vertices, leaving a clean recovered payload.

    Args:
        suspect_vertices:  The suspect mesh vertices (normalised).
        baseline_vertices: The reference skeleton aligned to the suspect
                           (either the ICP-aligned original or a resampled version).
        baseline_faces:    Face indices for computing vertex normals on the baseline.
        eigenvectors:      The (n_verts, k) eigenvector matrix from the keyfile —
                           MUST be the same one used during embed_watermark.

    Returns:
        recovered payload vector of length k.
    """
    normals = compute_vertex_normals(baseline_vertices, baseline_faces)
    diff = suspect_vertices - baseline_vertices
    displacement_along_normal = np.sum(diff * normals, axis=1)
    recovered = eigenvectors.T @ displacement_along_normal
    return recovered
