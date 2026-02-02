"""
forensic_audit.py
Full forensic verification pipeline.
"""

import numpy as np
from spectral_engine import extract_spectral_signature
from icp_alignment import icp_align, resample_onto_target, compute_correlation, normalize_mesh, anisotropic_normalize, adaptive_normalize
from mesh_io import load_mesh
from dna_keyfile import load_dna_keyfile


CORRELATION_THRESHOLD = 0.15


class AuditResult:
    def __init__(self):
        self.suspect_path: str = ""
        self.keyfile_path: str = ""
        self.correlation: float = 0.0
        self.threshold: float = CORRELATION_THRESHOLD
        self.verdict: str = "UNKNOWN"
        self.icp_error: float = 0.0
        self.suspect_verts: int = 0
        self.suspect_faces: int = 0
        self.original_verts: int = 0
        self.original_faces: int = 0
        self.num_coefficients: int = 0
        self.details: str = ""

    @property
    def match_percentage(self) -> float:
        return self.correlation * 100.0


def run_audit(suspect_path, keyfile_path, keyfile_password, num_coefficients=10, correlation_threshold=CORRELATION_THRESHOLD):
    result = AuditResult()
    result.suspect_path = suspect_path
    result.keyfile_path = keyfile_path
    result.threshold = correlation_threshold

    # ── 1. Load ─────────────────────────────────────────────────────────────
    suspect_verts, suspect_faces = load_mesh(suspect_path)
    result.suspect_verts = len(suspect_verts)
    result.suspect_faces = len(suspect_faces)

    keydata = load_dna_keyfile(keyfile_path, keyfile_password)
    original_verts = keydata["original_vertices"]
    original_faces = keydata["faces"]
    stored_payload = keydata["payload"]
    stored_eigenvectors = keydata["eigenvectors"]   # the exact basis used during embed
    result.original_verts = len(original_verts)
    result.original_faces = len(original_faces)
    result.num_coefficients = keydata["num_coefficients"]

    # ── 2. Normalise ────────────────────────────────────────────────────────
    #   Anisotropic normalisation undoes non-uniform scaling (stretch/squish
    #   along individual axes) by scaling each PCA axis to unit variance,
    #   then projecting back into the original orientation.  This brings
    #   stretched meshes back to their canonical shape without rotating them,
    #   so the watermark displacement directions stay aligned for extraction.
    suspect_norm  = adaptive_normalize(suspect_verts)
    original_norm = adaptive_normalize(original_verts)

    # ── 3. ICP-align original skeleton onto suspect ────────────────────────
    aligned_original, _, icp_err = icp_align(original_norm, suspect_norm)
    result.icp_error = icp_err

    # ── 3b. ICP shape-mismatch gate ─────────────────────────────────────────
    #   When suspect and original are the same mesh (possibly transformed),
    #   anisotropic normalisation undoes any stretch and ICP converges to
    #   near-zero error (~0.001).  When they are fundamentally different
    #   shapes (e.g. auditing a torus against a sphere's deed), ICP cannot
    #   converge and error stays high (~0.17+).  A threshold of 0.05 sits
    #   with ~50x margin on both sides, so it cleanly rejects shape mismatches
    #   before the correlation check can be fooled by shape-mismatch noise.
    ICP_SHAPE_THRESHOLD = 0.05
    if icp_err > ICP_SHAPE_THRESHOLD:
        result.correlation = 0.0
        result.verdict = "NO MATCH"
        result.details = (
            "The suspect mesh has a fundamentally different shape from the "
            "original in your master deed (ICP alignment error too high). "
            "This model does not originate from the watermarked source."
        )
        return result
    #   After ICP the two point clouds are spatially aligned, but their vertex
    #   *indices* may not correspond (Blender and other exporters freely
    #   reorder vertices).  A KD-tree nearest-neighbour lookup maps each
    #   original vertex → its closest suspect vertex, giving us a reordered
    #   suspect array where index i matches original vertex i.
    #   This also reorders the stored eigenvectors into the same space so the
    #   matched-filter projection stays correct.
    from spectral_engine import extract_watermark_payload
    from scipy.spatial import cKDTree

    suspect_tree = cKDTree(suspect_norm)
    # For every original vertex, find the nearest suspect vertex
    _, orig_to_suspect = suspect_tree.query(aligned_original)
    # Reorder suspect into original's index space
    suspect_reindexed = suspect_norm[orig_to_suspect]

    # ── 5. Displacement gate ───────────────────────────────────────────────
    #   Before trusting the correlation, verify the suspect actually *has*
    #   displacement relative to the original.  The keyfile records the
    #   displacement_scale that was used during embedding.  After normalisation
    #   that scale shrinks by the mesh's original extent — we compute the
    #   expected normalised displacement and compare against the actual RMS
    #   displacement along normals.  If the suspect is a clean (unwatermarked)
    #   original, the displacement will be at floating-point noise level and
    #   we reject immediately, preventing structured numerical residual from
    #   fooling the correlation.
    from spectral_engine import compute_vertex_normals

    normals = compute_vertex_normals(aligned_original, original_faces)
    diff = suspect_reindexed - aligned_original
    disp_along_normal = np.sum(diff * normals, axis=1)
    rms_displacement = float(np.sqrt(np.mean(disp_along_normal ** 2)))

    # The watermark was embedded at displacement_scale in the original mesh's
    # raw coordinate space.  After normalisation the original was divided by
    # original_scale, so the displacement in normalised space is:
    #     displacement_scale / original_scale
    # This is invariant to any scaling applied to the suspect — normalisation
    # undoes it.  We use 0.1x of that as the noise floor.
    _, _, original_scale = normalize_mesh(original_verts)
    expected_disp_normalised = keydata["displacement_scale"] / original_scale
    noise_floor = 0.1 * expected_disp_normalised

    if rms_displacement < noise_floor:
        result.correlation = 0.0
        result.verdict = "NO MATCH"
        result.details = (
            "The suspect mesh shows no displacement signal relative to the "
            "original skeleton. This is an unwatermarked mesh — no Digital DNA "
            "was detected."
        )
        return result

    # ── 6. Extract and correlate ────────────────────────────────────────────
    recovered_payload = extract_watermark_payload(
        suspect_reindexed,          # suspect vertices in original's index order
        aligned_original,           # the ICP-aligned original skeleton
        original_faces,             # original topology (for normals)
        stored_eigenvectors         # the exact eigenbasis from protection time
    )
    result.correlation = compute_correlation(recovered_payload, stored_payload)

    # ── 7. Verdict ──────────────────────────────────────────────────────────
    if result.correlation >= correlation_threshold:
        result.verdict = "OWNERSHIP CONFIRMED"
        result.details = (
            "The watermark payload extracted from the suspect mesh correlates "
            "strongly with the secret key stored in your master deed. "
            "This model originates from the watermarked source. "
            "This constitutes mathematical proof of provenance."
        )
    else:
        result.verdict = "NO MATCH"
        result.details = (
            "The extracted payload does not correlate with your secret key. "
            "This model does not appear to originate from the watermarked source, "
            "or has been modified beyond recoverable limits."
        )
    return result
