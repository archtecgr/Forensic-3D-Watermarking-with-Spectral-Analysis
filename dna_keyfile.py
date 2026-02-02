"""
dna_keyfile.py
Encrypted .dna.npz keyfile creation, saving, and loading.
"""

import numpy as np
import hashlib
import os
import json


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=100000, dklen=32)


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    output = bytearray(len(data))
    block, pos = 0, 0
    while pos < len(data):
        block_key = hashlib.sha256(key + block.to_bytes(4, "big")).digest()
        chunk_len = min(32, len(data) - pos)
        for i in range(chunk_len):
            output[pos + i] = data[pos + i] ^ block_key[i]
        pos += chunk_len
        block += 1
    return bytes(output)


_xor_decrypt = _xor_encrypt  # XOR is self-inverse


def save_dna_keyfile(filepath: str, metadata: dict, password: str) -> None:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    config = {
        "secret_key_hash": metadata["secret_key_hash"],
        "num_coefficients": int(metadata["num_coefficients"]),
        "safety_divisor": float(metadata["safety_divisor"]),
        "avg_edge_length": float(metadata["avg_edge_length"]),
        "displacement_scale": float(metadata["displacement_scale"]),
    }
    encrypted_config = _xor_encrypt(json.dumps(config).encode(), key)
    encrypted_payload = _xor_encrypt(metadata["payload"].tobytes(), key)
    encrypted_eigenvalues = _xor_encrypt(metadata["eigenvalues"].tobytes(), key)
    encrypted_eigenvectors = _xor_encrypt(metadata["eigenvectors"].tobytes(), key)
    np.savez(
        filepath,
        salt=np.frombuffer(salt, dtype=np.uint8),
        encrypted_config=np.frombuffer(encrypted_config, dtype=np.uint8),
        encrypted_payload=np.frombuffer(encrypted_payload, dtype=np.uint8),
        encrypted_eigenvalues=np.frombuffer(encrypted_eigenvalues, dtype=np.uint8),
        encrypted_eigenvectors=np.frombuffer(encrypted_eigenvectors, dtype=np.uint8),
        payload_len=np.array([len(metadata["payload"])]),
        eigenvalues_len=np.array([len(metadata["eigenvalues"])]),
        eigenvectors_shape=np.array(metadata["eigenvectors"].shape),
        original_vertices=metadata["original_vertices"],
        faces=metadata["faces"],
    )


def load_dna_keyfile(filepath: str, password: str) -> dict:
    data = np.load(filepath, allow_pickle=False)
    salt = data["salt"].tobytes()
    key = _derive_key(password, salt)
    try:
        config = json.loads(_xor_decrypt(data["encrypted_config"].tobytes(), key).decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Decryption failed — incorrect password or corrupted keyfile.")
    payload_len = int(data["payload_len"][0])
    payload = np.frombuffer(_xor_decrypt(data["encrypted_payload"].tobytes(), key), dtype=np.float64)[:payload_len].copy()
    eigenvalues_len = int(data["eigenvalues_len"][0])
    eigenvalues = np.frombuffer(_xor_decrypt(data["encrypted_eigenvalues"].tobytes(), key), dtype=np.float64)[:eigenvalues_len].copy()
    evec_shape = tuple(data["eigenvectors_shape"])
    eigenvectors = np.frombuffer(
        _xor_decrypt(data["encrypted_eigenvectors"].tobytes(), key), dtype=np.float64
    )[:evec_shape[0] * evec_shape[1]].copy().reshape(evec_shape)
    return {
        "secret_key_hash": config["secret_key_hash"],
        "num_coefficients": config["num_coefficients"],
        "safety_divisor": config["safety_divisor"],
        "avg_edge_length": config["avg_edge_length"],
        "displacement_scale": config["displacement_scale"],
        "eigenvalues": eigenvalues,
        "eigenvectors": eigenvectors,
        "payload": payload,
        "original_vertices": data["original_vertices"],
        "faces": data["faces"],
    }
