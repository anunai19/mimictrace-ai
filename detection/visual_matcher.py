import math
import re
from typing import Dict, Tuple

import numpy as np
from PIL import Image

HASH_REGEX = re.compile(r"^[0-9a-fA-F]{16}$")
PHASH_SIDE = 32
PHASH_SUB_SIDE = 8
DHASH_WIDTH = 9
DHASH_HEIGHT = 8


def _get_dct_matrix(n: int = 32) -> np.ndarray:
    """Precompute orthogonal DCT-II matrix of shape (n, n)."""
    matrix = np.zeros((n, n), dtype=np.float64)
    alpha_0 = math.sqrt(1.0 / n)
    alpha_k = math.sqrt(2.0 / n)
    for u in range(n):
        alpha = alpha_0 if u == 0 else alpha_k
        for x in range(n):
            matrix[u, x] = alpha * math.cos((math.pi * (2 * x + 1) * u) / (2.0 * n))
    return matrix


_DCT_32 = _get_dct_matrix(PHASH_SIDE)


def _pack_bits_to_hex(bits: np.ndarray) -> str:
    """Pack an array of 64 boolean bits into a 16-character lowercase hex string."""
    if len(bits) != 64:
        raise ValueError("Bit array must contain exactly 64 elements.")
    hex_chars = []
    for i in range(0, 64, 4):
        nibble = (
            (int(bits[i]) << 3)
            | (int(bits[i + 1]) << 2)
            | (int(bits[i + 2]) << 1)
            | int(bits[i + 3])
        )
        hex_chars.append(f"{nibble:x}")
    return "".join(hex_chars)


def compute_phash_64(image: Image.Image) -> str:
    """
    Compute a deterministic 64-bit DCT perceptual hash (pHash).

    1. Convert image to grayscale (mode 'L').
    2. Resample to 32x32 using LANCZOS.
    3. Compute orthogonal 2D DCT-II: C = D * I * D^T.
    4. Extract top-left 8x8 low-frequency matrix (64 coefficients).
    5. Compute AC median M over the 63 AC coefficients (excluding DC at (0, 0)).
    6. Evaluate all 64 coefficients in row-major order: bit is 1 if coeff > M, else 0.
       Ties (coeff == M) evaluate strictly to 0.
    7. Pack into a 16-character lowercase hexadecimal string.
    """
    gray = image.convert("L")
    resized = gray.resize((PHASH_SIDE, PHASH_SIDE), Image.Resampling.LANCZOS)
    pixels = np.asarray(resized, dtype=np.float64)

    # 2D DCT-II: D * I * D^T
    dct_2d = _DCT_32 @ pixels @ _DCT_32.T

    # Suppress floating-point noise below numerical threshold
    dct_2d = np.where(np.abs(dct_2d) < 1e-9, 0.0, dct_2d)

    # Extract 8x8 low-frequency submatrix
    low_freq = dct_2d[:PHASH_SUB_SIDE, :PHASH_SUB_SIDE]

    # Flatten in row-major order
    coeffs = low_freq.flatten()

    # 63 AC coefficients (excluding index 0 which is DC)
    ac_coeffs = coeffs[1:]
    median = float(np.median(ac_coeffs))

    # All 64 positions evaluated strictly: coeff > median
    bits = coeffs > median
    return _pack_bits_to_hex(bits)


def compute_dhash_64(image: Image.Image) -> str:
    """
    Compute a deterministic 64-bit gradient difference hash (dHash).

    1. Convert image to grayscale (mode 'L').
    2. Resample to 9 columns x 8 rows using LANCZOS.
    3. For each row, compare adjacent horizontal pixels: bit is 1 if P[r, c] > P[r, c+1], else 0.
    4. Pack into a 16-character lowercase hexadecimal string.
    """
    gray = image.convert("L")
    resized = gray.resize((DHASH_WIDTH, DHASH_HEIGHT), Image.Resampling.LANCZOS)
    pixels = np.asarray(resized, dtype=np.float64)

    # Pixels shape is (8, 9): 8 rows, 9 columns
    # Difference between adjacent columns: pixels[:, :-1] > pixels[:, 1:]
    diff = pixels[:, :-1] > pixels[:, 1:]
    bits = diff.flatten()
    return _pack_bits_to_hex(bits)


def compute_image_hashes(image: Image.Image) -> Tuple[str, str]:
    """Extract both 64-bit pHash and dHash from an active in-memory Pillow image."""
    return compute_phash_64(image), compute_dhash_64(image)


def hamming_distance(hash1: str, hash2: str) -> int:
    """Calculate popcount Hamming distance between two 16-character hex hashes."""
    if not isinstance(hash1, str) or not HASH_REGEX.match(hash1):
        raise ValueError(f"Invalid 16-character hex hash: {hash1!r}")
    if not isinstance(hash2, str) or not HASH_REGEX.match(hash2):
        raise ValueError(f"Invalid 16-character hex hash: {hash2!r}")
    val1 = int(hash1, 16)
    val2 = int(hash2, 16)
    return bin(val1 ^ val2).count("1")


def evaluate_hash_distance(
    query_phash: str,
    query_dhash: str,
    target_phash: str,
    target_dhash: str,
) -> Dict[str, int]:
    """Calculate pHash and dHash distances between query and target hashes."""
    return {
        "phash_distance": hamming_distance(query_phash, target_phash),
        "dhash_distance": hamming_distance(query_dhash, target_dhash),
    }
