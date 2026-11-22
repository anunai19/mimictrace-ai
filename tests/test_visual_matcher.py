import unittest

import numpy as np
from PIL import Image

from detection.visual_matcher import (
    _DCT_32,
    _pack_bits_to_hex,
    compute_dhash_64,
    compute_image_hashes,
    compute_phash_64,
    evaluate_hash_distance,
    hamming_distance,
)


class TestVisualMatcher(unittest.TestCase):

    def test_dct_matrix_is_orthogonal(self):
        # D * D^T must equal identity matrix of size 32
        identity = np.eye(32, dtype=np.float64)
        product = _DCT_32 @ _DCT_32.T
        np.testing.assert_allclose(product, identity, atol=1e-12)

    def test_pack_bits_to_hex(self):
        # 64 zeros -> 16 zeros
        self.assertEqual(_pack_bits_to_hex(np.zeros(64, dtype=bool)), "0" * 16)
        # 64 ones -> 16 f's
        self.assertEqual(_pack_bits_to_hex(np.ones(64, dtype=bool)), "f" * 16)
        # Single bit at index 0 -> '8' followed by 15 zeros
        bits = np.zeros(64, dtype=bool)
        bits[0] = True
        self.assertEqual(_pack_bits_to_hex(bits), "8" + "0" * 15)
        # Invalid bit array length raises ValueError
        with self.assertRaises(ValueError):
            _pack_bits_to_hex(np.zeros(63, dtype=bool))

    def test_phash_and_dhash_deterministic_format(self):
        # Arbitrary image must return exactly 16-character lowercase hex strings
        image = Image.new("RGB", (64, 64), (120, 150, 180))
        phash, dhash = compute_image_hashes(image)

        self.assertEqual(len(phash), 16)
        self.assertEqual(len(dhash), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in phash))
        self.assertTrue(all(c in "0123456789abcdef" for c in dhash))

        # Repeated calls on same image must produce bit-for-bit identical hashes
        phash2, dhash2 = compute_image_hashes(image)
        self.assertEqual(phash, phash2)
        self.assertEqual(dhash, dhash2)
        image.close()

    def test_synthetic_test_vector_solid_white(self):
        # Solid white: DC > 0, AC = 0, AC median = 0.
        # DC > 0 is True (bit 0 = 1). All AC > 0 is False (bits 1..63 = 0).
        # Expected pHash: '8000000000000000'.
        # Expected dHash: no gradient, all differences False -> '0000000000000000'.
        image = Image.new("RGB", (32, 32), (255, 255, 255))
        self.assertEqual(compute_phash_64(image), "8000000000000000")
        self.assertEqual(compute_dhash_64(image), "0000000000000000")
        image.close()

    def test_synthetic_test_vector_solid_black(self):
        # Solid black: DC = 0, AC = 0, AC median = 0.
        # All coefficients <= 0. All 64 bits are False.
        # Expected pHash: '0000000000000000'.
        # Expected dHash: no gradient -> '0000000000000000'.
        image = Image.new("RGB", (32, 32), (0, 0, 0))
        self.assertEqual(compute_phash_64(image), "0000000000000000")
        self.assertEqual(compute_dhash_64(image), "0000000000000000")
        image.close()

    def test_synthetic_test_vector_horizontal_gradient_dhash(self):
        # Left-to-right decreasing brightness (255 down to 0)
        # Every horizontal pair P[r, c] > P[r, c+1] is True (1).
        # Expected dHash: 64 ones -> 'ffffffffffffffff'.
        pixels = np.zeros((8, 9), dtype=np.uint8)
        for col in range(9):
            pixels[:, col] = 255 - col * 25
        image = Image.fromarray(pixels, mode="L")
        self.assertEqual(compute_dhash_64(image), "ffffffffffffffff")
        image.close()

        # Left-to-right increasing brightness (0 up to 255)
        # Every horizontal pair P[r, c] > P[r, c+1] is False (0).
        # Expected dHash: 64 zeros -> '0000000000000000'.
        pixels_rev = np.zeros((8, 9), dtype=np.uint8)
        for col in range(9):
            pixels_rev[:, col] = col * 25
        image_rev = Image.fromarray(pixels_rev, mode="L")
        self.assertEqual(compute_dhash_64(image_rev), "0000000000000000")
        image_rev.close()

    def test_matrix_orientation_sensitivity(self):
        # Vertical stripe vs Horizontal stripe must produce distinct hashes
        vertical_stripes = np.zeros((32, 32), dtype=np.uint8)
        vertical_stripes[:, :16] = 255
        img_v = Image.fromarray(vertical_stripes, mode="L")

        horizontal_stripes = np.zeros((32, 32), dtype=np.uint8)
        horizontal_stripes[:16, :] = 255
        img_h = Image.fromarray(horizontal_stripes, mode="L")

        phash_v, dhash_v = compute_image_hashes(img_v)
        phash_h, dhash_h = compute_image_hashes(img_h)

        self.assertNotEqual(phash_v, phash_h)
        self.assertNotEqual(dhash_v, dhash_h)
        img_v.close()
        img_h.close()

    def test_hamming_distance_boundaries(self):
        # Identical hashes -> 0
        self.assertEqual(
            hamming_distance("0123456789abcdef", "0123456789abcdef"),
            0,
        )
        # Completely inverted hashes -> 64
        self.assertEqual(
            hamming_distance("0000000000000000", "ffffffffffffffff"),
            64,
        )
        # Single bit differences
        self.assertEqual(
            hamming_distance("0000000000000001", "0000000000000000"),
            1,
        )
        self.assertEqual(
            hamming_distance("8000000000000000", "0000000000000000"),
            1,
        )
        # Case insensitive input
        self.assertEqual(
            hamming_distance("0123456789ABCDEF", "0123456789abcdef"),
            0,
        )

    def test_hamming_distance_validation_rejects_malformed_hashes(self):
        for bad in ("short", "0123456789abcdef0", "not_hex_string!!", 12345):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    hamming_distance("0123456789abcdef", bad)

    def test_evaluate_hash_distance(self):
        dist = evaluate_hash_distance(
            query_phash="8000000000000000",
            query_dhash="0000000000000000",
            target_phash="0000000000000000",
            target_dhash="ffffffffffffffff",
        )
        self.assertEqual(dist["phash_distance"], 1)
        self.assertEqual(dist["dhash_distance"], 64)


if __name__ == "__main__":
    unittest.main()
