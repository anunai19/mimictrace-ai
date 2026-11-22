import concurrent.futures
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from app import create_app
from detection.visual_catalog import (
    CatalogInstance,
    CatalogState,
    get_catalog,
    load_catalog,
    reset_cached_catalog,
)
from detection.visual_matcher import compute_image_hashes


def _make_png_bytes(size=(32, 32), color=(255, 0, 0)):
    buf = io.BytesIO()
    img = Image.new("RGB", size, color)
    img.save(buf, format="PNG")
    img.close()
    return buf.getvalue()


def _make_manifest(
    mode="hash_only",
    version="1.0.0-uncalibrated",
    calibration_status="uncalibrated",
    brands=None,
):
    if brands is None:
        brands = {
            "google": {
                "brand_name": "Google",
                "canonical_domain": "google.com",
                "variants": [
                    {
                        "variant_id": "google_g_icon",
                        "precomputed_hashes": {
                            "phash_64": "0123456789abcdef",
                            "dhash_64": "fedcba9876543210",
                        },
                    }
                ],
            }
        }
    return {
        "catalog_version": version,
        "mode": mode,
        "calibration_status": calibration_status,
        "brands": brands,
    }


class TestVisualCatalog(unittest.TestCase):

    def setUp(self):
        reset_cached_catalog()

    def tearDown(self):
        reset_cached_catalog()

    def test_default_manifest_loads_as_unavailable_empty_catalog(self):
        catalog = get_catalog()
        self.assertFalse(catalog.is_available)
        self.assertEqual(catalog.state, CatalogState.UNAVAILABLE)
        self.assertEqual(catalog.failure_reason, "empty_catalog")
        self.assertEqual(catalog.configured_brands_count, 0)
        self.assertEqual(catalog.brands, {})

    def test_valid_hash_only_catalog_loads_successfully(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_g_icon",
                            "precomputed_hashes": {
                                "phash_64": "0123456789abcdef",
                                "dhash_64": "fedcba9876543210",
                            },
                            "aspect_ratio": 1.0,
                        }
                    ],
                },
                "apple": {
                    "brand_name": "Apple",
                    "canonical_domain": "apple.com",
                    "variants": [
                        {
                            "variant_id": "apple_monochrome",
                            "precomputed_hashes": {
                                "phash_64": "aabbccddeeff0011",
                                "dhash_64": "2233445566778899",
                            },
                        }
                    ],
                },
            }
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="hash_only", brands=brands)),
                encoding="utf-8",
            )

            catalog = load_catalog(manifest_path)
            self.assertTrue(catalog.is_available)
            self.assertEqual(catalog.state, CatalogState.READY)
            self.assertIsNone(catalog.failure_reason)
            self.assertEqual(catalog.mode, "hash_only")
            self.assertEqual(catalog.configured_brands_count, 2)

            google = catalog.get_brand("google")
            self.assertIsNotNone(google)
            self.assertEqual(google.brand_name, "Google")
            self.assertEqual(google.canonical_domain, "google.com")
            self.assertEqual(len(google.variants), 1)
            self.assertEqual(google.variants[0].variant_id, "google_g_icon")
            self.assertEqual(google.variants[0].phash_64, "0123456789abcdef")
            self.assertEqual(google.variants[0].aspect_ratio, 1.0)

            all_variants = catalog.get_all_variants()
            self.assertEqual(len(all_variants), 2)

    def test_valid_asset_backed_catalog_verifies_sha256_and_perceptual_hashes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            assets_dir = tmp_path / "assets"
            assets_dir.mkdir()
            asset_file = assets_dir / "google.png"

            png_bytes = _make_png_bytes(size=(48, 48), color=(100, 150, 200))
            asset_file.write_bytes(png_bytes)
            computed_sha = hashlib.sha256(png_bytes).hexdigest()

            with Image.open(io.BytesIO(png_bytes)) as img:
                expected_phash, expected_dhash = compute_image_hashes(img)

            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_icon",
                            "asset_path": "assets/google.png",
                            "sha256": computed_sha,
                            "precomputed_hashes": {
                                "phash_64": expected_phash,
                                "dhash_64": expected_dhash,
                            },
                        }
                    ],
                }
            }
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="asset_backed", brands=brands)),
                encoding="utf-8",
            )

            catalog = load_catalog(manifest_path)
            self.assertTrue(catalog.is_available)
            self.assertEqual(catalog.mode, "asset_backed")
            self.assertEqual(catalog.configured_brands_count, 1)

    def test_asset_backed_catalog_rejects_hash_mismatch_even_with_valid_sha256(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            assets_dir = tmp_path / "assets"
            assets_dir.mkdir()
            asset_file = assets_dir / "google.png"

            png_bytes = _make_png_bytes(size=(32, 32), color=(200, 100, 50))
            asset_file.write_bytes(png_bytes)
            computed_sha = hashlib.sha256(png_bytes).hexdigest()

            # Declare a different valid hex hash that doesn't match the actual image
            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_icon",
                            "asset_path": "assets/google.png",
                            "sha256": computed_sha,
                            "precomputed_hashes": {
                                "phash_64": "0000000000000000",
                                "dhash_64": "ffffffffffffffff",
                            },
                        }
                    ],
                }
            }
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="asset_backed", brands=brands)),
                encoding="utf-8",
            )

            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "hash_asset_mismatch")

    def test_missing_manifest_returns_unavailable(self):
        catalog = load_catalog(Path("/non/existent/manifest.json"))
        self.assertFalse(catalog.is_available)
        self.assertEqual(catalog.failure_reason, "manifest_missing")

    def test_malformed_json_returns_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_path.write_text("{not valid json", encoding="utf-8")
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "invalid_manifest")

    def test_placeholder_hashes_are_rejected(self):
        for placeholder in (
            "NOT_REAL_HASH_01",
            "not_real_hash_01",
            "placeholder_hash",
            "12345",  # too short
            "0123456789abcdef0",  # too long (17 chars)
            "0123456789abcdeg",  # invalid hex 'g'
        ):
            with self.subTest(placeholder=placeholder):
                with tempfile.TemporaryDirectory() as tmpdir:
                    manifest_path = Path(tmpdir) / "manifest.json"
                    brands = {
                        "google": {
                            "brand_name": "Google",
                            "canonical_domain": "google.com",
                            "variants": [
                                {
                                    "variant_id": "google_g_icon",
                                    "precomputed_hashes": {
                                        "phash_64": placeholder,
                                        "dhash_64": "fedcba9876543210",
                                    },
                                }
                            ],
                        }
                    }
                    manifest_path.write_text(
                        json.dumps(_make_manifest(brands=brands)),
                        encoding="utf-8",
                    )
                    catalog = load_catalog(manifest_path)
                    self.assertFalse(catalog.is_available)
                    self.assertEqual(catalog.failure_reason, "invalid_hash_data")

    def test_missing_asset_in_asset_backed_mode_returns_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            manifest_path = tmp_path / "manifest.json"
            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_icon",
                            "asset_path": "assets/missing.png",
                            "sha256": "0" * 64,
                            "precomputed_hashes": {
                                "phash_64": "0123456789abcdef",
                                "dhash_64": "fedcba9876543210",
                            },
                        }
                    ],
                }
            }
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="asset_backed", brands=brands)),
                encoding="utf-8",
            )
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "asset_missing")

    def test_sha256_mismatch_in_asset_backed_mode_returns_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            assets_dir = tmp_path / "assets"
            assets_dir.mkdir()
            asset_file = assets_dir / "google.png"
            asset_file.write_bytes(b"some content")

            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_icon",
                            "asset_path": "assets/google.png",
                            "sha256": "1" * 64,  # mismatched checksum
                            "precomputed_hashes": {
                                "phash_64": "0123456789abcdef",
                                "dhash_64": "fedcba9876543210",
                            },
                        }
                    ],
                }
            }
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="asset_backed", brands=brands)),
                encoding="utf-8",
            )
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "integrity_mismatch")

    def test_corrupt_image_asset_returns_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            assets_dir = tmp_path / "assets"
            assets_dir.mkdir()
            asset_file = assets_dir / "google.png"
            not_an_image = b"not a png image data"
            asset_file.write_bytes(not_an_image)
            computed_sha = hashlib.sha256(not_an_image).hexdigest()

            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_icon",
                            "asset_path": "assets/google.png",
                            "sha256": computed_sha,
                            "precomputed_hashes": {
                                "phash_64": "0123456789abcdef",
                                "dhash_64": "fedcba9876543210",
                            },
                        }
                    ],
                }
            }
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="asset_backed", brands=brands)),
                encoding="utf-8",
            )
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "corrupt_asset")

    def test_oversized_image_asset_returns_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            assets_dir = tmp_path / "assets"
            assets_dir.mkdir()
            asset_file = assets_dir / "oversized.png"
            # 2 MiB + 1 byte
            asset_file.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            computed_sha = hashlib.sha256(asset_file.read_bytes()).hexdigest()

            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_icon",
                            "asset_path": "assets/oversized.png",
                            "sha256": computed_sha,
                            "precomputed_hashes": {
                                "phash_64": "0123456789abcdef",
                                "dhash_64": "fedcba9876543210",
                            },
                        }
                    ],
                }
            }
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="asset_backed", brands=brands)),
                encoding="utf-8",
            )
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "asset_limit_exceeded")

    def test_path_traversal_in_asset_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            manifest_path = tmp_path / "manifest.json"
            brands = {
                "google": {
                    "brand_name": "Google",
                    "canonical_domain": "google.com",
                    "variants": [
                        {
                            "variant_id": "google_icon",
                            "asset_path": "../../etc/passwd",
                            "sha256": "0" * 64,
                            "precomputed_hashes": {
                                "phash_64": "0123456789abcdef",
                                "dhash_64": "fedcba9876543210",
                            },
                        }
                    ],
                }
            }
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="asset_backed", brands=brands)),
                encoding="utf-8",
            )
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "path_traversal_detected")

    def test_unsupported_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(_make_manifest(mode="hybrid_invalid")),
                encoding="utf-8",
            )
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "unsupported_mode")

    def test_unsupported_calibration_status_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(_make_manifest(calibration_status="arbitrary")),
                encoding="utf-8",
            )
            catalog = load_catalog(manifest_path)
            self.assertFalse(catalog.is_available)
            self.assertEqual(catalog.failure_reason, "invalid_calibration_status")

    def test_lazy_caching_and_thread_safety(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(get_catalog) for _ in range(20)]
            results = [f.result() for f in futures]

        first_instance = results[0]
        for item in results[1:]:
            self.assertIs(item, first_instance)

    def test_flask_startup_independent_of_catalog(self):
        app = create_app()
        client = app.test_client()

        with patch("app.routes.analyze_url", return_value={"hostname": "example.com", "features": {}}), \
             patch("app.routes.predict_url_features", return_value={"status": "unavailable"}):
            response = client.post("/api/analyze", json={"url": "https://example.com"})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])


if __name__ == "__main__":
    unittest.main()
