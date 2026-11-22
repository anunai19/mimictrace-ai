import base64
import http.client
import io
import struct
import unittest
import zlib
from unittest.mock import MagicMock, patch

import dns.resolver
from PIL import Image
import requests

from detection.visual_analyzer import (
    MAX_ANALYSIS_DIMENSION,
    MAX_LOGO_IMAGE_BYTES,
    InvalidLogoImageError,
    LogoImageLimitError,
    analyze_logo_crop,
)
from detection.visual_catalog import CatalogInstance, CatalogState, VisualBrand, VisualVariant


def _image_bytes(
    image_format="PNG",
    size=(40, 20),
    mode="RGB",
    color=None,
    *,
    exif=None,
    save_all=False,
    append_images=(),
):
    color = color or ((10, 20, 30, 128) if mode == "RGBA" else (10, 20, 30))
    image = Image.new(mode, size, color)
    output = io.BytesIO()
    options = {}
    if exif is not None:
        options["exif"] = exif
    if save_all:
        options["save_all"] = True
        options["append_images"] = list(append_images)
    image.save(output, format=image_format, **options)
    image.close()
    return output.getvalue()


def _png_with_dimensions(width, height):
    data = bytearray(_image_bytes(size=(1, 1)))
    ihdr_data_start = 16
    ihdr_data_end = ihdr_data_start + 13
    data[ihdr_data_start:ihdr_data_start + 8] = struct.pack(">II", width, height)
    checksum = zlib.crc32(b"IHDR" + data[ihdr_data_start:ihdr_data_end])
    data[ihdr_data_end:ihdr_data_end + 4] = struct.pack(">I", checksum)
    return bytes(data)


class TestVisualAnalyzer(unittest.TestCase):

    def test_valid_png_with_baseline_empty_catalog_reports_unavailable_empty_catalog(self):
        record = analyze_logo_crop(
            _image_bytes(),
            filename="logo.png",
            content_type="image/png",
        )

        self.assertEqual(record.status, "unavailable")
        self.assertEqual(
            record.observation["availability"],
            "empty_catalog",
        )
        self.assertEqual(record.observation["decoded_format"], "PNG")
        self.assertEqual(record.observation["analysis_color_mode"], "RGB")
        self.assertEqual(record.observation["catalog_brands_configured"], 0)
        self.assertIsNone(record.observation["candidate_brand"])
        self.assertIsNone(record.observation["match_result"])
        self.assertEqual(record.observation["evaluations"], [])
        self.assertIn("query_phash", record.observation)
        self.assertIn("query_dhash", record.observation)
        self.assertEqual(len(record.observation["query_phash"]), 16)
        self.assertEqual(len(record.observation["query_dhash"]), 16)

    def test_valid_jpeg_is_preprocessed_and_hashed(self):
        record = analyze_logo_crop(
            _image_bytes("JPEG"),
            filename="logo.jpeg",
            content_type="image/jpeg",
        )

        self.assertEqual(record.status, "unavailable")
        self.assertEqual(record.observation["decoded_format"], "JPEG")
        self.assertEqual(len(record.observation["query_phash"]), 16)
        self.assertEqual(len(record.observation["query_dhash"]), 16)

    def test_active_uncalibrated_catalog_returns_observed_status_and_raw_distances(self):
        mock_brand = VisualBrand(
            brand_id="test_brand",
            brand_name="TestBrand",
            canonical_domain="testbrand.com",
            variants=(
                VisualVariant(
                    variant_id="test_icon",
                    phash_64="0000000000000000",
                    dhash_64="ffffffffffffffff",
                ),
            ),
        )
        mock_catalog = CatalogInstance(
            state=CatalogState.READY,
            failure_reason=None,
            mode="hash_only",
            version="1.0.0-uncalibrated",
            calibration_status="uncalibrated",
            brands={"test_brand": mock_brand},
        )

        with patch("detection.visual_analyzer.get_catalog", return_value=mock_catalog):
            record = analyze_logo_crop(
                _image_bytes(),
                filename="logo.png",
                content_type="image/png",
            )

        self.assertEqual(record.status, "observed")
        self.assertEqual(record.observation["availability"], "available")
        self.assertEqual(record.observation["calibration_state"], "uncalibrated")
        self.assertEqual(record.observation["catalog_brands_configured"], 1)
        self.assertIsNone(record.observation["candidate_brand"])
        self.assertIsNone(record.observation["reference_variant"])
        self.assertIsNone(record.observation["match_result"])
        self.assertEqual(len(record.observation["evaluations"]), 1)

        eval0 = record.observation["evaluations"][0]
        self.assertEqual(eval0["brand"], "TestBrand")
        self.assertEqual(eval0["canonical_domain"], "testbrand.com")
        self.assertEqual(eval0["variant_id"], "test_icon")
        self.assertIsInstance(eval0["phash_distance"], int)
        self.assertIsInstance(eval0["dhash_distance"], int)

        serialized = record.to_json()
        self.assertIn("uncalibrated experimental mode", serialized)
        self.assertIn("Visual similarity alone does not establish", serialized)
        self.assertNotIn("phishing", serialized.lower())

    def test_image_resource_cleanup_in_finally_on_hash_error(self):
        closed_images = []

        original_close = Image.Image.close

        def tracking_close(self):
            closed_images.append(self)
            return original_close(self)

        with patch.object(Image.Image, "close", side_effect=tracking_close, autospec=True):
            with patch("detection.visual_analyzer.compute_image_hashes", side_effect=ValueError("hash failure")):
                with self.assertRaises(InvalidLogoImageError):
                    analyze_logo_crop(_image_bytes())

        # Verify that close was called on the allocated image instances
        self.assertTrue(len(closed_images) >= 1)

    def test_invalid_image_bytes_are_rejected(self):
        with self.assertRaises(InvalidLogoImageError):
            analyze_logo_crop(b"not an image")

    def test_truncated_image_is_rejected(self):
        truncated = _image_bytes()[:-16]

        with self.assertRaises(InvalidLogoImageError):
            analyze_logo_crop(truncated)

    def test_unsupported_image_format_is_rejected(self):
        with self.assertRaises(InvalidLogoImageError):
            analyze_logo_crop(
                _image_bytes("GIF"),
                filename="logo.gif",
                content_type="image/gif",
            )

    def test_svg_is_rejected(self):
        with self.assertRaises(InvalidLogoImageError):
            analyze_logo_crop(
                b'<svg xmlns="http://www.w3.org/2000/svg"></svg>',
                filename="logo.svg",
                content_type="image/svg+xml",
            )

    def test_animated_png_is_rejected(self):
        second = Image.new("RGB", (4, 4), "blue")
        animated = _image_bytes(
            "PNG",
            (4, 4),
            save_all=True,
            append_images=(second,),
        )
        second.close()

        with self.assertRaises(InvalidLogoImageError):
            analyze_logo_crop(
                animated,
                filename="animated.png",
                content_type="image/png",
            )

    def test_mime_type_spoofing_is_rejected(self):
        with self.assertRaises(InvalidLogoImageError):
            analyze_logo_crop(
                _image_bytes(),
                filename="logo.png",
                content_type="image/jpeg",
            )

    def test_extension_spoofing_is_rejected(self):
        with self.assertRaises(InvalidLogoImageError):
            analyze_logo_crop(
                _image_bytes(),
                filename="logo.jpg",
                content_type="image/png",
            )

    def test_compressed_file_over_limit_is_rejected_before_decode(self):
        oversized = b"x" * (MAX_LOGO_IMAGE_BYTES + 1)
        with patch(
            "detection.visual_analyzer.Image.open",
            side_effect=AssertionError("Image decoder must not run"),
        ):
            with self.assertRaises(LogoImageLimitError):
                analyze_logo_crop(oversized)

    def test_width_or_height_over_limit_is_rejected(self):
        for size in ((4097, 1), (1, 4097)):
            with self.subTest(size=size):
                with self.assertRaises(LogoImageLimitError):
                    analyze_logo_crop(_png_with_dimensions(*size))

    def test_total_pixel_limit_is_rejected(self):
        with self.assertRaises(LogoImageLimitError):
            analyze_logo_crop(_png_with_dimensions(4000, 3001))

    def test_decompression_bomb_warning_is_rejected(self):
        with patch("detection.visual_analyzer.Image.MAX_IMAGE_PIXELS", 100):
            with self.assertRaises(LogoImageLimitError):
                analyze_logo_crop(_png_with_dimensions(20, 20))

    def test_decompression_bomb_error_is_rejected(self):
        with patch("detection.visual_analyzer.Image.MAX_IMAGE_PIXELS", 50):
            with self.assertRaises(LogoImageLimitError):
                analyze_logo_crop(_png_with_dimensions(11, 11))

    def test_exif_orientation_is_normalized_and_metadata_is_not_returned(self):
        exif = Image.Exif()
        exif[274] = 6
        exif[270] = "private image description"
        image_bytes = _image_bytes(
            "JPEG",
            size=(60, 30),
            exif=exif,
        )

        record = analyze_logo_crop(
            image_bytes,
            filename="logo.jpg",
            content_type="image/jpeg",
        )

        self.assertEqual(record.observation["normalized_width"], 30)
        self.assertEqual(record.observation["normalized_height"], 60)
        self.assertNotIn("private image description", record.to_json())

    def test_transparency_is_composited_to_rgb(self):
        record = analyze_logo_crop(
            _image_bytes("PNG", mode="RGBA"),
            filename="logo.png",
            content_type="image/png",
        )

        self.assertEqual(record.observation["analysis_color_mode"], "RGB")

    def test_large_valid_image_is_resized_with_aspect_ratio(self):
        record = analyze_logo_crop(
            _image_bytes("JPEG", size=(1024, 512)),
            filename="logo.jpg",
            content_type="image/jpeg",
        )

        width = record.observation["analysis_width"]
        height = record.observation["analysis_height"]
        self.assertLessEqual(max(width, height), MAX_ANALYSIS_DIMENSION)
        self.assertAlmostEqual(width / height, 2.0)

    def test_no_upload_returns_not_run(self):
        record = analyze_logo_crop()

        self.assertEqual(record.status, "not_run")
        self.assertEqual(record.observation["availability"], "no_image_uploaded")

    def test_evidence_contains_no_filename_path_metadata_or_image_bytes(self):
        image_bytes = _image_bytes("JPEG")
        filename = "C:\\private\\logo-secret.jpg"
        record = analyze_logo_crop(
            image_bytes,
            filename=filename,
            content_type="image/jpeg",
        )
        serialized = record.to_json()

        self.assertNotIn(filename, serialized)
        self.assertNotIn("private", serialized)
        self.assertNotIn(base64.b64encode(image_bytes).decode("ascii"), serialized)
        self.assertNotIn("exif", serialized.lower())
        self.assertNotIn("pixel", serialized.lower())

    def test_analyzer_makes_no_network_requests(self):
        with patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("DNS access"),
        ), patch(
            "socket.socket",
            side_effect=AssertionError("socket access"),
        ), patch(
            "dns.resolver.Resolver",
            side_effect=AssertionError("DNS access"),
        ), patch(
            "requests.get",
            side_effect=AssertionError("HTTP access"),
        ), patch(
            "requests.sessions.Session.request",
            side_effect=AssertionError("HTTP access"),
        ), patch(
            "http.client.HTTPConnection",
            side_effect=AssertionError("HTTP access"),
        ), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("HTTPS access"),
        ):
            record = analyze_logo_crop(_image_bytes())

        self.assertEqual(record.status, "unavailable")
        record.to_json()


if __name__ == "__main__":
    unittest.main()
