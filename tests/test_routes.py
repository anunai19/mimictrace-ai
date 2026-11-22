import io
import threading
import unittest
from unittest.mock import patch

from app import create_app
from detection.evidence import EvidenceRecord
from app.routes import _analyze_html_url, _read_logo_upload
from detection.html_fetcher import HTMLFetchResult
from detection.visual_analyzer import LogoImageLimitError, MAX_LOGO_IMAGE_BYTES
from models.predict_model import ModelPredictionError, ModelUnavailableError
from werkzeug.datastructures import FileStorage, MultiDict

from PIL import Image


def _png_bytes(size=(16, 12)):
    image = Image.new("RGB", size, (20, 40, 60))
    output = io.BytesIO()
    image.save(output, format="PNG")
    image.close()
    return output.getvalue()


class TestAnalyzeRoute(unittest.TestCase):

    def setUp(self):
        self.client = create_app().test_client()

    def assert_bad_request(self, response):
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertFalse(body["success"])
        self.assertTrue(body["error"])

    def test_html_http_input_is_unavailable_without_parsing(self):
        with patch(
            "app.routes.fetch_html",
            return_value=HTMLFetchResult("unavailable", "https_required"),
        ), patch("app.routes.analyze_html_document") as html_analyzer:
            record = _analyze_html_url("http://example.com/")

        self.assertEqual(record.status, "unavailable")
        self.assertEqual(
            record.observation["availability"],
            "https_required",
        )
        self.assertTrue(any("HTTPS" in item for item in record.uncertainty))
        html_analyzer.assert_not_called()

    def test_unsupported_html_response_type_is_unavailable(self):
        with patch(
            "app.routes.fetch_html",
            return_value=HTMLFetchResult("error", "unsupported_content_type"),
        ), patch("app.routes.analyze_html_document") as html_analyzer:
            record = _analyze_html_url("https://example.com/")

        self.assertEqual(record.status, "unavailable")
        self.assertEqual(
            record.observation["availability"],
            "unsupported_content_type",
        )
        html_analyzer.assert_not_called()

    def test_valid_url_preserves_response_and_features(self):
        prediction = {
            "status": "available",
            "label": "phishing",
            "is_phishing": True,
            "disclaimer": "Estimate only."
        }
        with patch(
            "app.routes.predict_url_features",
            return_value=prediction
        ):
            response = self.client.post(
                "/api/analyze",
                json={"url": "https://example.com/login"}
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(
            set(body),
            {"success", "message", "analysis"}
        )
        self.assertTrue(body["success"])
        self.assertEqual(
            body["message"],
            "URL features extracted successfully."
        )
        self.assertEqual(
            body["analysis"]["normalized_url"],
            "https://example.com/login"
        )
        self.assertEqual(body["analysis"]["hostname"], "example.com")
        self.assertEqual(
            body["analysis"]["features"]["uses_https"],
            1
        )
        self.assertEqual(
            body["analysis"]["features"]["suspicious_keyword_count"],
            1
        )
        self.assertEqual(body["analysis"]["prediction"], prediction)

    def test_legitimate_prediction_is_distinguished(self):
        prediction = {
            "status": "available",
            "label": "legitimate",
            "is_phishing": False,
            "disclaimer": "Estimate only."
        }
        with patch(
            "app.routes.predict_url_features",
            return_value=prediction
        ):
            response = self.client.post(
                "/api/analyze",
                json={"url": "https://example.com"}
            )

        self.assertTrue(response.get_json()["success"])
        self.assertEqual(
            response.get_json()["analysis"]["prediction"]["label"],
            "legitimate"
        )

    def test_missing_model_keeps_features_and_marks_prediction_unavailable(self):
        with patch(
            "app.routes.predict_url_features",
            side_effect=ModelUnavailableError("missing artifact")
        ):
            response = self.client.post(
                "/api/analyze",
                json={"url": "https://example.com/login"}
            )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["success"])
        self.assertIn("features", body["analysis"])
        self.assertEqual(
            body["analysis"]["prediction"],
            {
                "status": "unavailable",
                "error": "The prediction model is unavailable."
            }
        )

    def test_prediction_error_keeps_features_and_marks_prediction_unavailable(self):
        with patch(
            "app.routes.predict_url_features",
            side_effect=ModelPredictionError("prediction failed")
        ):
            response = self.client.post(
                "/api/analyze",
                json={"url": "https://example.com/login"}
            )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["success"])
        self.assertIn("features", body["analysis"])
        self.assertEqual(
            body["analysis"]["prediction"]["status"],
            "unavailable"
        )

    def test_malformed_json_returns_bad_request(self):
        response = self.client.post(
            "/api/analyze",
            data='{"url":',
            content_type="application/json"
        )

        self.assert_bad_request(response)

    def test_non_json_request_returns_bad_request(self):
        response = self.client.post(
            "/api/analyze",
            data="url=https://example.com",
            content_type="text/plain"
        )

        self.assert_bad_request(response)

    def test_non_object_json_returns_bad_request(self):
        response = self.client.post(
            "/api/analyze",
            json=["https://example.com"]
        )

        self.assert_bad_request(response)

    def test_missing_url_returns_bad_request(self):
        response = self.client.post("/api/analyze", json={})

        self.assert_bad_request(response)

    def test_non_string_url_returns_bad_request(self):
        for value in (None, 42, ["https://example.com"]):
            with self.subTest(value=value):
                response = self.client.post(
                    "/api/analyze",
                    json={"url": value}
                )

                self.assert_bad_request(response)

    def test_empty_url_returns_bad_request(self):
        for value in ("", "   "):
            with self.subTest(value=value):
                response = self.client.post(
                    "/api/analyze",
                    json={"url": value}
                )

                self.assert_bad_request(response)

    def test_deeper_analysis_returns_structured_evidence(self):
        dns_records = {
            record_type: EvidenceRecord(
                source=f"dns.{record_type.lower()}",
                observation={"record_type": record_type},
                status="unavailable",
                uncertainty=["No live lookup in this test."],
            )
            for record_type in ("A", "AAAA", "MX", "NS", "TXT")
        }
        domain_record = EvidenceRecord(
            source="domain.whois",
            observation={"availability": "registration_data_unavailable"},
            status="unavailable",
            uncertainty=["Registration data may be unavailable."],
        )
        tls_record = EvidenceRecord(
            source="tls.certificate",
            observation={"availability": "timeout"},
            status="error",
            uncertainty=["TLS timed out."],
        )
        brand_record = EvidenceRecord(
            source="brand.impersonation",
            observation={"matches": []},
            status="observed",
            uncertainty=["Similarity does not prove impersonation."],
        )
        html_record = EvidenceRecord(
            source="html.static",
            observation={"availability": "available", "indicators": []},
            status="observed",
            uncertainty=["Static content only."],
        )
        with patch("app.routes.lookup_dns", return_value=dns_records) as dns_lookup, \
             patch(
                 "app.routes.fetch_html",
                 return_value=HTMLFetchResult(
                     "observed",
                     "available",
                     b"<html></html>",
                     "https://example.com/",
                     0,
                 ),
             ) as html_fetch, \
             patch(
                 "app.routes.analyze_html_document",
                 return_value=html_record,
             ) as html_analyzer, \
             patch(
                 "app.routes.lookup_domain_registration",
                 return_value=domain_record,
             ) as domain_lookup, \
             patch(
                 "app.routes.analyze_tls_certificate",
                 return_value=tls_record,
             ) as tls_analysis, \
             patch(
                 "app.routes.analyze_brand_impersonation",
                 return_value=brand_record,
             ) as brand_analysis:
            response = self.client.post(
                "/api/analyze/deeper",
                json={"url": "https://example.com"},
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("success", body)
        self.assertIn("message", body)
        self.assertIn("evidence", body)
        # risk_assessment is an optional additional key added by Stage 7 evidence fusion
        self.assertTrue(body["success"])
        self.assertEqual(
            set(body["evidence"]),
            {
                "html",
                "dns",
                "domain",
                "tls",
                "brand",
                "visual",
                "relationships",
            },
        )
        self.assertEqual(set(body["evidence"]["dns"]), {"A", "AAAA", "MX", "NS", "TXT"})
        for record in (
            *body["evidence"]["dns"].values(),
            body["evidence"]["html"],
            body["evidence"]["domain"],
            body["evidence"]["tls"],
            body["evidence"]["brand"],
            body["evidence"]["visual"],
            body["evidence"]["relationships"],
        ):
            self.assertEqual(
                set(record),
                {"source", "observation", "status", "uncertainty"},
            )
        self.assertEqual(body["evidence"]["tls"]["status"], "error")
        self.assertEqual(body["evidence"]["visual"]["status"], "not_run")
        self.assertEqual(
            body["evidence"]["visual"]["observation"]["availability"],
            "no_image_uploaded",
        )
        self.assertEqual(
            body["evidence"]["relationships"]["source"],
            "relationship.graph",
        )
        self.assertEqual(
            body["evidence"]["relationships"]["status"],
            "unavailable",
        )
        dns_lookup.assert_called_once_with("https://example.com")
        domain_lookup.assert_called_once_with("https://example.com")
        tls_analysis.assert_called_once_with("https://example.com")
        brand_analysis.assert_called_once_with("https://example.com")
        html_fetch.assert_called_once_with("https://example.com")
        html_analyzer.assert_called_once_with(
            b"<html></html>",
            "https://example.com",
            final_url="https://example.com/",
            redirect_count=0,
        )

    def test_valid_multipart_request_preprocesses_one_logo_crop(self):
        dns_records = {
            record_type: EvidenceRecord(
                source=f"dns.{record_type.lower()}",
                observation={},
                status="unavailable",
                uncertainty=["Mocked DNS evidence."],
            )
            for record_type in ("A", "AAAA", "MX", "NS", "TXT")
        }
        with patch("app.routes.fetch_html", return_value=HTMLFetchResult(
            "unavailable",
            "https_required",
        )), patch("app.routes.lookup_dns", return_value=dns_records), patch(
            "app.routes.lookup_domain_registration",
            return_value=EvidenceRecord(
                "domain.whois", {}, "unavailable", ["Mocked WHOIS evidence."]
            ),
        ), patch(
            "app.routes.analyze_tls_certificate",
            return_value=EvidenceRecord(
                "tls.certificate", {}, "unavailable", ["Mocked TLS evidence."]
            ),
        ), patch(
            "app.routes.analyze_brand_impersonation",
            return_value=EvidenceRecord(
                "brand.impersonation", {"matches": []}, "observed",
                ["URL matching only."],
            ),
        ), patch(
            "app.routes.analyze_relationship_graph",
            return_value=EvidenceRecord(
                "relationship.graph", {}, "unavailable", ["Mocked graph."]
            ),
        ):
            response = self.client.post(
                "/api/analyze/deeper",
                data={
                    "url": "https://example.com",
                    "logo_crop": (
                        io.BytesIO(_png_bytes()),
                        "logo.png",
                        "image/png",
                    ),
                },
            )

        self.assertEqual(response.status_code, 200)
        visual = response.get_json()["evidence"]["visual"]
        self.assertEqual(visual["source"], "visual.logo_crop")
        self.assertEqual(visual["status"], "unavailable")
        self.assertEqual(
            visual["observation"]["availability"],
            "empty_catalog",
        )
        self.assertNotIn("matches", visual["observation"])
        self.assertNotIn("similarity_score", str(visual))

    def test_invalid_multipart_image_returns_sanitized_bad_request_before_analysis(self):
        with patch("app.routes.fetch_html") as html_fetch, patch(
            "app.routes.lookup_dns"
        ) as dns_lookup, patch(
            "app.routes.lookup_domain_registration"
        ) as domain_lookup, patch(
            "app.routes.analyze_tls_certificate"
        ) as tls_analysis, patch(
            "app.routes.analyze_brand_impersonation"
        ) as brand_analysis:
            response = self.client.post(
                "/api/analyze/deeper",
                data={
                    "url": "https://example.com",
                    "logo_crop": (
                        io.BytesIO(b"not an image"),
                        "C:\\private\\secret.png",
                        "image/png",
                    ),
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(
            body["error"],
            "The upload must be a valid static PNG or JPEG logo crop.",
        )
        self.assertNotIn("secret", str(body))
        html_fetch.assert_not_called()
        dns_lookup.assert_not_called()
        domain_lookup.assert_not_called()
        tls_analysis.assert_not_called()
        brand_analysis.assert_not_called()

    def test_more_than_one_uploaded_image_is_rejected(self):
        response = self.client.post(
            "/api/analyze/deeper",
            data=MultiDict([
                ("url", "https://example.com"),
                ("logo_crop", (io.BytesIO(_png_bytes()), "one.png", "image/png")),
                ("logo_crop", (io.BytesIO(_png_bytes()), "two.png", "image/png")),
            ]),
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "Upload exactly one logo crop.",
        )

    def test_oversized_request_returns_json_413(self):
        self.client.application.config["MAX_CONTENT_LENGTH"] = 128

        response = self.client.post(
            "/api/analyze/deeper",
            data={
                "url": "https://example.com",
                "logo_crop": (io.BytesIO(b"x" * 512), "logo.png", "image/png"),
            },
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json(),
            {
                "success": False,
                "error": "Request body exceeds the allowed size.",
            },
        )

    def test_image_over_compressed_limit_returns_413(self):
        with patch(
            "app.routes._read_logo_upload",
            side_effect=LogoImageLimitError(),
        ), patch("app.routes.fetch_html") as html_fetch:
            response = self.client.post(
                "/api/analyze/deeper",
                data={
                    "url": "https://example.com",
                    "logo_crop": (
                        io.BytesIO(_png_bytes()),
                        "large.png",
                        "image/png",
                    ),
                },
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json()["error"],
            "The uploaded logo crop exceeds the allowed size or dimensions.",
        )
        html_fetch.assert_not_called()

    def test_logo_upload_stream_is_closed_after_reading(self):
        stream = io.BytesIO(b"small upload")
        upload = FileStorage(
            stream=stream,
            filename="logo.png",
            content_type="image/png",
        )

        self.assertEqual(_read_logo_upload(upload), b"small upload")
        self.assertTrue(stream.closed)

    def test_oversized_logo_upload_stream_is_closed(self):
        stream = io.BytesIO(b"x" * (MAX_LOGO_IMAGE_BYTES + 1))
        upload = FileStorage(
            stream=stream,
            filename="logo.png",
            content_type="image/png",
        )

        with self.assertRaises(LogoImageLimitError):
            _read_logo_upload(upload)
        self.assertTrue(stream.closed)

    def test_unexpected_visual_error_does_not_expose_internal_details(self):
        dns_records = {
            record_type: EvidenceRecord(
                source=f"dns.{record_type.lower()}",
                observation={},
                status="unavailable",
                uncertainty=["Mocked DNS evidence."],
            )
            for record_type in ("A", "AAAA", "MX", "NS", "TXT")
        }
        with patch(
            "app.routes.analyze_logo_crop",
            side_effect=RuntimeError("C:\\private\\decoder\\traceback"),
        ), patch("app.routes.fetch_html", return_value=HTMLFetchResult(
            "unavailable",
            "https_required",
        )), patch("app.routes.lookup_dns", return_value=dns_records), patch(
            "app.routes.lookup_domain_registration",
            return_value=EvidenceRecord(
                "domain.whois", {}, "unavailable", ["Mocked WHOIS evidence."]
            ),
        ), patch(
            "app.routes.analyze_tls_certificate",
            return_value=EvidenceRecord(
                "tls.certificate", {}, "unavailable", ["Mocked TLS evidence."]
            ),
        ), patch(
            "app.routes.analyze_brand_impersonation",
            return_value=EvidenceRecord(
                "brand.impersonation", {"matches": []}, "observed",
                ["URL matching only."],
            ),
        ):
            response = self.client.post(
                "/api/analyze/deeper",
                data={
                    "url": "https://example.com",
                    "logo_crop": (
                        io.BytesIO(_png_bytes()),
                        "logo.png",
                        "image/png",
                    ),
                },
            )

        self.assertEqual(response.status_code, 200)
        visual = response.get_json()["evidence"]["visual"]
        self.assertEqual(visual["status"], "error")
        self.assertEqual(
            visual["observation"]["availability"],
            "processing_failed",
        )
        self.assertNotIn("private", str(response.get_json()))
        self.assertNotIn("traceback", str(response.get_json()))

    def test_deeper_analysis_sanitizes_module_failures_and_releases_slot(self):
        slots = threading.BoundedSemaphore(value=1)
        with patch("app.routes._DEEPER_ANALYSIS_SLOTS", slots), \
             patch(
                 "app.routes.lookup_dns",
                 side_effect=RuntimeError("sensitive resolver detail"),
             ), patch(
                 "app.routes.lookup_domain_registration",
                 side_effect=RuntimeError("sensitive WHOIS detail"),
             ), patch(
                 "app.routes.analyze_tls_certificate",
                 side_effect=RuntimeError("sensitive TLS detail"),
             ), patch(
                 "app.routes.analyze_brand_impersonation",
                 side_effect=RuntimeError("sensitive brand detail"),
             ), patch(
                 "app.routes.analyze_relationship_graph",
                 side_effect=RuntimeError("sensitive graph detail"),
             ), patch(
                 "app.routes.fetch_html",
                 side_effect=RuntimeError("sensitive HTML fetch detail"),
             ):
            response = self.client.post(
                "/api/analyze/deeper",
                json={"url": "https://example.com"},
            )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(all(
            record["status"] == "error"
            for record in body["evidence"]["dns"].values()
        ))
        self.assertEqual(body["evidence"]["domain"]["status"], "error")
        self.assertEqual(body["evidence"]["tls"]["status"], "error")
        self.assertEqual(body["evidence"]["brand"]["status"], "error")
        self.assertEqual(body["evidence"]["html"]["status"], "error")
        self.assertEqual(body["evidence"]["relationships"]["status"], "error")
        self.assertNotIn("sensitive", str(body))
        self.assertTrue(slots.acquire(blocking=False))
        slots.release()

    def test_deeper_analysis_returns_503_when_all_slots_are_busy(self):
        slots = threading.BoundedSemaphore(value=1)
        self.assertTrue(slots.acquire(blocking=False))
        with patch("app.routes._DEEPER_ANALYSIS_SLOTS", slots), \
             patch("app.routes.lookup_dns") as dns_lookup, \
             patch("app.routes.lookup_domain_registration") as domain_lookup, \
             patch("app.routes.analyze_tls_certificate") as tls_analysis, \
             patch("app.routes.analyze_brand_impersonation") as brand_analysis, \
             patch("app.routes.analyze_relationship_graph") as relationship_analysis, \
             patch("app.routes.fetch_html") as html_fetch:
            response = self.client.post(
                "/api/analyze/deeper",
                json={"url": "https://example.com"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json(),
            {
                "success": False,
                "error": "Deeper analysis is busy. Please try again shortly.",
            },
        )
        dns_lookup.assert_not_called()
        domain_lookup.assert_not_called()
        tls_analysis.assert_not_called()
        brand_analysis.assert_not_called()
        relationship_analysis.assert_not_called()
        html_fetch.assert_not_called()
        slots.release()

    def test_deeper_analysis_invalid_input_does_not_call_modules(self):
        with patch("app.routes.lookup_dns") as dns_lookup, \
             patch("app.routes.lookup_domain_registration") as domain_lookup, \
             patch("app.routes.analyze_tls_certificate") as tls_analysis, \
             patch("app.routes.analyze_brand_impersonation") as brand_analysis, \
             patch("app.routes.analyze_relationship_graph") as relationship_analysis, \
             patch("app.routes.fetch_html") as html_fetch:
            response = self.client.post(
                "/api/analyze/deeper",
                json={"url": "https://"},
            )

        self.assert_bad_request(response)
        dns_lookup.assert_not_called()
        domain_lookup.assert_not_called()
        tls_analysis.assert_not_called()
        brand_analysis.assert_not_called()
        relationship_analysis.assert_not_called()
        html_fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
