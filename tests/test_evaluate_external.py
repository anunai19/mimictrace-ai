import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from models.evaluate_external import (
    EXPECTED_FEATURE_NAMES,
    EXPECTED_MODEL_SHA256,
    ExternalEvaluationError,
    _url_keys,
    _assert_model_integrity,
    _validate_output_path,
    evaluate_external_frame,
    load_external_csv,
    load_verified_model,
    run_external_evaluation,
    validate_label_manifest
)
from detection.url_analyzer import analyze_url


MODEL_CUTOFF = "2026-11-15T23:33:46+05:30"
LABEL_MANIFEST = {
    "source": "synthetic-source",
    "snapshot_id": "synthetic-v1",
    "label_mapping": {
        "phishing": {
            "target": "phishing",
            "basis": "verified_phishing"
        },
        "benign": {
            "target": "legitimate",
            "basis": "independent_verification"
        }
    }
}


class FixedPredictionModel:

    def __init__(self, predictions):
        self.predictions = predictions
        self.feature_columns = None

    def predict(self, features):
        self.feature_columns = list(features.columns)
        return self.predictions[:len(features)]

    def fit(self, *_args, **_kwargs):
        raise AssertionError("The evaluation runner must not fit a model.")


def external_frame():
    return pd.DataFrame([
        {
            "url": "https://training.example.com/path",
            "label": "phishing",
            "source": "synthetic-source",
            "source_label": "phishing",
            "timestamp": "2023-10-01T12:00:00Z",
            "snapshot_id": "synthetic-v1"
        },
        {
            "url": "https://training.example.com/path",
            "label": "phishing",
            "source": "synthetic-source",
            "source_label": "phishing",
            "timestamp": "2023-10-02T12:00:00Z",
            "snapshot_id": "synthetic-v1"
        },
        {
            "url": "https://sub.training.example.com/another",
            "label": "phishing",
            "source": "synthetic-source",
            "source_label": "phishing",
            "timestamp": "2023-10-03T12:00:00Z",
            "snapshot_id": "synthetic-v1"
        },
        {
            "url": "https://safe-new.org/",
            "label": "legitimate",
            "source": "synthetic-source",
            "source_label": "benign",
            "timestamp": "2023-10-04T12:00:00Z",
            "snapshot_id": "synthetic-v1"
        },
        {
            "url": "https://phishing-new.net/login",
            "label": "phishing",
            "source": "synthetic-source",
            "source_label": "phishing",
            "timestamp": "2023-10-05T12:00:00Z",
            "snapshot_id": "synthetic-v1"
        }
    ])


def reference_frame():
    return pd.DataFrame({
        "URL": ["https://training.example.com/path"],
        "Domain": ["example.com"]
    })


class TestExternalEvaluation(unittest.TestCase):

    def test_loads_only_the_hash_pinned_saved_pipeline(self):
        artifact = load_verified_model()

        self.assertEqual(_assert_model_integrity(), EXPECTED_MODEL_SHA256)
        self.assertEqual(artifact["feature_names"], list(EXPECTED_FEATURE_NAMES))
        self.assertEqual(
            artifact["dataset"]["model_label_mapping"],
            {"0": "legitimate", "1": "phishing"}
        )

    def test_validates_urls_and_reports_url_and_domain_overlap(self):
        model = FixedPredictionModel([1, 0, 1])
        report = evaluate_external_frame(
            external_frame(),
            reference_frame(),
            model,
            MODEL_CUTOFF,
            LABEL_MANIFEST
        )

        self.assertEqual(model.feature_columns, list(EXPECTED_FEATURE_NAMES))
        self.assertEqual(
            report["input"]["duplicate_url_rows_removed"],
            1
        )
        self.assertEqual(
            report["overlap_checks"]["exact_url_overlap_rows_excluded"],
            1
        )
        self.assertEqual(
            report["overlap_checks"]["training_domain_overlap_rows"],
            2
        )
        self.assertEqual(
            report["cohorts"]["no_exact_url_overlap"]["sample_count"],
            3
        )
        self.assertEqual(
            report["cohorts"]["domain_overlapping_with_training"]
            ["sample_count"],
            1
        )
        self.assertEqual(
            report["cohorts"]["unseen_domains_vs_training"]["sample_count"],
            2
        )
        self.assertEqual(
            report["overlap_checks"]["domain_key_equivalence"]
            ["mismatched_training_rows"],
            0
        )
        self.assertEqual(
            report["cohorts"]["after_model_cutoff"]["sample_count"],
            0
        )
        self.assertIn(
            "not independently",
            report["input"]["timestamp_semantics"]
        )

    def test_rejects_non_http_urls(self):
        frame = external_frame().iloc[[0]].copy()
        frame.loc[frame.index[0], "url"] = "ftp://example.com/file"

        with self.assertRaisesRegex(ExternalEvaluationError, "absolute HTTP"):
            evaluate_external_frame(
                frame,
                reference_frame(),
                FixedPredictionModel([]),
                MODEL_CUTOFF,
                LABEL_MANIFEST
            )

    def test_rejects_missing_provenance_fields_and_invalid_labels(self):
        missing_field_frame = external_frame().drop(columns=["source_label"])
        with self.assertRaisesRegex(ExternalEvaluationError, "missing required"):
            evaluate_external_frame(
                missing_field_frame,
                reference_frame(),
                FixedPredictionModel([]),
                MODEL_CUTOFF,
                LABEL_MANIFEST
            )

        invalid_label_frame = external_frame().iloc[[0]].copy()
        invalid_label_frame.loc[invalid_label_frame.index[0], "label"] = "malware"
        with self.assertRaisesRegex(ExternalEvaluationError, "label must be"):
            evaluate_external_frame(
                invalid_label_frame,
                reference_frame(),
                FixedPredictionModel([]),
                MODEL_CUTOFF,
                LABEL_MANIFEST
            )

    def test_rejects_conflicting_labels_for_duplicate_urls(self):
        frame = external_frame().iloc[[0, 3]].copy()
        frame.loc[frame.index[1], "url"] = frame.iloc[0]["url"]

        with self.assertRaisesRegex(
            ExternalEvaluationError,
            "conflicting target labels"
        ):
            evaluate_external_frame(
                frame,
                reference_frame(),
                FixedPredictionModel([]),
                MODEL_CUTOFF,
                LABEL_MANIFEST
            )

    def test_rejects_cohort_with_only_training_url_overlaps(self):
        frame = external_frame().iloc[[0]].copy()

        with self.assertRaisesRegex(ExternalEvaluationError, "no independent"):
            evaluate_external_frame(
                frame,
                reference_frame(),
                FixedPredictionModel([]),
                MODEL_CUTOFF,
                LABEL_MANIFEST
            )

    def test_requires_timezone_for_cutoff_and_source_timestamps(self):
        with self.assertRaisesRegex(ExternalEvaluationError, "explicit timezone"):
            evaluate_external_frame(
                external_frame(),
                reference_frame(),
                FixedPredictionModel([1, 0, 1]),
                "2026-11-15T23:33:46",
                LABEL_MANIFEST
            )

        frame = external_frame().iloc[[0]].copy()
        frame.loc[frame.index[0], "timestamp"] = "2023-10-01T12:00:00"
        with self.assertRaisesRegex(ExternalEvaluationError, "explicit timezone"):
            evaluate_external_frame(
                frame,
                reference_frame(),
                FixedPredictionModel([]),
                MODEL_CUTOFF,
                LABEL_MANIFEST
            )

    def test_writes_a_separate_report_without_overwriting_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "synthetic.csv"
            reference_path = root / "reference.zip"
            manifest_path = root / "labels.json"
            report_path = root / "reports" / "result.json"
            external_frame().to_csv(csv_path, index=False)
            reference_path.write_bytes(b"synthetic reference placeholder")
            manifest_path.write_text(
                json.dumps(LABEL_MANIFEST),
                encoding="utf-8"
            )
            model = FixedPredictionModel([1, 0, 1])

            with patch(
                "models.evaluate_external.load_dataset_frame",
                return_value=reference_frame()
            ), patch(
                "models.evaluate_external.load_verified_model",
                return_value={
                    "model": model,
                    "split": {"strategy": "StratifiedGroupKFold"},
                    "evaluation": {
                        "positive_class": "phishing",
                        "precision": 0.9984,
                        "recall": 0.9857,
                        "f1_score": 0.9920,
                        "confusion_matrix": [[26939, 31], [287, 19817]]
                    }
                }
            ):
                written_path, report = run_external_evaluation(
                    dataset_path=csv_path,
                    label_manifest_path=manifest_path,
                    report_path=report_path,
                    model_cutoff=MODEL_CUTOFF,
                    reference_path=reference_path
                )

            saved_report = json.loads(written_path.read_text(encoding="utf-8"))
            self.assertEqual(written_path, report_path.resolve())
            self.assertEqual(saved_report["model"]["sha256"], EXPECTED_MODEL_SHA256)
            self.assertEqual(
                saved_report["input"]["sha256"],
                report["input"]["sha256"]
            )
            self.assertEqual(
                saved_report["label_mapping_manifest"]["sha256"],
                report["label_mapping_manifest"]["sha256"]
            )
            self.assertEqual(
                saved_report["comparison"]["original_uci_grouped_holdout"]
                ["metrics"]["confusion_matrix"],
                [[26939, 31], [287, 19817]]
            )
            self.assertTrue(csv_path.is_file())
            self.assertTrue(reference_path.is_file())
            self.assertEqual(model.feature_columns, list(EXPECTED_FEATURE_NAMES))

            with self.assertRaises(FileExistsError):
                run_external_evaluation(
                    dataset_path=csv_path,
                    label_manifest_path=manifest_path,
                    report_path=report_path,
                    model_cutoff=MODEL_CUTOFF,
                    reference_path=reference_path
                )

    def test_refuses_to_use_model_path_for_report(self):
        with self.assertRaisesRegex(ExternalEvaluationError, "must be separate"):
            _validate_output_path(
                Path(__file__).resolve().parents[1]
                / "models"
                / "phishing_url_model.joblib",
                "external.csv",
                "reference.zip",
                "manifest.json"
            )

    def test_feature_values_match_the_existing_url_analyzer(self):
        url = "https://example.com/login?id=123"
        _, _, _, actual = _url_keys(url)
        expected = analyze_url(url)["features"]

        self.assertEqual(tuple(actual), EXPECTED_FEATURE_NAMES)
        self.assertEqual(actual, expected)

    def test_url_canonicalization_handles_idna_dots_ports_and_escapes(self):
        first = _url_keys("https://BÜCHER.example.:443/a%7eb%2f")[0]
        second = _url_keys("https://xn--bcher-kva.example/a~b%2F")[0]

        self.assertEqual(first, second)
        with self.assertRaisesRegex(ExternalEvaluationError, "percent-encoding"):
            _url_keys("https://example.com/%GG")

    def test_manifest_rejects_ambiguous_or_nondetection_label_mappings(self):
        invalid_mappings = [
            {
                "phishing": {"target": "phishing", "basis": "vendor_flag"},
                "benign": {"target": "legitimate", "basis": "independent_verification"}
            },
            {
                "phishing": {"target": "phishing", "basis": "verified_phishing"},
                "undetected": {"target": "legitimate", "basis": "independent_verification"}
            },
            {
                "phishing": {"target": "phishing", "basis": "verified_phishing"},
                "benign": {"target": "legitimate", "basis": "vendor_non_detection"}
            }
        ]
        for mapping in invalid_mappings:
            manifest = dict(LABEL_MANIFEST, label_mapping=mapping)
            with self.subTest(mapping=mapping):
                with self.assertRaises(ExternalEvaluationError):
                    validate_label_manifest(manifest)

    def test_manifest_must_match_source_labels_and_targets(self):
        frame = external_frame().iloc[[3]].copy()
        frame.loc[frame.index[0], "source_label"] = "phishing"

        with self.assertRaisesRegex(ExternalEvaluationError, "disagrees"):
            evaluate_external_frame(
                frame,
                reference_frame(),
                FixedPredictionModel([0]),
                MODEL_CUTOFF,
                LABEL_MANIFEST
            )

    def test_timezone_offsets_and_cutoff_boundary_are_compared_in_utc(self):
        frame = external_frame().iloc[[3, 4]].copy().reset_index(drop=True)
        frame.loc[0, "timestamp"] = "2023-10-04T17:30:00+05:30"
        frame.loc[1, "timestamp"] = "2023-10-04T12:00:01Z"
        report = evaluate_external_frame(
            frame,
            reference_frame(),
            FixedPredictionModel([0, 1]),
            "2023-10-04T12:00:00Z",
            LABEL_MANIFEST
        )

        self.assertEqual(report["input"]["source_timestamp_after_cutoff_count"], 1)
        self.assertEqual(
            report["cohorts"]["after_model_cutoff"]["sample_count"],
            1
        )

    def test_reference_domain_key_mismatches_are_reported(self):
        reference = pd.DataFrame({
            "URL": ["https://training.example.com/path"],
            "Domain": ["training.example.com"]
        })
        report = evaluate_external_frame(
            external_frame(),
            reference,
            FixedPredictionModel([1, 0, 1]),
            MODEL_CUTOFF,
            LABEL_MANIFEST
        )

        equivalence = report["overlap_checks"]["domain_key_equivalence"]
        self.assertFalse(equivalence["exactly_equivalent"])
        self.assertEqual(equivalence["mismatched_training_rows"], 1)
        self.assertEqual(
            report["overlap_checks"]
            ["training_domain_overlap_rows_excluding_exact_url"],
            1
        )

    def test_dataset_row_and_byte_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "oversized.csv"
            csv_path.write_text("url,label\nhttps://a.example,1\n", encoding="utf-8")
            with patch("models.evaluate_external.MAX_EXTERNAL_ROWS", 0):
                with self.assertRaisesRegex(ExternalEvaluationError, "row limit"):
                    load_external_csv(csv_path)
            with patch("models.evaluate_external.MAX_EXTERNAL_BYTES", 1):
                with self.assertRaisesRegex(ExternalEvaluationError, "byte limit"):
                    load_external_csv(csv_path)

    def test_hash_mismatch_stops_model_loading(self):
        with patch("models.evaluate_external._sha256", return_value="0" * 64):
            with self.assertRaisesRegex(ExternalEvaluationError, "SHA-256"):
                _assert_model_integrity()

    def test_rejects_input_reference_and_report_path_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "dataset.csv"
            reference = root / "reference.zip"
            manifest = root / "manifest.json"
            report = root / "report.json"
            with self.assertRaisesRegex(ExternalEvaluationError, "separate files"):
                _validate_output_path(report, dataset, dataset, manifest)

            for collision in (dataset, reference, manifest):
                with self.subTest(collision=collision):
                    with self.assertRaisesRegex(
                        ExternalEvaluationError,
                        "must be separate"
                    ):
                        _validate_output_path(
                            collision,
                            dataset,
                            reference,
                            manifest
                        )


if __name__ == "__main__":
    unittest.main()
