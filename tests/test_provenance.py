import hashlib
import json
import tempfile
import unittest
import uuid
from datetime import datetime
from pathlib import Path

from models.provenance import (
    ProvenanceError,
    build_manifest,
    create_run_id,
    utc_timestamp,
    validate_manifest,
    verify_artifact_hash,
    write_manifest_exclusive
)


FEATURE_NAMES = ["url_length", "hostname_length"]
TEST_TIMESTAMPS = {
    "run_started_at_utc": "2026-11-16T08:00:00.000000Z",
    "model_fit_started_at_utc": "2026-11-16T08:00:01.000000Z",
    "model_fit_completed_at_utc": "2026-11-16T08:00:02.000000Z",
    "run_completed_at_utc": "2026-11-16T08:00:03.000000Z"
}


def build_test_manifest(model_path, dataset_hash):
    file_hashes = {
        "models/train_model.py": "a" * 64,
        "models/model_utils.py": "b" * 64
    }
    source_manifest = hashlib.sha256(
        json.dumps(
            file_hashes,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    return build_manifest(
        run_id=model_path.parent.name,
        timestamps=TEST_TIMESTAMPS,
        model_path=model_path,
        dataset_metadata={
            "name": "Synthetic test dataset",
            "id": "test",
            "source": "test://fixture",
            "license": "test",
            "retrieved_date": "2026-11-16",
            "archive_sha256": dataset_hash,
            "version": dataset_hash
        },
        dataset_sha256=dataset_hash,
        feature_names=FEATURE_NAMES,
        model_configuration={
            "type": "sklearn.pipeline.Pipeline",
            "steps": [
                {
                    "name": "scaler",
                    "type": "sklearn.preprocessing.StandardScaler",
                    "parameters": {}
                }
            ],
            "baseline": {
                "type": "sklearn.dummy.DummyClassifier",
                "parameters": {}
            }
        },
        preprocessing={
            "feature_extractor": "test.feature_extractor",
            "feature_extractor_source_sha256": "c" * 64,
            "feature_order": FEATURE_NAMES,
            "scaler": {"type": "StandardScaler"}
        },
        split_metadata={
            "strategy": "StratifiedGroupKFold",
            "group_field": "Domain",
            "n_splits": 2,
            "fold": 0,
            "random_state": 42,
            "shuffle": True,
            "train_rows": 2,
            "test_rows": 2,
            "overlap_checks": {
                "url_overlap_count": 0,
                "domain_overlap_count": 0
            }
        },
        model_metrics={
            "positive_class": "phishing",
            "precision": 1.0,
            "recall": 1.0,
            "f1_score": 1.0,
            "confusion_matrix": [[1, 0], [0, 1]]
        },
        baseline_metrics={
            "positive_class": "phishing",
            "precision": 0.5,
            "recall": 0.5,
            "f1_score": 0.5,
            "confusion_matrix": [[1, 1], [1, 1]]
        },
        source_metadata={
            "git_commit": None,
            "working_tree": "unavailable",
            "file_hashes": file_hashes,
            "source_manifest_sha256": source_manifest
        },
        environment={
            "python_version": "3.test",
            "python_implementation": "CPython",
            "platform": "test",
            "packages": {
                "joblib": "1.test",
                "numpy": "2.test",
                "pandas": "3.test",
                "scikit-learn": "1.test"
            }
        }
    )


class TestProvenance(unittest.TestCase):

    def test_run_ids_are_unique_canonical_uuid4_values(self):
        first = create_run_id()
        second = create_run_id()

        self.assertNotEqual(first, second)
        self.assertEqual(uuid.UUID(first).version, 4)
        self.assertEqual(str(uuid.UUID(first)), first)

    def test_clock_timestamp_is_utc_and_z_suffixed(self):
        timestamp = utc_timestamp()

        self.assertTrue(timestamp.endswith("Z"))
        parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00")
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_manifest_marks_computer_clock_as_unattested(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / create_run_id()
            run_dir.mkdir()
            model_path = run_dir / "model.joblib"
            model_path.write_bytes(b"synthetic model")
            dataset_hash = hashlib.sha256(b"dataset").hexdigest()
            manifest = build_test_manifest(model_path, dataset_hash)

            validate_manifest(manifest)
            self.assertEqual(
                manifest["timestamps"]["trust_status"],
                "observed_unattested"
            )
            self.assertEqual(
                manifest["timestamps"]["source"],
                "computer_clock"
            )

    def test_manifest_rejects_unattested_or_non_utc_timestamp_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / create_run_id()
            run_dir.mkdir()
            model_path = run_dir / "model.joblib"
            model_path.write_bytes(b"synthetic model")
            dataset_hash = hashlib.sha256(b"dataset").hexdigest()

            unmarked = build_test_manifest(model_path, dataset_hash)
            unmarked["timestamps"]["trust_status"] = "attested"
            with self.assertRaisesRegex(ProvenanceError, "observed_unattested"):
                validate_manifest(unmarked)

            non_utc = build_test_manifest(model_path, dataset_hash)
            non_utc["timestamps"]["run_started_at_utc"] = (
                "2026-11-16T08:00:00+01:00"
            )
            with self.assertRaisesRegex(ProvenanceError, "ending in Z"):
                validate_manifest(non_utc)

    def test_manifest_rejects_non_chronological_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / create_run_id()
            run_dir.mkdir()
            model_path = run_dir / "model.joblib"
            model_path.write_bytes(b"synthetic model")
            dataset_hash = hashlib.sha256(b"dataset").hexdigest()
            manifest = build_test_manifest(model_path, dataset_hash)
            manifest["timestamps"]["model_fit_started_at_utc"] = (
                "2026-11-16T07:59:59.000000Z"
            )

            with self.assertRaisesRegex(ProvenanceError, "chronological"):
                validate_manifest(manifest)

    def test_manifest_and_model_hash_are_written_and_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / create_run_id()
            run_dir.mkdir()
            model_path = run_dir / "model.joblib"
            manifest_path = run_dir / "provenance.json"
            model_path.write_bytes(b"synthetic model")
            dataset_hash = hashlib.sha256(b"dataset").hexdigest()
            manifest = build_test_manifest(model_path, dataset_hash)

            write_manifest_exclusive(manifest_path, manifest, model_path)

            saved_manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            validate_manifest(saved_manifest)
            self.assertEqual(
                verify_artifact_hash(
                    model_path,
                    saved_manifest["artifact"]["sha256"]
                ),
                hashlib.sha256(b"synthetic model").hexdigest()
            )

    def test_existing_manifest_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / create_run_id()
            run_dir.mkdir()
            model_path = run_dir / "model.joblib"
            manifest_path = run_dir / "provenance.json"
            original_manifest = b"existing manifest"
            model_path.write_bytes(b"synthetic model")
            manifest_path.write_bytes(original_manifest)
            dataset_hash = hashlib.sha256(b"dataset").hexdigest()
            manifest = build_test_manifest(model_path, dataset_hash)

            with self.assertRaises(FileExistsError):
                write_manifest_exclusive(manifest_path, manifest, model_path)

            self.assertEqual(manifest_path.read_bytes(), original_manifest)

    def test_model_hash_mismatch_prevents_manifest_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / create_run_id()
            run_dir.mkdir()
            model_path = run_dir / "model.joblib"
            manifest_path = run_dir / "provenance.json"
            model_path.write_bytes(b"original model")
            dataset_hash = hashlib.sha256(b"dataset").hexdigest()
            manifest = build_test_manifest(model_path, dataset_hash)
            model_path.write_bytes(b"changed model")

            with self.assertRaisesRegex(ProvenanceError, "SHA-256"):
                write_manifest_exclusive(manifest_path, manifest, model_path)

            self.assertFalse(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
