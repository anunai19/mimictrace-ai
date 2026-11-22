import hashlib
import json
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
import pandas as pd

from models.model_utils import (
    DEFAULT_DATASET_PATH,
    DEFAULT_MODEL_PATH,
    sha256_file
)
from models.train_model import (
    APPROVED_DATASET_SHA256,
    DEFAULT_TRAINING_RUNS_DIR,
    _is_reparse_point,
    _validate_run_directory,
    _validate_training_runs_path,
    main,
    train_baseline,
    validate_approved_dataset,
    validate_training_runs_dir
)


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "at_symbol_count",
    "digit_count",
    "uses_https",
    "uses_ip_address",
    "suspicious_keyword_count"
]


def make_training_fixture(dataset_path):
    features = pd.DataFrame(
        [
            {
                name: float((row + column) % 4)
                for column, name in enumerate(FEATURE_NAMES)
            }
            for row in range(12)
        ],
        columns=FEATURE_NAMES
    )
    labels = pd.Series([0, 1] * 6)
    groups = pd.Series([f"domain-{index}" for index in range(12)])
    urls = pd.Series([f"https://domain-{index}.example/path" for index in range(12)])
    dataset_hash = sha256_file(dataset_path)
    metadata = {
        "name": "Synthetic test dataset",
        "id": "test",
        "source": "test://fixture",
        "license": "test",
        "retrieved_date": "2026-11-16",
        "archive_sha256": dataset_hash,
        "version": dataset_hash,
        "model_label_mapping": {
            "0": "legitimate",
            "1": "phishing"
        }
    }
    return features, labels, groups, urls, metadata


class TestTrainModel(unittest.TestCase):

    def setUp(self):
        self.original_model_hash = (
            sha256_file(DEFAULT_MODEL_PATH)
            if DEFAULT_MODEL_PATH.is_file()
            else None
        )

    def assert_original_model_unchanged(self):
        if self.original_model_hash is not None:
            self.assertEqual(
                sha256_file(DEFAULT_MODEL_PATH),
                self.original_model_hash
            )

    def run_with_synthetic_data(self, dataset_path, runs_dir):
        fixture = make_training_fixture(dataset_path)
        train_indices = np.array([0, 1, 2, 3, 4, 5, 6, 7])
        test_indices = np.array([8, 9, 10, 11])
        with patch(
            "models.train_model.validate_approved_dataset",
            return_value=(dataset_path, fixture[4]["archive_sha256"])
        ), patch(
            "models.train_model.validate_training_runs_dir",
            return_value=runs_dir
        ), patch(
            "models.train_model.prepare_dataset",
            return_value=fixture
        ), patch(
            "models.train_model.domain_group_split",
            return_value=(train_indices, test_indices)
        ), patch(
            "models.train_model.check_split_overlap",
            return_value={
                "url_overlap_count": 0,
                "domain_overlap_count": 0
            }
        ):
            return train_baseline(dataset_path)

    def test_training_writes_new_model_and_provenance_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset_path = root / "synthetic-dataset.zip"
            dataset_path.write_bytes(b"synthetic dataset bytes")
            runs_dir = root / "training_runs"

            model_path, report = self.run_with_synthetic_data(
                dataset_path,
                runs_dir
            )

            run_dir = model_path.parent
            run_id = run_dir.name
            manifest_path = run_dir / "provenance.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(str(uuid.UUID(run_id)), run_id)
            self.assertEqual(uuid.UUID(run_id).version, 4)
            self.assertEqual(manifest["run_id"], run_id)
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(
                manifest["timestamps"]["trust_status"],
                "observed_unattested"
            )
            self.assertEqual(
                manifest["artifact"]["sha256"],
                hashlib.sha256(model_path.read_bytes()).hexdigest()
            )
            self.assertEqual(
                manifest["dataset"]["sha256"],
                hashlib.sha256(dataset_path.read_bytes()).hexdigest()
            )
            self.assertEqual(
                manifest["preprocessing"]["feature_names"],
                FEATURE_NAMES
            )
            self.assertEqual(
                manifest["preprocessing"]["feature_order"],
                FEATURE_NAMES
            )
            self.assertEqual(manifest["split"]["random_state"], 42)
            self.assertEqual(manifest["split"]["group_field"], "Domain")
            self.assertIn("logistic_regression", report["metrics"])
            self.assertTrue(model_path.is_file())
            self.assert_original_model_unchanged()

    def test_existing_run_directory_is_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            runs_dir = Path(directory) / "training_runs"
            run_id = str(uuid.uuid4())
            existing_run = runs_dir / run_id
            existing_run.mkdir(parents=True)
            sentinel = existing_run / "sentinel.txt"
            sentinel.write_text("keep", encoding="utf-8")

            with patch(
                "models.train_model.validate_approved_dataset",
                return_value=(Path(directory) / "unused.zip", "unused-hash")
            ), patch(
                "models.train_model.validate_training_runs_dir",
                return_value=runs_dir
            ), patch(
                "models.train_model.create_run_id",
                return_value=run_id
            ):
                with self.assertRaises(FileExistsError):
                    train_baseline(
                        dataset_path=Path(directory) / "unused.zip"
                    )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertFalse((existing_run / "provenance.json").exists())
            self.assert_original_model_unchanged()

    def test_training_failure_does_not_create_success_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset_path = root / "synthetic-dataset.zip"
            dataset_path.write_bytes(b"synthetic dataset bytes")
            runs_dir = root / "training_runs"
            fixture = make_training_fixture(dataset_path)
            train_indices = np.array([0, 1, 2, 3, 4, 5, 6, 7])
            test_indices = np.array([8, 9, 10, 11])

            with patch(
                "models.train_model.prepare_dataset",
                return_value=fixture
            ), patch(
                "models.train_model.validate_approved_dataset",
                return_value=(dataset_path, fixture[4]["archive_sha256"])
            ), patch(
                "models.train_model.validate_training_runs_dir",
                return_value=runs_dir
            ), patch(
                "models.train_model.domain_group_split",
                return_value=(train_indices, test_indices)
            ), patch(
                "models.train_model.check_split_overlap",
                return_value={
                    "url_overlap_count": 0,
                    "domain_overlap_count": 0
                }
            ), patch(
                "models.train_model.Pipeline.fit",
                side_effect=RuntimeError("synthetic fitting failure")
            ):
                with self.assertRaisesRegex(RuntimeError, "synthetic fitting"):
                    train_baseline(dataset_path)

            self.assertEqual(len(list(runs_dir.iterdir())), 1)
            run_dir = next(runs_dir.iterdir())
            self.assertFalse((run_dir / "provenance.json").exists())
            self.assertFalse((run_dir / DEFAULT_MODEL_PATH.name).exists())
            self.assert_original_model_unchanged()

    def test_approved_local_dataset_archive_is_accepted(self):
        resolved_path, dataset_hash = validate_approved_dataset(
            DEFAULT_DATASET_PATH
        )

        self.assertEqual(resolved_path, DEFAULT_DATASET_PATH.resolve())
        self.assertEqual(dataset_hash.upper(), APPROVED_DATASET_SHA256)

    def test_different_local_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            alternate_archive = Path(directory) / "other.zip"
            alternate_archive.write_bytes(b"not the approved archive")

            with self.assertRaisesRegex(ValueError, "Only the approved"):
                validate_approved_dataset(alternate_archive)

    def test_modified_archive_at_approved_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            modified_archive = Path(directory) / "dataset.zip"
            modified_archive.write_bytes(b"modified approved archive")

            with patch(
                "models.train_model.DEFAULT_DATASET_PATH",
                modified_archive
            ):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    validate_approved_dataset(modified_archive)

    def test_dataset_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset_directory = Path(directory) / "dataset"
            dataset_directory.mkdir()

            with patch(
                "models.train_model.DEFAULT_DATASET_PATH",
                dataset_directory
            ):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    validate_approved_dataset(dataset_directory)

    def test_remote_dataset_url_is_rejected_without_access(self):
        for dataset_path in (
            "https://example.invalid/data.zip",
            Path("https://example.invalid/data.zip")
        ):
            with self.subTest(dataset_path=dataset_path):
                with self.assertRaisesRegex(ValueError, "Remote dataset URLs"):
                    validate_approved_dataset(dataset_path)

    def test_arbitrary_training_output_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "approved directory"):
                validate_training_runs_dir(Path(directory) / "other-runs")

    def test_windows_reparse_point_attribute_is_detected(self):
        metadata = SimpleNamespace(
            st_mode=stat.S_IFDIR,
            st_file_attributes=0x400
        )
        with patch("models.train_model.Path.lstat", return_value=metadata):
            self.assertTrue(_is_reparse_point(Path("training_runs")))

    def test_reparse_output_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            redirected_root = root / "training_runs"
            try:
                redirected_root.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"Directory symlinks are unavailable: {error}")

            with self.assertRaisesRegex(ValueError, "reparse point"):
                _validate_training_runs_path(redirected_root, redirected_root)

    def test_reparse_run_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs_dir = root / "training_runs"
            runs_dir.mkdir()
            outside = root / "outside"
            outside.mkdir()
            redirected_run = runs_dir / str(uuid.uuid4())
            try:
                redirected_run.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"Directory symlinks are unavailable: {error}")

            with patch(
                "models.train_model.validate_training_runs_dir",
                return_value=runs_dir
            ):
                with self.assertRaisesRegex(ValueError, "reparse point"):
                    _validate_run_directory(redirected_run, runs_dir)

    def test_training_output_path_traversal_is_rejected(self):
        traversal_path = DEFAULT_TRAINING_RUNS_DIR / ".." / "alternate"

        with self.assertRaisesRegex(ValueError, "traversal"):
            validate_training_runs_dir(traversal_path)

    def test_train_baseline_does_not_accept_output_root_override(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TypeError):
                train_baseline(
                    dataset_path=Path(directory) / "unused.zip",
                    runs_dir=Path(directory) / "other-runs"
                )

    def test_direct_unconfirmed_approved_dataset_is_rejected_before_io(self):
        run_directory_existed = DEFAULT_TRAINING_RUNS_DIR.exists()
        with patch(
            "models.train_model.validate_approved_dataset"
        ) as dataset_validator, patch(
            "models.train_model.validate_training_runs_dir"
        ) as output_validator, patch(
            "models.train_model.Pipeline.fit"
        ) as model_fit:
            with self.assertRaisesRegex(ValueError, "requires"):
                train_baseline(dataset_path=DEFAULT_DATASET_PATH)

        dataset_validator.assert_not_called()
        output_validator.assert_not_called()
        model_fit.assert_not_called()
        self.assertEqual(
            DEFAULT_TRAINING_RUNS_DIR.exists(),
            run_directory_existed
        )

    def test_isolated_synthetic_dataset_needs_no_real_dataset_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset_path = Path(directory) / "synthetic.zip"
            dataset_path.write_bytes(b"synthetic fixture only")
            with patch(
                "models.train_model.validate_approved_dataset",
                return_value=(dataset_path, "synthetic-hash")
            ) as dataset_validator, patch(
                "models.train_model.validate_training_runs_dir",
                side_effect=RuntimeError("stop before directory creation")
            ):
                with self.assertRaisesRegex(RuntimeError, "stop before"):
                    train_baseline(dataset_path=dataset_path)

            dataset_validator.assert_called_once_with(dataset_path)

    def test_cli_requires_explicit_approved_dataset_confirmation(self):
        run_directory_existed = DEFAULT_TRAINING_RUNS_DIR.exists()
        with patch("sys.argv", ["train_model.py"]), patch(
            "models.train_model.train_baseline"
        ) as trainer, patch(
            "argparse.ArgumentParser.error",
            side_effect=SystemExit(2)
        ) as parser_error:
            with self.assertRaises(SystemExit):
                main()

        trainer.assert_not_called()
        parser_error.assert_called_once()
        self.assertEqual(
            DEFAULT_TRAINING_RUNS_DIR.exists(),
            run_directory_existed
        )

    def test_cli_confirmation_calls_trainer_without_training_in_test(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset_path = Path(directory) / "synthetic.zip"
            model_path = Path(directory) / "run" / DEFAULT_MODEL_PATH.name
            with patch(
                "sys.argv",
                [
                    "train_model.py",
                    "--dataset",
                    str(dataset_path),
                    "--confirm-approved-dataset"
                ]
            ), patch(
                "models.train_model.train_baseline",
                return_value=(model_path, {})
            ) as trainer:
                main()

            trainer.assert_called_once_with(
                dataset_path=dataset_path,
                confirm_approved_dataset=True
            )

    def test_original_model_hash_remains_unchanged(self):
        self.assertEqual(
            sha256_file(DEFAULT_MODEL_PATH).upper(),
            "80B646B4AE1B90EE2A80D0214D2A175A05B0E75562FF1FD85D26AE32CD4FEE3E"
        )


if __name__ == "__main__":
    unittest.main()
