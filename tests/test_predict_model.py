import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib

from models.predict_model import (
    ModelPredictionError,
    ModelUnavailableError,
    load_model,
    predict_url_features
)


FEATURES = {
    "url_length": 24,
    "hostname_length": 11,
    "path_length": 6,
    "dot_count": 1,
    "hyphen_count": 0,
    "at_symbol_count": 0,
    "digit_count": 0,
    "uses_https": 1,
    "uses_ip_address": 0,
    "suspicious_keyword_count": 1
}


class FixedPredictionModel:

    def __init__(self, label):
        self.label = label
        self.columns = None

    def predict(self, frame):
        self.columns = list(frame.columns)
        return [self.label]


def build_artifact(model):
    return {
        "model": model,
        "feature_names": list(FEATURES),
        "dataset": {
            "model_label_mapping": {
                "0": "legitimate",
                "1": "phishing"
            }
        }
    }


class TestPredictModel(unittest.TestCase):

    def test_prediction_maps_both_model_labels(self):
        cases = (
            (1, "phishing", True),
            (0, "legitimate", False)
        )
        for model_label, expected_label, is_phishing in cases:
            with self.subTest(model_label=model_label):
                model = FixedPredictionModel(model_label)
                with patch(
                    "models.predict_model.load_model",
                    return_value=build_artifact(model)
                ):
                    prediction = predict_url_features(FEATURES)

                self.assertEqual(prediction["label"], expected_label)
                self.assertEqual(prediction["is_phishing"], is_phishing)
                self.assertIn("not a guaranteed security verdict", prediction["disclaimer"])
                self.assertEqual(model.columns, list(FEATURES))

    def test_feature_schema_mismatch_is_an_explicit_error(self):
        with patch(
            "models.predict_model.load_model",
            return_value=build_artifact(FixedPredictionModel(0))
        ):
            with self.assertRaises(ModelPredictionError):
                predict_url_features({"url_length": 24})

    def test_missing_model_file_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "missing.joblib"
            with self.assertRaisesRegex(ModelUnavailableError, "missing"):
                load_model(missing_path)

    def test_invalid_model_artifact_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "invalid.joblib"
            joblib.dump({"unexpected": "content"}, artifact_path)

            with self.assertRaisesRegex(ModelUnavailableError, "invalid"):
                load_model(artifact_path)

    def test_unreadable_model_artifact_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "unreadable.joblib"
            artifact_path.write_bytes(b"not a model artifact")

            with patch("models.predict_model.logger.exception"):
                with self.assertRaisesRegex(ModelUnavailableError, "could not be loaded"):
                    load_model(artifact_path)

    def test_prediction_failure_is_wrapped(self):
        class FailingModel:
            def predict(self, frame):
                raise RuntimeError("model failure")

        with patch(
            "models.predict_model.load_model",
            return_value=build_artifact(FailingModel())
        ), patch("models.predict_model.logger.exception"):
            with self.assertRaisesRegex(ModelPredictionError, "could not generate"):
                predict_url_features(FEATURES)


if __name__ == "__main__":
    unittest.main()
