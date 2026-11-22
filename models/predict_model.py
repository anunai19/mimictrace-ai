import logging
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from models.model_utils import DEFAULT_MODEL_PATH


logger = logging.getLogger(__name__)


class ModelUnavailableError(Exception):
    pass


class ModelPredictionError(Exception):
    pass


@lru_cache(maxsize=1)
def load_model(model_path=DEFAULT_MODEL_PATH):
    model_path = Path(model_path)
    if not model_path.is_file():
        raise ModelUnavailableError("The prediction model file is missing.")

    try:
        # joblib uses pickle; only load the fixed application-owned artifact.
        artifact = joblib.load(model_path)
    except Exception as error:
        logger.exception("Failed to load local prediction artifact.")
        raise ModelUnavailableError(
            "The saved prediction model could not be loaded."
        ) from error

    required_keys = {"model", "feature_names", "dataset"}
    if not isinstance(artifact, dict) or not required_keys.issubset(artifact):
        raise ModelUnavailableError("The saved prediction model is invalid.")

    model = artifact["model"]
    feature_names = artifact["feature_names"]
    dataset_metadata = artifact["dataset"]
    if (
        not isinstance(model, Pipeline)
        or not {"scaler", "classifier"}.issubset(model.named_steps)
        or not isinstance(feature_names, list)
        or not feature_names
        or not all(isinstance(name, str) for name in feature_names)
        or len(set(feature_names)) != len(feature_names)
        or not isinstance(dataset_metadata, dict)
        or dataset_metadata.get("model_label_mapping")
        != {"0": "legitimate", "1": "phishing"}
    ):
        raise ModelUnavailableError("The saved prediction model is invalid.")

    return artifact


def predict_url_features(features):
    artifact = load_model()
    feature_names = artifact["feature_names"]
    if not isinstance(features, dict) or set(features) != set(feature_names):
        raise ModelPredictionError(
            "Extracted URL features do not match the model feature schema."
        )

    try:
        row = pd.DataFrame(
            [{name: features[name] for name in feature_names}],
            columns=feature_names
        )
        if not np.isfinite(row.to_numpy(dtype=float)).all():
            raise ModelPredictionError("Extracted URL features are not finite.")
        predicted_label = int(artifact["model"].predict(row)[0])
    except ModelPredictionError:
        raise
    except Exception as error:
        logger.exception("Model inference failed.")
        raise ModelPredictionError(
            "The model could not generate a prediction."
        ) from error

    if predicted_label not in (0, 1):
        raise ModelPredictionError("The model returned an unsupported label.")

    return {
        "status": "available",
        "label": artifact["dataset"]["model_label_mapping"][str(predicted_label)],
        "is_phishing": predicted_label == 1,
        "disclaimer": (
            "This model output is an estimate, not a guaranteed security verdict."
        )
    }
