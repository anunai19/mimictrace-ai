import argparse
import json
from pathlib import Path

import joblib

from models.model_utils import (
    DEFAULT_DATASET_PATH,
    DEFAULT_MODEL_PATH,
    classification_metrics,
    check_split_overlap,
    domain_group_split,
    prepare_dataset
)


def evaluate_saved_model(dataset_path=DEFAULT_DATASET_PATH, model_path=DEFAULT_MODEL_PATH):
    artifact = joblib.load(model_path)
    if not isinstance(artifact, dict) or not {
        "model",
        "feature_names",
        "dataset",
        "split"
    }.issubset(artifact):
        raise ValueError("Model artifact has an unsupported format.")

    features, labels, groups, urls, dataset_metadata = prepare_dataset(dataset_path)
    if dataset_metadata["archive_sha256"] != artifact["dataset"]["archive_sha256"]:
        raise ValueError(
            "Dataset archive does not match the dataset used to train this model."
        )
    if list(features.columns) != artifact["feature_names"]:
        raise ValueError("Dataset feature schema does not match the model artifact.")

    train_indices, test_indices = domain_group_split(
        labels,
        groups,
        n_splits=artifact["split"]["n_splits"],
        fold=artifact["split"]["fold"]
    )
    overlap_checks = check_split_overlap(
        urls,
        groups,
        train_indices,
        test_indices
    )
    predictions = artifact["model"].predict(features.iloc[test_indices])
    return {
        "dataset_sha256": dataset_metadata["archive_sha256"],
        "split": artifact["split"],
        "overlap_checks": overlap_checks,
        "metrics": classification_metrics(
            labels.iloc[test_indices],
            predictions
        )
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate a saved URL phishing model on its held-out domain fold."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_PATH,
        help="Path to the approved UCI dataset ZIP archive."
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help="Path to a model artifact produced by models.train_model."
    )
    args = parser.parse_args()
    report = evaluate_saved_model(args.dataset, args.model)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()