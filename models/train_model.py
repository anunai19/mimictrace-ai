import argparse
import json
import stat
from pathlib import Path
from urllib.parse import urlsplit

import joblib
from detection.url_analyzer import SUSPICIOUS_WORDS
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from models.provenance import (
    ProvenanceError,
    build_manifest,
    collect_environment,
    collect_source_metadata,
    create_run_id,
    utc_timestamp,
    write_manifest_exclusive
)
from models.model_utils import (
    DEFAULT_DATASET_PATH,
    DEFAULT_MODEL_PATH,
    classification_metrics,
    check_split_overlap,
    class_distribution,
    domain_group_split,
    prepare_dataset,
    sha256_file
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TRAINING_RUNS_DIR = Path(__file__).resolve().parent / "training_runs"
APPROVED_DATASET_SHA256 = (
    "0A639FD03AEA6308C5B1C10C92AA23C2CE1505447A9137271865CD0BADC9A59A"
)
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse_point(path):
    try:
        metadata = Path(path).lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISLNK(metadata.st_mode)
        or bool(
            getattr(metadata, "st_file_attributes", 0)
            & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        )
    )


def _validate_training_runs_path(output_dir, approved_dir):
    requested_path = Path(output_dir)
    if ".." in requested_path.parts:
        raise ValueError("Training output path cannot contain traversal segments.")

    approved_absolute = Path(approved_dir).absolute()
    requested_absolute = requested_path.absolute()
    if _is_reparse_point(approved_absolute):
        raise ValueError("Approved training output directory cannot be a reparse point.")
    if _is_reparse_point(requested_absolute):
        raise ValueError("Training output path cannot be a reparse point.")

    try:
        approved_resolved = approved_absolute.resolve(strict=False)
        requested_resolved = requested_absolute.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise ValueError("Training output path could not be resolved safely.") from error

    if approved_resolved != approved_absolute:
        raise ValueError("Approved training output directory cannot be redirected.")
    if requested_resolved != approved_absolute:
        raise ValueError(
            f"Training output must be under the approved directory: {approved_absolute}"
        )
    return approved_absolute


def validate_training_runs_dir(output_dir):
    approved_dir = Path(__file__).resolve().parent / "training_runs"
    return _validate_training_runs_path(output_dir, approved_dir)


def _validate_run_directory(run_dir, runs_dir):
    runs_dir = validate_training_runs_dir(runs_dir)
    run_dir = Path(run_dir).absolute()
    if run_dir.parent != runs_dir:
        raise ValueError("Training run directory must be directly under the approved root.")
    if _is_reparse_point(runs_dir) or _is_reparse_point(run_dir):
        raise ValueError("Training run paths cannot be reparse points.")
    if not runs_dir.is_dir() or not run_dir.is_dir():
        raise ValueError("Training run directories must exist as regular directories.")

    try:
        resolved_root = runs_dir.resolve(strict=True)
        resolved_run = run_dir.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("Training run directory changed during validation.") from error
    if resolved_root != runs_dir or resolved_run.parent != resolved_root:
        raise ValueError("Training run directory was redirected.")
    return run_dir


def validate_approved_dataset(dataset_path):
    try:
        raw_path = str(dataset_path)
        parsed_path = urlsplit(raw_path)
        is_windows_drive_path = (
            len(raw_path) >= 3
            and raw_path[0].isalpha()
            and raw_path[1] == ":"
            and raw_path[2] in ("\\", "/")
        )
        if parsed_path.scheme and not is_windows_drive_path:
            raise ValueError("Remote dataset URLs are not accepted.")

        approved_path = Path(DEFAULT_DATASET_PATH).absolute()
        resolved_approved_path = approved_path.resolve(strict=True)
        resolved_dataset_path = Path(dataset_path).resolve(strict=True)
    except (OSError, RuntimeError, TypeError) as error:
        raise ValueError(
            "The approved local UCI dataset archive must exist."
        ) from error

    if resolved_approved_path != approved_path:
        raise ValueError("The approved dataset path cannot be redirected.")
    if not resolved_dataset_path.is_file():
        raise ValueError("The approved dataset path must be a regular file.")
    if resolved_dataset_path != resolved_approved_path:
        raise ValueError(
            f"Only the approved local dataset archive is accepted: {approved_path}"
        )

    dataset_sha256 = sha256_file(resolved_dataset_path)
    if dataset_sha256.upper() != APPROVED_DATASET_SHA256:
        raise ValueError(
            "The approved dataset archive SHA-256 does not match the pinned value."
        )
    return resolved_dataset_path, dataset_sha256


def _uses_approved_dataset_path(dataset_path):
    try:
        dataset_path = Path(dataset_path)
        approved_path = Path(DEFAULT_DATASET_PATH)
        if dataset_path.absolute() == approved_path.absolute():
            return True
        return (
            dataset_path.resolve(strict=False)
            == approved_path.resolve(strict=False)
        )
    except (OSError, RuntimeError, TypeError):
        return False


def train_baseline(
    dataset_path=DEFAULT_DATASET_PATH,
    *,
    confirm_approved_dataset=False
):
    if (
        _uses_approved_dataset_path(dataset_path)
        and confirm_approved_dataset is not True
    ):
        raise ValueError(
            "Training on the approved UCI dataset requires "
            "confirm_approved_dataset=True."
        )

    dataset_path, dataset_sha256 = validate_approved_dataset(dataset_path)
    runs_dir = validate_training_runs_dir(DEFAULT_TRAINING_RUNS_DIR)
    runs_dir.mkdir(exist_ok=True)
    runs_dir = validate_training_runs_dir(runs_dir)

    dataset_path = Path(dataset_path)
    run_id = create_run_id()
    run_dir = runs_dir / run_id
    runs_dir = validate_training_runs_dir(runs_dir)
    run_dir.mkdir(exist_ok=False)
    _validate_run_directory(run_dir, runs_dir)
    run_started_at = utc_timestamp()

    source_metadata = collect_source_metadata(PROJECT_ROOT)
    environment = collect_environment()
    features, labels, groups, urls, dataset_metadata = prepare_dataset(dataset_path)
    if dataset_metadata["archive_sha256"] != dataset_sha256:
        raise ProvenanceError("Dataset archive changed while it was being prepared.")

    train_indices, test_indices = domain_group_split(labels, groups)
    overlap_checks = check_split_overlap(
        urls,
        groups,
        train_indices,
        test_indices
    )
    x_train = features.iloc[train_indices]
    x_test = features.iloc[test_indices]
    y_train = labels.iloc[train_indices]
    y_test = labels.iloc[test_indices]

    dummy = DummyClassifier(strategy="most_frequent")
    dummy.fit(x_train, y_train)
    dummy_metrics = classification_metrics(y_test, dummy.predict(x_test))

    scaler = StandardScaler()
    logistic_regression = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        random_state=42
    )
    classifier = Pipeline([
        ("scaler", scaler),
        ("classifier", logistic_regression)
    ])
    model_fit_started_at = utc_timestamp()
    classifier.fit(x_train, y_train)
    model_fit_completed_at = utc_timestamp()
    model_metrics = classification_metrics(y_test, classifier.predict(x_test))

    split_metadata = {
        "strategy": "StratifiedGroupKFold",
        "n_splits": 5,
        "fold": 0,
        "random_state": 42,
        "shuffle": True,
        "group_field": "Domain",
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "train_domains": int(groups.iloc[train_indices].nunique()),
        "test_domains": int(groups.iloc[test_indices].nunique()),
        "train_class_distribution": class_distribution(y_train),
        "test_class_distribution": class_distribution(y_test),
        "overlap_checks": overlap_checks
    }
    report = {
        "dataset": dataset_metadata,
        "split": split_metadata,
        "metrics": {
            "dummy_classifier": dummy_metrics,
            "logistic_regression": model_metrics
        }
    }
    artifact = {
        "model": classifier,
        "feature_names": list(features.columns),
        "dataset": dataset_metadata,
        "split": split_metadata,
        "evaluation": model_metrics
    }

    model_path = run_dir / DEFAULT_MODEL_PATH.name
    _validate_run_directory(run_dir, runs_dir)
    with model_path.open("xb") as artifact_file:
        joblib.dump(artifact, artifact_file)

    if sha256_file(dataset_path) != dataset_sha256:
        raise ProvenanceError("Dataset archive changed during training.")
    if collect_source_metadata(PROJECT_ROOT) != source_metadata:
        raise ProvenanceError("Relevant source files changed during training.")

    timestamps = {
        "run_started_at_utc": run_started_at,
        "model_fit_started_at_utc": model_fit_started_at,
        "model_fit_completed_at_utc": model_fit_completed_at,
        "run_completed_at_utc": utc_timestamp()
    }
    source_hashes = source_metadata["file_hashes"]
    model_configuration = {
        "type": "sklearn.pipeline.Pipeline",
        "steps": [
            {
                "name": name,
                "type": (
                    f"{type(estimator).__module__}."
                    f"{type(estimator).__qualname__}"
                ),
                "parameters": estimator.get_params(deep=False)
            }
            for name, estimator in classifier.steps
        ],
        "baseline": {
            "type": "sklearn.dummy.DummyClassifier",
            "parameters": dummy.get_params(deep=False)
        }
    }
    preprocessing = {
        "feature_extractor": "detection.url_analyzer.analyze_url",
        "feature_extractor_source_sha256": source_hashes[
            "detection/url_analyzer.py"
        ],
        "feature_order": list(features.columns),
        "url_normalization": {
            "trim_whitespace": True,
            "default_scheme": "https",
            "accepted_schemes": ["http", "https"],
            "suspicious_keywords": list(SUSPICIOUS_WORDS)
        },
        "scaler": {
            "type": "StandardScaler",
            "parameters": scaler.get_params(deep=False)
        }
    }
    manifest = build_manifest(
        run_id=run_id,
        timestamps=timestamps,
        model_path=model_path,
        dataset_metadata=dataset_metadata,
        dataset_sha256=dataset_sha256,
        feature_names=list(features.columns),
        model_configuration=model_configuration,
        preprocessing=preprocessing,
        split_metadata=split_metadata,
        model_metrics=model_metrics,
        baseline_metrics=dummy_metrics,
        source_metadata=source_metadata,
        environment=environment
    )
    _validate_run_directory(run_dir, runs_dir)
    write_manifest_exclusive(
        run_dir / "provenance.json",
        manifest,
        model_path
    )
    return model_path, report


def main():
    parser = argparse.ArgumentParser(
        description="Train and evaluate a URL-only phishing baseline."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_PATH,
        help="Path to the approved UCI dataset ZIP archive."
    )
    parser.add_argument(
        "--confirm-approved-dataset",
        action="store_true",
        help="Confirm that this command may train on the approved UCI dataset."
    )
    args = parser.parse_args()
    if not args.confirm_approved_dataset:
        parser.error(
            "Training is disabled by default; pass --confirm-approved-dataset "
            "to explicitly allow it."
        )

    model_path, report = train_baseline(
        dataset_path=args.dataset,
        confirm_approved_dataset=args.confirm_approved_dataset
    )
    print(json.dumps(report, indent=2))
    print(f"Training run ID: {model_path.parent.name}")
    print(f"Saved model artifact: {model_path}")
    print(f"Saved provenance manifest: {model_path.parent / 'provenance.json'}")


if __name__ == "__main__":
    main()