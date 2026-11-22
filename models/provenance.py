import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from models.model_utils import sha256_file


SCHEMA_VERSION = "1.0"
SOURCE_FILES = (
    "requirements.txt",
    "models/train_model.py",
    "models/model_utils.py",
    "models/provenance.py",
    "detection/url_analyzer.py"
)
PACKAGE_DISTRIBUTIONS = (
    "joblib",
    "numpy",
    "pandas",
    "scikit-learn"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_FIELDS = (
    "run_started_at_utc",
    "model_fit_started_at_utc",
    "model_fit_completed_at_utc",
    "run_completed_at_utc"
)


class ProvenanceError(ValueError):
    pass


def create_run_id():
    return str(uuid.uuid4())


def utc_timestamp():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _git_value(project_root, *arguments):
    try:
        result = subprocess.run(
            ["git", "-C", str(project_root), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=5
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None
    return result.stdout.strip()


def collect_source_metadata(project_root):
    project_root = Path(project_root).resolve()
    file_hashes = {}
    for relative_path in SOURCE_FILES:
        source_path = project_root / relative_path
        if not source_path.is_file():
            raise ProvenanceError(
                f"Required provenance source file is missing: {relative_path}"
            )
        file_hashes[relative_path] = sha256_file(source_path)

    canonical_files = json.dumps(
        file_hashes,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")
    git_commit = _git_value(project_root, "rev-parse", "HEAD")
    if git_commit:
        git_status = _git_value(
            project_root,
            "status",
            "--porcelain",
            "--untracked-files=no"
        )
        working_tree = (
            "clean" if git_status == ""
            else "dirty" if git_status is not None
            else "unavailable"
        )
    else:
        working_tree = "unavailable"

    return {
        "git_commit": git_commit or None,
        "working_tree": working_tree,
        "file_hashes": file_hashes,
        "source_manifest_sha256": hashlib.sha256(canonical_files).hexdigest()
    }


def collect_environment():
    package_versions = {}
    for distribution in PACKAGE_DISTRIBUTIONS:
        try:
            package_versions[distribution] = version(distribution)
        except PackageNotFoundError as error:
            raise ProvenanceError(
                f"Cannot record installed package version: {distribution}"
            ) from error

    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "packages": package_versions
    }


def build_manifest(
    *,
    run_id,
    timestamps,
    model_path,
    dataset_metadata,
    dataset_sha256,
    feature_names,
    model_configuration,
    preprocessing,
    split_metadata,
    model_metrics,
    baseline_metrics,
    source_metadata,
    environment
):
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "status": "completed",
        "timestamps": {
            "source": "computer_clock",
            "trust_status": "observed_unattested",
            **timestamps
        },
        "artifact": {
            "relative_path": Path(model_path).name,
            "sha256": sha256_file(model_path)
        },
        "dataset": {
            **dataset_metadata,
            "sha256": dataset_sha256
        },
        "source_code": source_metadata,
        "environment": environment,
        "model": model_configuration,
        "preprocessing": {
            "feature_names": list(feature_names),
            **preprocessing
        },
        "split": split_metadata,
        "evaluation": {
            "methodology": (
                "Single stratified domain-grouped held-out fold; "
                "no temporal split or hyperparameter tuning."
            ),
            "positive_class": "phishing",
            "metrics": model_metrics,
            "baseline": {
                "type": "DummyClassifier",
                "strategy": "most_frequent",
                "metrics": baseline_metrics
            }
        }
    }


def _parse_utc_timestamp(value, field_name):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProvenanceError(
            f"{field_name} must be a timezone-qualified UTC timestamp ending in Z."
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProvenanceError(f"{field_name} is not a valid ISO timestamp.") from error
    if parsed.utcoffset() != timedelta(0):
        raise ProvenanceError(f"{field_name} must use UTC.")
    return parsed


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ProvenanceError("Provenance manifest must be a JSON object.")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ProvenanceError("Unsupported provenance schema version.")
    if manifest.get("status") != "completed":
        raise ProvenanceError("Only completed training runs have a success manifest.")

    try:
        parsed_run_id = uuid.UUID(manifest["run_id"])
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ProvenanceError("Provenance run_id must be a UUID.") from error
    if parsed_run_id.version != 4 or str(parsed_run_id) != manifest["run_id"]:
        raise ProvenanceError("Provenance run_id must be a canonical UUID4.")

    timestamps = manifest.get("timestamps")
    if (
        not isinstance(timestamps, dict)
        or timestamps.get("source") != "computer_clock"
        or timestamps.get("trust_status") != "observed_unattested"
    ):
        raise ProvenanceError(
            "Computer-clock timestamps must be marked observed_unattested."
        )
    parsed_timestamps = {
        field: _parse_utc_timestamp(timestamps.get(field), field)
        for field in TIMESTAMP_FIELDS
    }
    if not (
        parsed_timestamps["run_started_at_utc"]
        <= parsed_timestamps["model_fit_started_at_utc"]
        <= parsed_timestamps["model_fit_completed_at_utc"]
        <= parsed_timestamps["run_completed_at_utc"]
    ):
        raise ProvenanceError("Training timestamps are not in chronological order.")

    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict) or not _is_sha256(artifact.get("sha256")):
        raise ProvenanceError("Artifact SHA-256 is missing or malformed.")
    relative_artifact_path = artifact.get("relative_path")
    if not isinstance(relative_artifact_path, str):
        raise ProvenanceError("Artifact path must be a relative string.")
    artifact_path = Path(relative_artifact_path)
    if (
        not artifact_path.name
        or artifact_path.is_absolute()
        or ".." in artifact_path.parts
    ):
        raise ProvenanceError("Artifact path must be a safe relative path.")

    dataset = manifest.get("dataset")
    if (
        not isinstance(dataset, dict)
        or not _is_sha256(dataset.get("sha256"))
        or dataset.get("archive_sha256") != dataset.get("sha256")
        or not isinstance(dataset.get("name"), str)
        or not isinstance(dataset.get("source"), str)
        or not isinstance(dataset.get("version"), str)
    ):
        raise ProvenanceError("Dataset identity or SHA-256 is missing.")

    source_code = manifest.get("source_code")
    file_hashes = (
        source_code.get("file_hashes")
        if isinstance(source_code, dict)
        else None
    )
    if (
        not isinstance(file_hashes, dict)
        or not file_hashes
        or any(
            not isinstance(path, str)
            or not _is_sha256(digest)
            for path, digest in file_hashes.items()
        )
        or not _is_sha256(source_code.get("source_manifest_sha256"))
    ):
        raise ProvenanceError("Source-code hashes are missing or malformed.")
    canonical_files = json.dumps(
        file_hashes,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")
    if hashlib.sha256(canonical_files).hexdigest() != source_code[
        "source_manifest_sha256"
    ]:
        raise ProvenanceError("Source-code manifest hash does not match its files.")

    environment = manifest.get("environment")
    if (
        not isinstance(environment, dict)
        or not isinstance(environment.get("python_version"), str)
        or not isinstance(environment.get("python_implementation"), str)
        or not isinstance(environment.get("platform"), str)
        or not isinstance(environment.get("packages"), dict)
        or not set(PACKAGE_DISTRIBUTIONS).issubset(environment["packages"])
        or any(not isinstance(value, str) for value in environment["packages"].values())
    ):
        raise ProvenanceError("Python/package environment metadata is invalid.")

    preprocessing = manifest.get("preprocessing")
    feature_names = (
        preprocessing.get("feature_names")
        if isinstance(preprocessing, dict)
        else None
    )
    if (
        not isinstance(feature_names, list)
        or not feature_names
        or any(not isinstance(name, str) or not name for name in feature_names)
        or len(set(feature_names)) != len(feature_names)
    ):
        raise ProvenanceError("Feature names must be non-empty and unique.")
    if preprocessing.get("feature_order") != feature_names:
        raise ProvenanceError("Recorded feature order does not match feature names.")

    if (
        not isinstance(preprocessing.get("feature_extractor"), str)
        or not _is_sha256(preprocessing.get("feature_extractor_source_sha256"))
        or not isinstance(preprocessing.get("scaler"), dict)
    ):
        raise ProvenanceError("Feature extraction or preprocessing metadata is missing.")

    model = manifest.get("model")
    if (
        not isinstance(model, dict)
        or not isinstance(model.get("type"), str)
        or not isinstance(model.get("steps"), list)
        or not model["steps"]
        or not isinstance(model.get("baseline"), dict)
        or any(
            not isinstance(step, dict)
            or not isinstance(step.get("name"), str)
            or not isinstance(step.get("type"), str)
            or not isinstance(step.get("parameters"), dict)
            for step in model["steps"]
        )
    ):
        raise ProvenanceError("Model configuration is missing.")
    split = manifest.get("split")
    if (
        not isinstance(split, dict)
        or not isinstance(split.get("strategy"), str)
        or not isinstance(split.get("group_field"), str)
        or not isinstance(split.get("shuffle"), bool)
        or type(split.get("n_splits")) is not int
        or type(split.get("fold")) is not int
        or type(split.get("random_state")) is not int
        or split["n_splits"] < 2
        or split["fold"] < 0
        or split["fold"] >= split["n_splits"]
        or type(split.get("train_rows")) is not int
        or type(split.get("test_rows")) is not int
        or split["train_rows"] < 1
        or split["test_rows"] < 1
        or not isinstance(split.get("overlap_checks"), dict)
        or type(split["overlap_checks"].get("url_overlap_count")) is not int
        or type(split["overlap_checks"].get("domain_overlap_count")) is not int
        or split["overlap_checks"].get("url_overlap_count") != 0
        or split["overlap_checks"].get("domain_overlap_count") != 0
    ):
        raise ProvenanceError("Train/test split configuration is missing.")
    evaluation = manifest.get("evaluation")
    if (
        not isinstance(evaluation, dict)
        or evaluation.get("positive_class") != "phishing"
        or not isinstance(evaluation.get("methodology"), str)
        or not isinstance(evaluation.get("metrics"), dict)
        or not {
            "precision",
            "recall",
            "f1_score",
            "confusion_matrix"
        }.issubset(evaluation["metrics"])
        or not isinstance(evaluation.get("baseline"), dict)
        or not isinstance(evaluation["baseline"].get("metrics"), dict)
    ):
        raise ProvenanceError("Evaluation metadata is missing.")
    _validate_metrics(evaluation["metrics"], "model")
    _validate_metrics(evaluation["baseline"]["metrics"], "baseline")
    try:
        json.dumps(manifest, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ProvenanceError("Provenance manifest is not valid finite JSON.") from error


def _validate_metrics(metrics, name):
    for metric_name in ("precision", "recall", "f1_score"):
        value = metrics.get(metric_name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= value <= 1
        ):
            raise ProvenanceError(
                f"{name} evaluation metric {metric_name} is invalid."
            )
    matrix = metrics.get("confusion_matrix")
    if (
        not isinstance(matrix, list)
        or len(matrix) != 2
        or any(
            not isinstance(row, list)
            or len(row) != 2
            or any(type(value) is not int or value < 0 for value in row)
            for row in matrix
        )
    ):
        raise ProvenanceError(f"{name} confusion matrix is invalid.")


def verify_artifact_hash(model_path, expected_sha256):
    if not _is_sha256(expected_sha256):
        raise ProvenanceError("Expected artifact SHA-256 is malformed.")
    actual_sha256 = sha256_file(model_path)
    if actual_sha256 != expected_sha256:
        raise ProvenanceError("Saved model artifact SHA-256 does not match the manifest.")
    return actual_sha256


def _is_sha256(value):
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def write_manifest_exclusive(manifest_path, manifest, model_path):
    manifest_path = Path(manifest_path)
    model_path = Path(model_path)
    validate_manifest(manifest)
    if manifest_path.parent.resolve() != model_path.parent.resolve():
        raise ProvenanceError("Manifest and model artifact must share a run directory.")
    if manifest_path.parent.name != manifest["run_id"]:
        raise ProvenanceError("Run directory name must match the manifest run_id.")
    if manifest["artifact"].get("relative_path") != model_path.name:
        raise ProvenanceError("Manifest artifact path does not match the saved model.")
    verify_artifact_hash(model_path, manifest["artifact"]["sha256"])
    content = json.dumps(
        manifest,
        indent=2,
        sort_keys=True,
        allow_nan=False
    ) + "\n"

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".provenance-",
        suffix=".tmp",
        dir=manifest_path.parent
    )
    temporary_path = Path(temporary_name)
    published = False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())

        # A hard link publishes the complete manifest atomically and refuses replacement.
        os.link(temporary_path, manifest_path)
        published = True

        saved_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        validate_manifest(saved_manifest)
        verify_artifact_hash(model_path, saved_manifest["artifact"]["sha256"])
        return manifest_path
    except Exception:
        if published:
            manifest_path.unlink()
        raise
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
