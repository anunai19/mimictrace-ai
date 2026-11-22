import argparse
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.pipeline import Pipeline

from detection.url_analyzer import analyze_url
from models.model_utils import (
    DEFAULT_DATASET_PATH,
    DEFAULT_MODEL_PATH,
    classification_metrics,
    class_distribution,
    load_dataset_frame,
    sha256_file
)


EXPECTED_MODEL_SHA256 = (
    "80B646B4AE1B90EE2A80D0214D2A175A05B0E75562FF1FD85D26AE32CD4FEE3E"
)
EXPECTED_FEATURE_NAMES = (
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
)
REQUIRED_COLUMNS = {
    "url",
    "label",
    "source",
    "source_label",
    "timestamp",
    "snapshot_id"
}
LABEL_MAPPING = {"0": "legitimate", "1": "phishing"}
MAX_EXTERNAL_ROWS = 100_000
MAX_EXTERNAL_BYTES = 50 * 1024 * 1024
UNSUPPORTED_SOURCE_LABELS = {
    "malware",
    "suspicious",
    "unknown",
    "unrated"
}
NONDETECTION_SOURCE_LABELS = {
    "not detected",
    "not_detected",
    "undetected",
    "vendor_negative",
    "no detection",
    "no detections",
    "no engines detected"
}
LEGITIMATE_LABEL_BASIS = {"independent_verification"}
PHISHING_LABEL_BASES = {"verified_phishing", "expert_consensus"}
UNRESERVED_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
PERCENT_ESCAPE = re.compile(r"%([0-9a-fA-F]{2})")
INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True
)


class ExternalEvaluationError(ValueError):
    pass


def load_external_csv(dataset_path):
    dataset_path = Path(dataset_path)
    if dataset_path.stat().st_size > MAX_EXTERNAL_BYTES:
        raise ExternalEvaluationError(
            f"External CSV exceeds the {MAX_EXTERNAL_BYTES:,}-byte limit. "
            "Prepare and document a bounded evaluation cohort."
        )
    frame = pd.read_csv(
        dataset_path,
        dtype=str,
        keep_default_na=False,
        nrows=MAX_EXTERNAL_ROWS + 1
    )
    if len(frame) > MAX_EXTERNAL_ROWS:
        raise ExternalEvaluationError(
            f"External CSV exceeds the {MAX_EXTERNAL_ROWS:,}-row limit. "
            "Prepare and document a bounded evaluation cohort."
        )
    return frame


def load_label_manifest(manifest_path):
    with Path(manifest_path).open("r", encoding="utf-8") as source:
        try:
            manifest = json.load(source)
        except json.JSONDecodeError as error:
            raise ExternalEvaluationError(
                "Label mapping manifest must contain valid JSON."
            ) from error
    return validate_label_manifest(manifest)


def validate_label_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ExternalEvaluationError("Label mapping manifest must be an object.")
    if not {
        "source",
        "snapshot_id",
        "label_mapping"
    }.issubset(manifest):
        raise ExternalEvaluationError(
            "Manifest requires source, snapshot_id, and label_mapping."
        )
    for field in ("source", "snapshot_id"):
        if not isinstance(manifest[field], str) or not manifest[field].strip():
            raise ExternalEvaluationError(
                f"Manifest {field} must be a non-empty string."
            )

    raw_mapping = manifest["label_mapping"]
    if not isinstance(raw_mapping, dict) or not raw_mapping:
        raise ExternalEvaluationError(
            "Manifest label_mapping must be a non-empty object."
        )

    normalized_mapping = {}
    for source_label, mapping in raw_mapping.items():
        if not isinstance(source_label, str) or not source_label.strip():
            raise ExternalEvaluationError(
                "Manifest source labels must be non-empty strings."
            )
        key = source_label.strip().casefold()
        if key in normalized_mapping:
            raise ExternalEvaluationError(
                "Manifest contains duplicate source labels after normalization."
            )
        if key in UNSUPPORTED_SOURCE_LABELS | NONDETECTION_SOURCE_LABELS:
            raise ExternalEvaluationError(
                f"Unsupported source label in manifest: {source_label}."
            )
        if (
            not isinstance(mapping, dict)
            or set(mapping) != {"target", "basis"}
            or not isinstance(mapping["target"], str)
            or not isinstance(mapping["basis"], str)
        ):
            raise ExternalEvaluationError(
                f"Manifest mapping for {source_label} requires target and basis."
            )

        target = mapping["target"].strip().casefold()
        basis = mapping["basis"].strip().casefold()
        if target == "legitimate" and basis not in LEGITIMATE_LABEL_BASIS:
            raise ExternalEvaluationError(
                "A legitimate label requires independent verification; "
                "vendor non-detection is not sufficient."
            )
        if target == "phishing" and basis not in PHISHING_LABEL_BASES:
            raise ExternalEvaluationError(
                f"Unsupported phishing evidence basis for {source_label}."
            )
        if target not in {"legitimate", "phishing"}:
            raise ExternalEvaluationError(
                f"Unsupported target label in manifest: {mapping['target']}."
            )
        normalized_mapping[key] = {"target": target, "basis": basis}

    if {entry["target"] for entry in normalized_mapping.values()} != {
        "legitimate",
        "phishing"
    }:
        raise ExternalEvaluationError(
            "Manifest must explicitly map source labels to both legitimate "
            "and phishing classes."
        )

    return {
        "source": manifest["source"].strip(),
        "snapshot_id": manifest["snapshot_id"].strip(),
        "label_mapping": normalized_mapping
    }


def _sha256(path):
    return sha256_file(path)


def _assert_model_integrity():
    actual_hash = _sha256(DEFAULT_MODEL_PATH).upper()
    if actual_hash != EXPECTED_MODEL_SHA256.upper():
        raise ExternalEvaluationError(
            "The saved model SHA-256 does not match the approved artifact."
        )
    return actual_hash


def load_verified_model():
    model_hash = _assert_model_integrity()
    artifact = joblib.load(DEFAULT_MODEL_PATH)
    required_artifact_keys = {
        "model",
        "feature_names",
        "dataset",
        "split",
        "evaluation"
    }
    if (
        not isinstance(artifact, dict)
        or not required_artifact_keys.issubset(artifact)
    ):
        raise ExternalEvaluationError("The saved model artifact is invalid.")

    model = artifact["model"]
    if (
        not isinstance(model, Pipeline)
        or not {"scaler", "classifier"}.issubset(model.named_steps)
        or artifact["feature_names"] != list(EXPECTED_FEATURE_NAMES)
        or not callable(getattr(model, "predict", None))
        or not isinstance(artifact["dataset"], dict)
        or not isinstance(artifact["split"], dict)
        or not isinstance(artifact["evaluation"], dict)
        or artifact["dataset"].get("model_label_mapping") != LABEL_MAPPING
    ):
        raise ExternalEvaluationError(
            "The saved model pipeline, feature schema, or label mapping is invalid."
        )

    if _assert_model_integrity() != model_hash:
        raise ExternalEvaluationError("The saved model changed while loading.")
    return artifact


def _parse_timestamp(value, field_name):
    if not isinstance(value, str) or not value.strip():
        raise ExternalEvaluationError(
            f"{field_name} must be a non-empty timestamp with a timezone."
        )
    try:
        timestamp = pd.Timestamp(value.strip())
    except (TypeError, ValueError) as error:
        raise ExternalEvaluationError(
            f"{field_name} is not a valid timestamp."
        ) from error
    if pd.isna(timestamp) or timestamp.tzinfo is None:
        raise ExternalEvaluationError(
            f"{field_name} must include an explicit timezone."
        )
    return timestamp.tz_convert("UTC")


def _normalize_percent_encoding(component):
    if INVALID_PERCENT_ESCAPE.search(component):
        raise ExternalEvaluationError(
            "URL contains an invalid percent-encoding escape."
        )

    def normalize_escape(match):
        byte_value = int(match.group(1), 16)
        character = chr(byte_value)
        if character in UNRESERVED_CHARACTERS:
            return character
        return f"%{byte_value:02X}"

    return PERCENT_ESCAPE.sub(normalize_escape, component)


def _url_keys(url):
    if not isinstance(url, str) or not url.strip():
        raise ExternalEvaluationError("URL must be a non-empty string.")

    candidate = url.strip()
    try:
        parsed = urlsplit(candidate)
    except ValueError as error:
        raise ExternalEvaluationError("URL is malformed.") from error
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
    ):
        raise ExternalEvaluationError(
            "URL must be an absolute HTTP or HTTPS URL with a hostname."
        )

    try:
        analysis = analyze_url(candidate)
    except ValueError as error:
        raise ExternalEvaluationError("URL is invalid.") from error
    features = analysis["features"]
    if tuple(features) != EXPECTED_FEATURE_NAMES:
        raise ExternalEvaluationError(
            "URL analyzer features do not match the saved model schema."
        )
    try:
        numeric_features = np.asarray(
            [features[name] for name in EXPECTED_FEATURE_NAMES],
            dtype=float
        )
    except (TypeError, ValueError) as error:
        raise ExternalEvaluationError("URL features must be numeric.") from error
    if not np.isfinite(numeric_features).all():
        raise ExternalEvaluationError("URL features must be finite.")

    raw_hostname = analysis["hostname"].lower().rstrip(".")
    if "%" in raw_hostname:
        raise ExternalEvaluationError(
            "Percent-encoded hostnames are not supported."
        )
    if ":" in raw_hostname:
        hostname = raw_hostname
    else:
        try:
            hostname = raw_hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ExternalEvaluationError(
                "URL hostname is not valid IDNA."
            ) from error
    extracted = DOMAIN_EXTRACTOR(hostname)
    registered_domain = (
        extracted.top_domain_under_public_suffix.lower()
        or hostname
    )

    try:
        port = parsed.port
    except ValueError as error:
        raise ExternalEvaluationError("URL contains an invalid port.") from error
    user_info = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = (
        (parsed.scheme.lower() == "http" and port == 80)
        or (parsed.scheme.lower() == "https" and port == 443)
    )
    port_suffix = f":{port}" if port is not None and not default_port else ""
    try:
        path = _normalize_percent_encoding(parsed.path)
        query = _normalize_percent_encoding(parsed.query)
        fragment = _normalize_percent_encoding(parsed.fragment)
    except ExternalEvaluationError:
        raise
    normalized_url = urlunsplit((
        parsed.scheme.lower(),
        f"{user_info}{authority_host}{port_suffix}",
        path,
        query,
        fragment
    ))
    return normalized_url, hostname, registered_domain, features


def _validate_external_frame(frame, label_manifest):
    label_manifest = validate_label_manifest(label_manifest)
    if not isinstance(frame, pd.DataFrame):
        raise ExternalEvaluationError("External input must be a DataFrame.")
    missing_columns = REQUIRED_COLUMNS - set(frame.columns)
    if missing_columns:
        raise ExternalEvaluationError(
            "External input is missing required columns: "
            + ", ".join(sorted(missing_columns))
        )
    if frame.empty:
        raise ExternalEvaluationError("External input contains no records.")

    records = []
    for row_index, row in frame.reset_index(drop=True).iterrows():
        row_number = row_index + 2
        text_fields = (
            "url",
            "label",
            "source",
            "source_label",
            "timestamp",
            "snapshot_id"
        )
        for field in text_fields:
            if not isinstance(row[field], str) or not row[field].strip():
                raise ExternalEvaluationError(
                    f"CSV row {row_number}: {field} must be a non-empty string."
                )

        source_label = row["source_label"].strip()
        source_label_key = source_label.casefold()
        if (
            source_label_key in UNSUPPORTED_SOURCE_LABELS
            or source_label_key in NONDETECTION_SOURCE_LABELS
        ):
            raise ExternalEvaluationError(
                f"CSV row {row_number}: unsupported source label "
                f"{source_label!r}."
            )
        mapped = label_manifest["label_mapping"].get(source_label_key)
        if mapped is None:
            raise ExternalEvaluationError(
                f"CSV row {row_number}: source label {source_label!r} is not "
                "present in the label mapping manifest."
            )
        label = row["label"].strip().casefold()
        if label not in {"legitimate", "phishing"}:
            raise ExternalEvaluationError(
                f"CSV row {row_number}: label must be legitimate or phishing."
            )
        if label != mapped["target"]:
            raise ExternalEvaluationError(
                f"CSV row {row_number}: normalized label disagrees with the "
                "source-specific manifest."
            )
        try:
            url_key, hostname, domain, features = _url_keys(row["url"])
        except ExternalEvaluationError as error:
            raise ExternalEvaluationError(
                f"CSV row {row_number}: {error}"
            ) from error
        try:
            timestamp = _parse_timestamp(
                row["timestamp"],
                f"CSV row {row_number} timestamp"
            )
        except ExternalEvaluationError as error:
            raise ExternalEvaluationError(str(error)) from error

        records.append({
            "url_key": url_key,
            "hostname": hostname,
            "domain": domain,
            "features": features,
            "label": 1 if label == "phishing" else 0,
            "source": row["source"].strip(),
            "source_label": source_label,
            "snapshot_id": row["snapshot_id"].strip(),
            "timestamp": timestamp
        })

    clean = pd.DataFrame.from_records(records)
    if clean["source"].nunique() != 1:
        raise ExternalEvaluationError(
            "Each evaluation input must contain exactly one source."
        )
    if clean["snapshot_id"].nunique() != 1:
        raise ExternalEvaluationError(
            "Each evaluation input must contain exactly one snapshot_id."
        )
    if clean["source"].iloc[0] != label_manifest["source"]:
        raise ExternalEvaluationError(
            "CSV source does not match the label mapping manifest."
        )
    if clean["snapshot_id"].iloc[0] != label_manifest["snapshot_id"]:
        raise ExternalEvaluationError(
            "CSV snapshot_id does not match the label mapping manifest."
        )

    conflicting_urls = clean.groupby("url_key")["label"].nunique().gt(1)
    if conflicting_urls.any():
        raise ExternalEvaluationError(
            "Duplicate normalized URLs have conflicting target labels."
        )

    duplicate_rows_removed = int(clean["url_key"].duplicated().sum())
    clean = (
        clean.sort_values("timestamp", kind="stable")
        .drop_duplicates(subset="url_key", keep="first")
        .reset_index(drop=True)
    )
    return clean, duplicate_rows_removed


def _build_reference_overlap_sets(reference_frame):
    if not isinstance(reference_frame, pd.DataFrame):
        raise ExternalEvaluationError("Reference dataset must be a DataFrame.")
    required = {"URL", "Domain"}
    if not required.issubset(reference_frame.columns):
        raise ExternalEvaluationError(
            "Reference dataset is missing the URL column."
        )
    if reference_frame.empty:
        raise ExternalEvaluationError("Reference dataset contains no URLs.")

    reference_urls = set()
    reference_domains = set()
    registrable_domains = set()
    mismatched_domain_rows = 0
    for row_number, row in enumerate(
        reference_frame.itertuples(index=False),
        start=1
    ):
        try:
            url_key, _, derived_domain, _ = _url_keys(row.URL)
        except ExternalEvaluationError as error:
            raise ExternalEvaluationError(
                f"Reference dataset row {row_number}: {error}"
            ) from error
        raw_domain = row.Domain
        if not isinstance(raw_domain, str) or not raw_domain.strip():
            raise ExternalEvaluationError(
                f"Reference dataset row {row_number}: Domain must be non-empty."
            )
        training_domain = raw_domain.strip().lower()
        reference_urls.add(url_key)
        reference_domains.add(training_domain)
        registrable_domains.add(derived_domain)
        if training_domain != derived_domain:
            mismatched_domain_rows += 1
    return (
        reference_urls,
        reference_domains,
        registrable_domains,
        mismatched_domain_rows
    )


def _cohort_report(actual, predicted, mask):
    selected = np.asarray(mask, dtype=bool)
    count = int(selected.sum())
    result = {
        "sample_count": count,
        "class_distribution": {
            "legitimate": 0,
            "phishing": 0
        },
        "metrics": None,
        "false_positive_count": None,
        "false_negative_count": None
    }
    if count == 0:
        return result

    cohort_actual = np.asarray(actual, dtype=int)[selected]
    cohort_predicted = np.asarray(predicted, dtype=int)[selected]
    result["class_distribution"] = class_distribution(cohort_actual)
    metrics = classification_metrics(cohort_actual, cohort_predicted)
    matrix = metrics["confusion_matrix"]
    result["metrics"] = metrics
    result["false_positive_count"] = int(matrix[0][1])
    result["false_negative_count"] = int(matrix[1][0])
    return result


def evaluate_external_frame(
    frame,
    reference_frame,
    model,
    model_cutoff,
    label_manifest
):
    cutoff = _parse_timestamp(model_cutoff, "Model cutoff")
    label_manifest = validate_label_manifest(label_manifest)
    clean, duplicate_rows_removed = _validate_external_frame(
        frame,
        label_manifest
    )
    (
        reference_urls,
        training_domain_groups,
        derived_registrable_domains,
        domain_key_mismatch_rows
    ) = _build_reference_overlap_sets(reference_frame)

    exact_overlap = clean["url_key"].isin(reference_urls).to_numpy()
    training_domains = training_domain_groups | derived_registrable_domains
    domain_overlap = clean["domain"].isin(training_domains).to_numpy()
    post_cutoff = clean["timestamp"].gt(cutoff).to_numpy()
    eligible = ~exact_overlap
    if not eligible.any():
        raise ExternalEvaluationError(
            "All external URLs overlap the UCI reference; no independent "
            "evaluation cohort remains."
        )

    eligible_rows = clean.loc[eligible]
    eligible_domain_overlap = domain_overlap[eligible]
    feature_frame = pd.DataFrame.from_records(
        eligible_rows["features"].tolist(),
        columns=EXPECTED_FEATURE_NAMES
    )
    if list(feature_frame.columns) != list(EXPECTED_FEATURE_NAMES):
        raise ExternalEvaluationError(
            "Prepared feature columns do not match the saved model schema."
        )
    predictions = np.asarray(model.predict(feature_frame))
    if (
        predictions.ndim != 1
        or len(predictions) != len(eligible_rows)
        or not np.isin(predictions, [0, 1]).all()
    ):
        raise ExternalEvaluationError(
            "Saved model returned invalid prediction labels."
        )
    predictions = predictions.astype(int)

    actual = eligible_rows["label"].to_numpy(dtype=int)
    eligible_domains = eligible_rows["domain"].to_numpy()
    eligible_timestamps = eligible_rows["timestamp"]
    eligible_post_cutoff = eligible_timestamps.gt(cutoff).to_numpy()
    eligible_unseen_domain = np.asarray(
        [domain not in training_domains for domain in eligible_domains],
        dtype=bool
    )

    source = clean["source"].iloc[0]
    snapshot_id = clean["snapshot_id"].iloc[0]
    normalized_mapping = label_manifest["label_mapping"]
    source_label_counts = {
        str(key): int(value)
        for key, value in Counter(clean["source_label"]).items()
    }
    cutoff_iso = cutoff.isoformat()
    report = {
        "evaluation_type": "independent_cross_dataset",
        "source": source,
        "snapshot_id": snapshot_id,
        "label_mapping_manifest": {
            "source": label_manifest["source"],
            "snapshot_id": label_manifest["snapshot_id"],
            "mapping": normalized_mapping,
            "legitimate_basis_requirement": "independent_verification"
        },
        "model": {
            "artifact": str(DEFAULT_MODEL_PATH.name),
            "sha256": EXPECTED_MODEL_SHA256,
            "label_mapping": LABEL_MAPPING,
            "feature_names": list(EXPECTED_FEATURE_NAMES),
            "cutoff_supplied_by_user": cutoff_iso,
            "cutoff_note": (
                "The artifact does not contain an exact fit timestamp; "
                "the supplied cutoff is not independently verified."
            )
        },
        "input": {
            "row_count": int(len(frame)),
            "maximum_supported_rows": MAX_EXTERNAL_ROWS,
            "unique_url_count": int(len(clean)),
            "duplicate_url_rows_removed": duplicate_rows_removed,
            "maximum_supported_bytes": MAX_EXTERNAL_BYTES,
            "source_label_counts": source_label_counts,
            "first_timestamp_utc": clean["timestamp"].min().isoformat(),
            "last_timestamp_utc": clean["timestamp"].max().isoformat(),
            "timestamp_semantics": (
                "Source-provided event timestamp; syntax and timezone are "
                "validated, but provenance and meaning are not independently "
                "verified."
            ),
            "source_timestamp_after_cutoff_count": int(post_cutoff.sum())
        },
        "overlap_checks": {
            "reference_dataset": "UCI PhiUSIIL training dataset",
            "reference_row_count": int(len(reference_frame)),
            "exact_url_overlap_rows_excluded": int(exact_overlap.sum()),
            "training_domain_overlap_rows": int(domain_overlap.sum()),
            "training_domain_overlap_rows_excluding_exact_url": int(
                (domain_overlap & ~exact_overlap).sum()
            ),
            "overlapping_external_registrable_domain_count": int(
                clean.loc[domain_overlap, "domain"].nunique()
            ),
            "domain_key_equivalence": {
                "training_group_column": "Domain",
                "external_key": "registrable domain from URL",
                "mismatched_training_rows": int(domain_key_mismatch_rows),
                "exactly_equivalent": domain_key_mismatch_rows == 0,
                "overlap_basis": (
                    "union of original UCI Domain groups and registrable "
                    "domains derived from UCI URLs"
                )
            }
        },
        "preprocessing": {
            "feature_extractor": "detection.url_analyzer.analyze_url",
            "feature_count": len(EXPECTED_FEATURE_NAMES),
            "domain_overlap_method": (
                "tldextract bundled suffix list with network access disabled"
            ),
            "preprocessing_fitted_on_external_data": False,
            "model_training_performed": False
        },
        "cohorts": {
            "no_exact_url_overlap": _cohort_report(
                actual,
                predictions,
                np.ones(len(eligible_rows), dtype=bool)
            ),
            "domain_overlapping_with_training": _cohort_report(
                actual,
                predictions,
                eligible_domain_overlap
            ),
            "unseen_domains_vs_training": _cohort_report(
                actual,
                predictions,
                eligible_unseen_domain
            ),
            "after_model_cutoff": _cohort_report(
                actual,
                predictions,
                eligible_post_cutoff
            ),
            "after_cutoff_and_unseen_domains": _cohort_report(
                actual,
                predictions,
                eligible_post_cutoff & eligible_unseen_domain
            )
        }
    }
    return report


def _validate_output_path(
    report_path,
    dataset_path,
    reference_path,
    label_manifest_path
):
    output = Path(report_path).resolve()
    input_paths = {
        Path(dataset_path).resolve(),
        Path(reference_path).resolve(),
        Path(label_manifest_path).resolve()
    }
    if len(input_paths) != 3:
        raise ExternalEvaluationError(
            "External dataset, reference dataset, and label manifest "
            "must use separate files."
        )
    model_path = Path(DEFAULT_MODEL_PATH).resolve()
    if model_path in input_paths:
        raise ExternalEvaluationError(
            "The saved model cannot be used as an evaluation input."
        )
    protected_paths = {model_path, *input_paths}
    if output in protected_paths:
        raise ExternalEvaluationError(
            "Report path must be separate from the model and input datasets."
        )
    if output.exists():
        raise FileExistsError(
            f"Report already exists and will not be overwritten: {output}"
        )
    return output


def run_external_evaluation(
    dataset_path,
    label_manifest_path,
    report_path,
    model_cutoff,
    reference_path=DEFAULT_DATASET_PATH
):
    dataset_path = Path(dataset_path)
    label_manifest_path = Path(label_manifest_path)
    reference_path = Path(reference_path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"External CSV not found: {dataset_path}")
    if not label_manifest_path.is_file():
        raise FileNotFoundError(
            f"Label mapping manifest not found: {label_manifest_path}"
        )
    if not reference_path.is_file():
        raise FileNotFoundError(
            f"UCI reference archive not found: {reference_path}"
        )
    output_path = _validate_output_path(
        report_path,
        dataset_path,
        reference_path,
        label_manifest_path
    )

    model_hash = _assert_model_integrity()
    external_hash = sha256_file(dataset_path)
    reference_hash = sha256_file(reference_path)
    manifest_hash = sha256_file(label_manifest_path)
    external_frame = load_external_csv(dataset_path)
    label_manifest = load_label_manifest(label_manifest_path)
    reference_frame = load_dataset_frame(reference_path)
    artifact = load_verified_model()
    report = evaluate_external_frame(
        external_frame,
        reference_frame,
        artifact["model"],
        model_cutoff,
        label_manifest
    )
    report["comparison"] = {
        "original_uci_grouped_holdout": {
            "split": artifact["split"],
            "metrics": artifact["evaluation"],
            "note": (
                "Stored training-time holdout metrics are included for context; "
                "they are not an independent or temporal evaluation."
            )
        }
    }
    if _assert_model_integrity() != model_hash:
        raise ExternalEvaluationError(
            "Saved model hash changed during evaluation; report not written."
        )
    if sha256_file(dataset_path) != external_hash:
        raise ExternalEvaluationError(
            "External input changed during evaluation; report not written."
        )
    if sha256_file(reference_path) != reference_hash:
        raise ExternalEvaluationError(
            "Reference archive changed during evaluation; report not written."
        )
    if sha256_file(label_manifest_path) != manifest_hash:
        raise ExternalEvaluationError(
            "Label manifest changed during evaluation; report not written."
        )

    report["model"]["sha256"] = model_hash
    report["input"]["sha256"] = external_hash
    report["label_mapping_manifest"]["sha256"] = manifest_hash
    report["overlap_checks"]["reference_dataset_sha256"] = reference_hash

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, sort_keys=True)
        destination.write("\n")
    if _assert_model_integrity() != model_hash:
        raise ExternalEvaluationError(
            "Saved model hash changed after report creation."
        )
    return output_path, report


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the frozen URL model on one approved, local CSV cohort. "
            "This command does not download data or train a model."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Local CSV with the required provenance and label columns."
    )
    parser.add_argument(
        "--reference-dataset",
        type=Path,
        default=DEFAULT_DATASET_PATH,
        help="Local UCI PhiUSIIL ZIP used only for overlap checks."
    )
    parser.add_argument(
        "--label-manifest",
        type=Path,
        required=True,
        help="JSON file declaring source labels and their evidence basis."
    )
    parser.add_argument(
        "--model-cutoff",
        required=True,
        help="Caller-supplied ISO-8601 cutoff timestamp, including timezone."
    )
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="New JSON report path; existing files are never overwritten."
    )
    args = parser.parse_args()
    report_path, _ = run_external_evaluation(
        dataset_path=args.dataset,
        label_manifest_path=args.label_manifest,
        reference_path=args.reference_dataset,
        model_cutoff=args.model_cutoff,
        report_path=args.report
    )
    print(f"Evaluation report written: {report_path}")


if __name__ == "__main__":
    main()
