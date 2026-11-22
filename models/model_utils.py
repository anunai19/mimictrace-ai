import hashlib
from pathlib import Path
from zipfile import ZipFile

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold

from detection.url_analyzer import analyze_url


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_PATH = (
    PROJECT_ROOT / "datasets" / "raw" / "phiusiil_phishing_url_dataset.zip"
)
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "phishing_url_model.joblib"
DATASET_SOURCE = (
    "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
)
DATASET_LICENSE = "CC BY 4.0"
DATASET_NAME = "PhiUSIIL Phishing URL Dataset"
DATASET_ID = "UCI Machine Learning Repository 967"
DATASET_RETRIEVED_DATE = "2026-11-15"
REQUIRED_COLUMNS = {"URL", "Domain", "label"}


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_dataset_frame(dataset_path=DEFAULT_DATASET_PATH):
    dataset_path = Path(dataset_path)
    if not dataset_path.is_file():
        raise FileNotFoundError(
            "Dataset archive not found. Expected the approved UCI PhiUSIIL "
            f"archive at {dataset_path}."
        )

    with ZipFile(dataset_path) as archive:
        csv_members = [
            member for member in archive.namelist()
            if member.lower().endswith(".csv")
        ]
        if len(csv_members) != 1:
            raise ValueError(
                "Dataset archive must contain exactly one CSV file."
            )

        with archive.open(csv_members[0]) as source:
            columns = set(pd.read_csv(source, nrows=0).columns)
        missing_columns = REQUIRED_COLUMNS - columns
        if missing_columns:
            raise ValueError(
                "Dataset is missing required columns: "
                + ", ".join(sorted(missing_columns))
            )

        with archive.open(csv_members[0]) as source:
            frame = pd.read_csv(
                source,
                usecols=list(REQUIRED_COLUMNS),
                low_memory=False
            )

    if frame.empty:
        raise ValueError("Dataset CSV contains no rows.")
    if frame[list(REQUIRED_COLUMNS)].isna().any().any():
        raise ValueError("Dataset URL, Domain, and label columns must not be missing.")
    if not frame["URL"].map(lambda value: isinstance(value, str)).all():
        raise ValueError("Every dataset URL must be a string.")

    frame["label"] = pd.to_numeric(frame["label"], errors="raise").astype(int)
    if not set(frame["label"].unique()).issubset({0, 1}):
        raise ValueError("Dataset labels must be 0 (phishing) or 1 (legitimate).")

    conflicting_urls = (
        frame.groupby("URL", sort=False)["label"].nunique().gt(1).any()
    )
    if conflicting_urls:
        raise ValueError("Duplicate URLs have conflicting target labels.")

    source_rows = len(frame)
    source_class_distribution = class_distribution(map_phishing_labels(frame["label"]))
    duplicate_url_rows_removed = int(frame["URL"].duplicated().sum())
    frame = frame.drop_duplicates(subset="URL", keep="first").reset_index(drop=True)
    frame.attrs["source_rows"] = source_rows
    frame.attrs["source_class_distribution"] = source_class_distribution
    frame.attrs["duplicate_url_rows_removed"] = duplicate_url_rows_removed
    return frame


def map_phishing_labels(labels):
    if not set(pd.Series(labels).dropna().unique()).issubset({0, 1}):
        raise ValueError("Expected UCI labels 0 (phishing) and 1 (legitimate).")
    if pd.Series(labels).isna().any():
        raise ValueError("Target labels must not be missing.")
    return pd.Series(labels).eq(0).astype("int8")


def prepare_dataset(dataset_path=DEFAULT_DATASET_PATH):
    frame = load_dataset_frame(dataset_path)
    duplicate_url_rows_removed = frame.attrs["duplicate_url_rows_removed"]
    source_rows = frame.attrs["source_rows"]
    source_class_distribution = frame.attrs["source_class_distribution"]

    feature_rows = [
        analyze_url(url)["features"]
        for url in frame["URL"]
    ]
    features = pd.DataFrame.from_records(feature_rows)
    if features.empty or not np.isfinite(features.to_numpy(dtype=float)).all():
        raise ValueError("URL features must be non-empty and finite.")

    labels = map_phishing_labels(frame["label"])
    groups = frame["Domain"].astype(str).str.strip().str.lower()
    if groups.eq("").any():
        raise ValueError("Dataset domain groups must not be empty.")
    urls = frame["URL"].astype(str)
    archive_sha256 = sha256_file(dataset_path)

    metadata = {
        "name": DATASET_NAME,
        "id": DATASET_ID,
        "source": DATASET_SOURCE,
        "license": DATASET_LICENSE,
        "retrieved_date": DATASET_RETRIEVED_DATE,
        "archive_sha256": archive_sha256,
        "version": archive_sha256,
        "rows_before_url_deduplication": source_rows,
        "rows_after_url_deduplication": len(frame),
        "duplicate_url_rows_removed": duplicate_url_rows_removed,
        "class_distribution_before_url_deduplication": source_class_distribution,
        "class_distribution_after_url_deduplication": class_distribution(labels),
        "original_label_mapping": {
            "0": "phishing",
            "1": "legitimate"
        },
        "model_label_mapping": {
            "0": "legitimate",
            "1": "phishing"
        }
    }
    return features, labels, groups, urls, metadata


def class_distribution(labels):
    labels = pd.Series(labels)
    return {
        "legitimate": int(labels.eq(0).sum()),
        "phishing": int(labels.eq(1).sum())
    }


def domain_group_split(labels, groups, n_splits=5, fold=0):
    labels = np.asarray(labels, dtype=int)
    groups = np.asarray(groups, dtype=str)
    if len(labels) != len(groups):
        raise ValueError("Labels and domain groups must have the same length.")
    if len(np.unique(groups)) < n_splits:
        raise ValueError("There must be at least one domain per split fold.")
    if fold < 0 or fold >= n_splits:
        raise ValueError("Fold index must be within the configured split range.")

    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=42
    )
    train_indices, test_indices = list(
        splitter.split(np.zeros(len(labels)), labels, groups)
    )[fold]

    if set(labels[train_indices]) != {0, 1} or set(labels[test_indices]) != {0, 1}:
        raise ValueError(
            "Domain-grouped split must include both classes in train and test."
        )
    if set(groups[train_indices]).intersection(groups[test_indices]):
        raise ValueError("Domain leakage detected between train and test folds.")

    return train_indices, test_indices


def check_split_overlap(urls, groups, train_indices, test_indices):
    urls = pd.Series(urls).astype(str).str.strip().str.lower()
    groups = pd.Series(groups).astype(str).str.strip().str.lower()
    train_urls = set(urls.iloc[train_indices])
    test_urls = set(urls.iloc[test_indices])
    train_groups = set(groups.iloc[train_indices])
    test_groups = set(groups.iloc[test_indices])
    overlap = {
        "url_overlap_count": len(train_urls.intersection(test_urls)),
        "domain_overlap_count": len(train_groups.intersection(test_groups))
    }
    if any(overlap.values()):
        raise ValueError(f"Train/test record overlap detected: {overlap}")
    return overlap


def classification_metrics(actual, predicted):
    precision, recall, f1_score, _ = precision_recall_fscore_support(
        actual,
        predicted,
        average="binary",
        pos_label=1,
        zero_division=0
    )
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    return {
        "positive_class": "phishing",
        "positive_class_label": 1,
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1_score),
        "confusion_matrix_labels": [0, 1],
        "confusion_matrix": matrix.tolist()
    }
