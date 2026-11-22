import unittest

import pandas as pd

from models.model_utils import (
    classification_metrics,
    check_split_overlap,
    domain_group_split,
    map_phishing_labels
)


class TestModelUtils(unittest.TestCase):

    def test_map_phishing_label_to_positive_class(self):
        mapped = map_phishing_labels(pd.Series([0, 1, 0]))

        self.assertEqual(mapped.tolist(), [1, 0, 1])

    def test_domain_group_split_keeps_domains_separate(self):
        labels = pd.Series([0, 0, 1, 1, 0, 0, 1, 1])
        groups = pd.Series([
            "legitimate-a", "legitimate-a",
            "phishing-a", "phishing-a",
            "legitimate-b", "legitimate-b",
            "phishing-b", "phishing-b"
        ])

        train_indices, test_indices = domain_group_split(
            labels,
            groups,
            n_splits=2
        )

        self.assertTrue(
            set(groups.iloc[train_indices]).isdisjoint(
                set(groups.iloc[test_indices])
            )
        )
        self.assertEqual(set(labels.iloc[train_indices]), {0, 1})
        self.assertEqual(set(labels.iloc[test_indices]), {0, 1})

    def test_classification_metrics_report_phishing_as_positive(self):
        metrics = classification_metrics(
            actual=[1, 1, 0, 0],
            predicted=[1, 0, 0, 1]
        )

        self.assertEqual(metrics["positive_class"], "phishing")
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["f1_score"], 0.5)
        self.assertEqual(metrics["confusion_matrix"], [[1, 1], [1, 1]])

    def test_split_overlap_check_rejects_repeated_urls_across_folds(self):
        with self.assertRaisesRegex(ValueError, "overlap detected"):
            check_split_overlap(
                urls=["https://example.com", "https://example.com"],
                groups=["example.com", "example.com"],
                train_indices=[0],
                test_indices=[1]
            )


if __name__ == "__main__":
    unittest.main()
