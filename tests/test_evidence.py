import json
import unittest

from detection.evidence import EvidenceRecord


class TestEvidenceRecord(unittest.TestCase):

    def test_valid_record_serializes_to_json_safe_data(self):
        record = EvidenceRecord(
            source="url_analysis",
            observation={"features": {"uses_https": 1, "url_length": 24}},
            status="observed",
            uncertainty=["URL features do not verify page content."],
        )

        encoded = record.to_json()
        decoded = json.loads(encoded)

        self.assertEqual(decoded, record.to_dict())
        self.assertEqual(decoded["status"], "observed")
        self.assertEqual(
            decoded["uncertainty"],
            ["URL features do not verify page content."]
        )

    def test_all_supported_status_values_are_accepted(self):
        for status in ("observed", "unavailable", "error", "not_run"):
            with self.subTest(status=status):
                EvidenceRecord(
                    source="dns",
                    observation={},
                    status=status,
                    uncertainty=[],
                )

    def test_invalid_source_status_and_uncertainty_are_rejected(self):
        invalid_records = (
            {"source": "", "observation": {}, "status": "observed", "uncertainty": []},
            {"source": "dns", "observation": {}, "status": "unknown", "uncertainty": []},
            {"source": "dns", "observation": {}, "status": "observed", "uncertainty": "not a list"},
            {"source": "dns", "observation": {}, "status": "observed", "uncertainty": [""]},
        )
        for values in invalid_records:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    EvidenceRecord(**values)

    def test_unserializable_or_non_finite_observation_is_rejected(self):
        invalid_observations = (
            {"value": object()},
            {"value": float("nan")},
            {1: "non-string object key"},
        )
        for observation in invalid_observations:
            with self.subTest(observation=observation):
                with self.assertRaises(ValueError):
                    EvidenceRecord(
                        source="test",
                        observation=observation,
                        status="observed",
                        uncertainty=[],
                    )

    def test_circular_observation_is_rejected(self):
        observation = {}
        observation["self"] = observation

        with self.assertRaises(ValueError):
            EvidenceRecord(
                source="test",
                observation=observation,
                status="observed",
                uncertainty=[],
            )


if __name__ == "__main__":
    unittest.main()
