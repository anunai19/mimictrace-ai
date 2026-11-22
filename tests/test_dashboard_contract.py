import unittest
from html.parser import HTMLParser

from app import create_app


class DashboardParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.elements_by_id = {}
        self.script_sources = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        element_id = attributes.get("id")
        if element_id:
            self.elements_by_id[element_id] = (tag, attributes)
        if tag == "script" and attributes.get("src"):
            self.script_sources.append(attributes["src"])


class TestDashboardContract(unittest.TestCase):

    def setUp(self):
        self.client = create_app().test_client()

    def test_existing_dashboard_contains_deeper_analysis_controls(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        parser = DashboardParser()
        parser.feed(response.get_data(as_text=True))

        self.assertIn("scanForm", parser.elements_by_id)
        self.assertIn("websiteUrl", parser.elements_by_id)
        self.assertIn("scanMessage", parser.elements_by_id)

        image_tag, image_attributes = parser.elements_by_id["logoCropInput"]
        self.assertEqual(image_tag, "input")
        self.assertEqual(image_attributes.get("type"), "file")
        self.assertEqual(
            image_attributes.get("accept"),
            "image/png,image/jpeg,.png,.jpg,.jpeg",
        )

        button_tag, button_attributes = parser.elements_by_id[
            "deeperAnalysisButton"
        ]
        self.assertEqual(button_tag, "button")
        self.assertEqual(button_attributes.get("type"), "button")
        self.assertIn("disabled", button_attributes)

        status_tag, status_attributes = parser.elements_by_id[
            "deeperAnalysisStatus"
        ]
        self.assertEqual(status_tag, "p")
        self.assertEqual(status_attributes.get("aria-live"), "polite")
        self.assertIn("deeperAnalysisResults", parser.elements_by_id)
        self.assertIn("/static/js/script.js", parser.script_sources)

    def test_dashboard_script_uses_text_nodes_not_html_insertion(self):
        response = self.client.get("/static/js/script.js")

        self.assertEqual(response.status_code, 200)
        script = response.get_data(as_text=True)
        response.close()
        self.assertIn("textContent", script)
        self.assertIn("createElement", script)
        self.assertNotIn("innerHTML", script)

    def test_primary_analysis_ignores_stale_url_responses(self):
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        primary_handler = script.split(
            'scanForm.addEventListener("submit"',
            1,
        )[1].split(
            'deeperButton.addEventListener("click"',
            1,
        )[0]
        request_sequence_check = primary_handler.index(
            "if (requestId !== primaryRequestId) return;"
        )
        current_url_check = primary_handler.index(
            "if (urlInput.value.trim() !== url) {"
        )
        result_rendering = primary_handler.index("data.analysis.hostname")
        enable_deeper = primary_handler.index("deeperButton.disabled = false;")

        self.assertLess(request_sequence_check, current_url_check)
        self.assertLess(current_url_check, result_rendering)
        self.assertLess(current_url_check, enable_deeper)
        self.assertIn("if (requestId === primaryRequestId)", primary_handler)
        self.assertIn("submitButton.disabled = false;", primary_handler)

    def test_dashboard_includes_relationship_evidence_section(self):
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        self.assertIn(
            '["html", "dns", "domain", "tls", "brand", "visual", "relationships"]',
            script,
        )
        self.assertIn('formData.append("logo_crop", selectedLogo)', script)
        self.assertIn('JSON.stringify({ url })', script)
        self.assertIn("textContent", script)
        self.assertNotIn("innerHTML", script)

    def test_missing_risk_assessment_defaults_to_inconclusive_not_safe(self):
        """When risk_assessment is absent, script must not default to likely_safe/low/legitimate."""
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        # Default level must be "inconclusive", not "low"
        self.assertIn('const level = hasValidAssessment ? riskAssessment.risk_level : "inconclusive";', script)
        # Default verdict must be "inconclusive", not "likely_safe"
        self.assertIn('const verdict = hasValidAssessment ? riskAssessment.verdict : "inconclusive";', script)
        # Default score must be null (unknown), not 0 presented as confirmed low-risk
        self.assertIn('const score = hasValidAssessment ? riskAssessment.risk_score : null;', script)

    def test_inconclusive_level_chip_shows_inconclusive_not_low_risk(self):
        """When verdict is inconclusive, level chip text must be INCONCLUSIVE, never LOW RISK."""
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        self.assertIn('const isInconclusive = verdict === "inconclusive" || assessmentState === "inconclusive";', script)
        self.assertIn('const levelChipText = isInconclusive ? "INCONCLUSIVE"', script)

    def test_evidence_sources_count_not_hardcoded_seven(self):
        """The EVIDENCE SOURCES count must be derived from evidence_summary, not hardcoded to 7."""
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        self.assertNotIn('"7 TELEMETRY"', script)
        self.assertIn('observedSourceCount', script)
        self.assertIn('status === "observed"', script)

    def test_assessment_state_used_for_inconclusive_detection(self):
        """assessment_state must be read from riskAssessment and used for inconclusive display."""
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        self.assertIn('const assessmentState = hasValidAssessment', script)
        self.assertIn('riskAssessment.assessment_state', script)
        self.assertIn('assessmentState === "inconclusive"', script)

    def test_inconclusive_shows_coverage_limitations(self):
        """Inconclusive assessments display backend-reported coverage limitations."""
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        self.assertIn("Coverage Limitations", script)
        self.assertIn("riskAssessment.limitations", script)

    def test_score_not_presented_as_safety_proof(self):
        """Score of 0 with inconclusive verdict must not be presented as proof of safety."""
        response = self.client.get("/static/js/script.js")
        script = response.get_data(as_text=True)
        response.close()

        self.assertIn('scoreIsUnknown', script)
        self.assertIn('text-warn', script)


if __name__ == "__main__":
    unittest.main()
