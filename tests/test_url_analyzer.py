import unittest

from detection.url_analyzer import analyze_url


class TestURLAnalyzer(unittest.TestCase):

    def test_valid_https_url(self):
        result = analyze_url("https://example.com")

        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["features"]["uses_https"], 1)

    def test_url_with_login_path(self):
        result = analyze_url("https://example.com/login")

        self.assertEqual(
            result["features"]["suspicious_keyword_count"], 1
        )

    def test_ip_address_detection(self):
        result = analyze_url("http://192.0.2.1/login")

        self.assertEqual(
            result["features"]["uses_ip_address"], 1
        )

    def test_empty_url(self):
        with self.assertRaises(ValueError):
            analyze_url("")

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            analyze_url("https://")

    def test_http_url(self):
        result = analyze_url("http://example.com")

        self.assertEqual(result["features"]["uses_https"], 0)


if __name__ == "__main__":
    unittest.main()
