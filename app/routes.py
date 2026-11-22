import threading

from flask import Blueprint, current_app, render_template, request, jsonify
from detection.url_analyzer import analyze_url
from detection.evidence import EvidenceRecord
from detection.brand_analyzer import analyze_brand_impersonation
from detection.html_analyzer import analyze_html_document
from detection.html_fetcher import fetch_html
from detection.visual_analyzer import (
    InvalidLogoImageError,
    LogoImageLimitError,
    MAX_LOGO_IMAGE_BYTES,
    analyze_logo_crop,
)
from intelligence.certificate_analysis import analyze_tls_certificate
from intelligence.dns_lookup import lookup_dns
from intelligence.domain_lookup import lookup_domain_registration
from intelligence.relationship_graph import analyze_relationship_graph
from detection.evidence_fusion import fuse_evidence
from models.predict_model import (
    ModelPredictionError,
    ModelUnavailableError,
    predict_url_features
)

main = Blueprint("main", __name__)

# This bounds concurrent lookups per worker process; it is not distributed.
_DEEPER_ANALYSIS_SLOTS = threading.BoundedSemaphore(value=2)
_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def _error_evidence(source, availability):
    return EvidenceRecord(
        source=source,
        observation={"availability": availability},
        status="error",
        uncertainty=["Analysis failed; internal error details are omitted."],
    ).to_dict()


def _safe_evidence_call(callback, source):
    try:
        record = callback()
        if not isinstance(record, EvidenceRecord):
            raise TypeError("Intelligence module returned an invalid evidence record.")
        return record.to_dict()
    except Exception:
        current_app.logger.exception("Deeper analysis module failed: %s", source)
        return _error_evidence(source, "error")


def _safe_dns_evidence(url):
    try:
        records = lookup_dns(url)
    except Exception:
        current_app.logger.exception("Deeper analysis module failed: dns")
        return {
            record_type: _error_evidence(
                f"dns.{record_type.lower()}",
                "error",
            )
            for record_type in _DNS_RECORD_TYPES
        }

    evidence = {}
    for record_type in _DNS_RECORD_TYPES:
        source = f"dns.{record_type.lower()}"
        try:
            record = records[record_type]
            if not isinstance(record, EvidenceRecord):
                raise TypeError("DNS lookup returned an invalid evidence record.")
            evidence[record_type] = record.to_dict()
        except Exception:
            current_app.logger.exception(
                "Deeper analysis DNS record failed: %s",
                record_type,
            )
            evidence[record_type] = _error_evidence(source, "error")
    return evidence


def _read_logo_upload(upload):
    chunks = []
    total = 0
    try:
        while total <= MAX_LOGO_IMAGE_BYTES:
            chunk = upload.stream.read(
                min(64 * 1024, MAX_LOGO_IMAGE_BYTES + 1 - total)
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LOGO_IMAGE_BYTES:
                raise LogoImageLimitError()
            chunks.append(chunk)
    except LogoImageLimitError:
        raise
    except (OSError, TypeError, ValueError):
        raise InvalidLogoImageError() from None
    finally:
        upload.close()
    return b"".join(chunks)


def _close_uploaded_files(files):
    if files is None:
        return
    for key in files.keys():
        for upload in files.getlist(key):
            upload.close()


def _analyze_html_url(url):
    result = fetch_html(url)
    if result.status == "observed":
        return analyze_html_document(
            result.content,
            url,
            final_url=result.final_url,
            redirect_count=result.redirect_count,
        )

    unavailable_reasons = {
        "https_required": "HTML retrieval requires HTTPS on port 443.",
        "http_status": "The page did not return a successful HTML response.",
        "unsupported_content_type": "The response content type is not supported HTML.",
        "unsupported_content_encoding": "The response content encoding is not supported.",
    }
    is_unavailable = result.status == "unavailable" or result.availability in {
        "http_status",
        "unsupported_content_type",
        "unsupported_content_encoding",
    }
    return EvidenceRecord(
        source="html.static",
        observation={
            "availability": result.availability,
            "redirect_count": result.redirect_count,
        },
        status="unavailable" if is_unavailable else "error",
        uncertainty=[
            unavailable_reasons.get(
                result.availability,
                "HTML retrieval did not complete; internal details are omitted.",
            ),
            "No page code was executed and no raw response content was returned.",
        ],
    )


@main.route("/")
def home():
    return render_template("index.html")

@main.route("/api/analyze", methods=["POST"])
def analyze():
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Request body must be valid JSON."
        }), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Request body must be a JSON object."
        }), 400

    if "url" not in data:
        return jsonify({
            "success": False,
            "error": "A URL is required."
        }), 400

    url = data["url"]
    if not isinstance(url, str):
        return jsonify({
            "success": False,
            "error": "The URL must be a string."
        }), 400

    if not url.strip():
        return jsonify({
            "success": False,
            "error": "Please enter a URL."
        }), 400

    try:
        result = analyze_url(url)
        try:
            result["prediction"] = predict_url_features(result["features"])
        except ModelUnavailableError:
            result["prediction"] = {
                "status": "unavailable",
                "error": "The prediction model is unavailable."
            }
        except ModelPredictionError:
            result["prediction"] = {
                "status": "unavailable",
                "error": "A model prediction could not be generated."
            }

        return jsonify({
            "success": True,
            "message": "URL features extracted successfully.",
            "analysis": result
        })
    except ValueError as error:
        return jsonify({"success": False, "error": str(error)}), 400
    except Exception:
        return jsonify({
            "success": False,
            "error": "An unexpected analysis error occurred."
        }), 500


@main.route("/api/analyze/deeper", methods=["POST"])
def analyze_deeper():
    logo_upload = None
    multipart_files = None
    if request.is_json:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Request body must be a JSON object."
            }), 400
        url = data.get("url")
    elif request.mimetype == "multipart/form-data":
        form = request.form
        multipart_files = request.files
        if set(form.keys()) != {"url"} or len(form.getlist("url")) != 1:
            _close_uploaded_files(multipart_files)
            return jsonify({
                "success": False,
                "error": "Multipart requests must contain one URL and one optional logo crop."
            }), 400
        file_keys = set(multipart_files.keys())
        uploads = multipart_files.getlist("logo_crop")
        if file_keys - {"logo_crop"} or len(uploads) > 1:
            _close_uploaded_files(multipart_files)
            return jsonify({
                "success": False,
                "error": "Upload exactly one logo crop."
            }), 400
        if uploads:
            logo_upload = uploads[0]
        url = form.get("url")
    else:
        return jsonify({
            "success": False,
            "error": "Request body must be valid JSON or multipart form data."
        }), 400

    if url is None:
        _close_uploaded_files(multipart_files)
        return jsonify({
            "success": False,
            "error": "A URL is required."
        }), 400

    if not isinstance(url, str):
        _close_uploaded_files(multipart_files)
        return jsonify({
            "success": False,
            "error": "The URL must be a string."
        }), 400

    if not url.strip():
        _close_uploaded_files(multipart_files)
        return jsonify({
            "success": False,
            "error": "Please enter a URL."
        }), 400

    try:
        analyze_url(url)
    except ValueError as error:
        _close_uploaded_files(multipart_files)
        return jsonify({"success": False, "error": str(error)}), 400

    if not _DEEPER_ANALYSIS_SLOTS.acquire(blocking=False):
        _close_uploaded_files(multipart_files)
        return jsonify({
            "success": False,
            "error": "Deeper analysis is busy. Please try again shortly."
        }), 503

    try:
        try:
            if logo_upload is None:
                visual_record = analyze_logo_crop()
            else:
                image_bytes = _read_logo_upload(logo_upload)
                visual_record = analyze_logo_crop(
                    image_bytes,
                    filename=logo_upload.filename,
                    content_type=logo_upload.mimetype,
                )
            if not isinstance(visual_record, EvidenceRecord):
                raise TypeError("Visual analyzer returned an invalid evidence record.")
            visual_evidence = visual_record.to_dict()
        except LogoImageLimitError:
            return jsonify({
                "success": False,
                "error": "The uploaded logo crop exceeds the allowed size or dimensions."
            }), 413
        except InvalidLogoImageError:
            return jsonify({
                "success": False,
                "error": "The upload must be a valid static PNG or JPEG logo crop."
            }), 400
        except Exception:
            current_app.logger.error("Logo crop preprocessing failed.")
            visual_evidence = _error_evidence(
                "visual.logo_crop",
                "processing_failed",
            )

        evidence = {
            "html": _safe_evidence_call(
                lambda: _analyze_html_url(url),
                "html.static",
            ),
            "dns": _safe_dns_evidence(url),
            "domain": _safe_evidence_call(
                lambda: lookup_domain_registration(url),
                "domain.whois",
            ),
            "tls": _safe_evidence_call(
                lambda: analyze_tls_certificate(url),
                "tls.certificate",
            ),
            "brand": _safe_evidence_call(
                lambda: analyze_brand_impersonation(url),
                "brand.impersonation",
            ),
            "visual": visual_evidence,
        }
        evidence["relationships"] = _safe_evidence_call(
            lambda: analyze_relationship_graph(evidence),
            "relationship.graph",
        )

        # --- Evidence fusion: aggregate all signals into a risk assessment --
        try:
            url_analysis = analyze_url(url)
            prediction_obj = None
            try:
                prediction_obj = predict_url_features(url_analysis["features"])
            except (ModelUnavailableError, ModelPredictionError):
                pass
            fusion_input = dict(evidence)
            fusion_input["analysis"] = {
                "features": url_analysis.get("features"),
                "prediction": prediction_obj,
            }
            risk_assessment = fuse_evidence(fusion_input)
        except Exception:
            current_app.logger.exception("Evidence fusion failed.")
            risk_assessment = {
                "risk_score": 0,
                "risk_level": "inconclusive",
                "verdict": "inconclusive",
                "evidence_sufficiency": "limited",
                "assessment_state": "inconclusive",
                "contributing_indicators": [],
                "negative_indicators": [],
                "evidence_summary": {
                    "source_statuses": {},
                    "positive_signal_count": 0,
                    "negative_signal_count": 0,
                },
                "recommended_actions": [
                    "Evidence is insufficient to verify the authenticity of this website. Do not enter credentials until verified.",
                    "Risk assessment could not be completed. Verify the website URL and TLS certificate directly in your browser before entering credentials.",
                ],
                "limitations": ["Evidence fusion failed; unable to generate a conclusive risk assessment."],
            }

        response_body = {
            "success": True,
            "message": "Deeper analysis completed.",
            "evidence": evidence,
            "risk_assessment": risk_assessment,
        }

        return jsonify(response_body)
    except Exception:
        current_app.logger.exception("Unexpected deeper analysis response failure.")
        return jsonify({
            "success": False,
            "error": "An unexpected deeper analysis error occurred."
        }), 500
    finally:
        try:
            if logo_upload is not None:
                logo_upload.close()
        finally:
            _DEEPER_ANALYSIS_SLOTS.release()
