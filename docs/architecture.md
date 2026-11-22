# MimicTrace AI — Architecture Document

## A. Project Overview and Purpose

MimicTrace AI is a Flask-based research and demonstration application for website impersonation and phishing detection. It analyzes submitted URLs using multiple evidence sources and combines available signals into an explainable risk assessment.

The application is designed for local research and demonstration, not as a production security service. Its assessment is intended to support investigation rather than guarantee whether a website is safe or malicious.

Key characteristics:

- Flask application with primary and deeper URL-analysis endpoints.
- Evidence collection from HTML, DNS, domain registration, TLS, brand analysis, visual analysis, and relationship analysis.
- Explainable evidence fusion with risk scores, verdicts, evidence sufficiency, and limitations.
- Optional machine-learning prediction. The application can continue its evidence-based analysis when the model is unavailable.

## B. High-Level Component Architecture

The application is organized into the following logical layers.

### 1. Flask application layer (`app/`)

- `app/__init__.py` creates the Flask application, configures the request-size limit, and registers the main blueprint.
- `app/routes.py` defines the homepage and analysis endpoints:
  - `GET /` serves the application interface.
  - `POST /api/analyze` performs primary URL analysis.
  - `POST /api/analyze/deeper` collects additional evidence and produces a fused assessment.
- `app/templates/` contains the HTML interface.
- `app/static/` contains frontend JavaScript and CSS.

### 2. Detection layer (`detection/`)

This layer analyzes URL characteristics and website content.

Its responsibilities include:

- Extracting URL-derived features.
- Inspecting fetched HTML for relevant indicators.
- Checking brand impersonation and Unicode-related indicators.
- Processing an optional uploaded logo image.
- Representing analysis results through structured evidence records.
- Combining signals through the evidence-fusion engine.

### 3. Intelligence layer (`intelligence/`)

This layer provides external information used during deeper analysis:

- DNS record lookup.
- Domain registration information.
- TLS certificate analysis.
- Relationship-graph analysis using collected evidence.

These operations depend on external data or network access and may be unavailable or fail.

### 4. Model layer (`models/`)

- `models/predict_model.py` loads and validates the optional prediction artifact and performs URL-feature inference.
- `models/model_utils.py` provides dataset and model-related utilities.
- `models/train_model.py` contains model-training functionality.
- `models/provenance.py` supports training-run provenance and manifest handling.
- Evaluation modules support model assessment.

The prediction model is optional and is not the sole basis of the application's final assessment.

### 5. Tests and documentation

- `tests/` contains automated tests for application behavior and individual components.
- `docs/` contains project architecture and research documentation.

## C. Request and Analysis Flow

### Primary analysis

The primary endpoint is `POST /api/analyze`.

At a high level, it:

1. Checks that the request contains valid JSON and an acceptable URL value.
2. Analyzes the submitted URL and extracts URL-derived features.
3. Attempts optional machine-learning prediction using the extracted features.
4. Returns the primary analysis result.

The primary endpoint is distinct from deeper analysis and does not itself perform the complete evidence-fusion workflow.

### Deeper analysis

The deeper endpoint is `POST /api/analyze/deeper`.

Its workflow is:

1. Validate and process the submitted URL and any supported optional logo-image input.
2. Collect HTML evidence.
3. Collect DNS evidence.
4. Retrieve domain-registration evidence.
5. Analyze TLS certificate evidence.
6. Analyze brand-impersonation indicators.
7. Process visual evidence when a logo image is supplied and successfully analyzed.
8. Analyze relationships using the collected evidence.
9. Extract URL features and attempt optional model prediction.
10. Pass the collected evidence and available analysis results to `fuse_evidence()`.
11. Return the collected evidence and risk assessment.

The evidence collection is designed to handle individual source failures. An unavailable source does not automatically mean that the target website is malicious or safe.

## D. Component Responsibilities

### Flask routes

The route layer validates incoming requests, coordinates analysis components, handles errors, and returns JSON responses.

### Evidence records

`detection/evidence.py` defines the structured evidence representation. Evidence records distinguish statuses such as:

- `observed`: evidence was successfully collected.
- `unavailable`: the source could not provide the requested evidence.
- `error`: an operation encountered an error.
- `not_run`: the relevant analysis was not performed.

A source that is unavailable or has failed must not be treated as if it produced a clean result.

### URL and content analysis

Detection modules inspect URL characteristics, fetched page content, brand indicators, and optional visual input. They produce evidence and signals for the assessment engine rather than independently determining the final verdict.

### Intelligence modules

DNS, domain-registration, TLS, and relationship-analysis components provide additional context. Their results depend on the availability and quality of external information.

### Optional machine-learning prediction

`models/predict_model.py` uses a cached model-loading function. It checks that the saved artifact contains the expected model, feature names, and dataset metadata.

The expected label mapping is:

- `0`: legitimate
- `1`: phishing

If the model artifact is missing, invalid, or cannot be used for prediction, the corresponding model errors are handled by the route. The application can continue without an available prediction.

The model output is an estimate, not a guaranteed security verdict.

## E. Evidence Combination into Final Assessment

The main assessment engine is `detection/evidence_fusion.py`.

It combines positive and negative indicators from available evidence sources. The engine groups signals and applies group-specific caps before calculating the overall score.

The configured group caps are:

| Signal group | Maximum contribution |
|---|---:|
| Brand | 30 |
| HTML | 28 |
| URL | 18 |
| Domain | 15 |
| Machine learning | 12 |
| TLS | 15 |
| Relationship graph | 10 |

Negative indicators adjust the score. The final score is clamped to the range 0–100.

### Risk levels

| Risk score | Risk level |
|---|---|
| 0–24 | Low |
| 25–49 | Moderate |
| 50–74 | High |
| 75–100 | Critical |

These values represent heuristic signal strength. They are not probabilities.

### Evidence sufficiency

Evidence sufficiency is calculated from observed sources:

- HTML
- Brand
- Domain
- TLS
- DNS, counted once when at least one DNS record is observed

The thresholds are:

- Four or more observed sources: `sufficient`
- Two or three observed sources: `partial`
- Fewer than two observed sources: `limited`

This measures the amount of collected evidence, not its reliability or correctness. Sufficient evidence does not guarantee that a website is safe.

### Verdict generation

The `_verdict()` function applies the following decision order:

1. A score of 75 or higher produces `high_risk`.
2. A score of 50 or higher, or the presence of a critical suspicious signal, produces `suspicious`.
3. Limited evidence sufficiency produces `inconclusive`.
4. A score of 25 or higher, or the presence of any positive signal, produces `low_concern`.
5. With sufficient evidence, an unobserved HTML source produces `inconclusive`; otherwise the verdict is `likely_safe`.
6. With partial evidence, a negative signal indicating verified TLS or an established domain can support `likely_safe` only when HTML evidence is also observed. If that condition is not met, the verdict is `inconclusive`.
7. Other partial-evidence cases produce `low_concern`.

Critical suspicious signals include:

- `brand_unicode_confusable`
- `brand_mixed_scripts`
- `html_cross_domain_form`

The implementation also adjusts the returned risk level to `inconclusive` when the final verdict is inconclusive.

The assessment includes supporting indicators, negative indicators, evidence summaries, recommended actions, and limitations. This makes the result more interpretable than a score alone.

## F. Important Limitations

1. **Optional model artifact:** Machine-learning prediction depends on a valid local model artifact. Its absence does not disable the other analysis components.

2. **Network dependencies:** HTML fetching, DNS, TLS, and domain-registration analysis depend on external services and network conditions. Failures can result from timeouts, unavailable services, or other connectivity problems.

3. **Optional visual analysis:** Visual evidence depends on supported logo-image input and successful processing. It is not necessarily available for every analysis.

4. **Incomplete evidence:** Missing or unavailable evidence reduces the information available to the assessment engine. It must not be interpreted as proof that a website is safe.

5. **Heuristic risk scores:** Risk scores and thresholds are implementation-defined indicators, not calibrated probabilities or guarantees of detection.

6. **Evidence sufficiency:** The sufficiency classification measures observed-source coverage. It does not independently establish evidence quality or website legitimacy.

7. **Model limitations:** Model predictions depend on the trained artifact, its feature schema, and the data used during training. Predictions should not be treated as definitive security decisions.

8. **Local demonstration scope:** The application is intended for local research and demonstration. The Flask development configuration is not a substitute for production deployment, security hardening, or operational monitoring.

9. **No definitive guarantee:** MimicTrace AI does not guarantee detection of every phishing or impersonation technique and should not replace professional security review.

## G. Summary

MimicTrace AI combines URL analysis, website evidence collection, external intelligence, optional visual analysis, optional machine-learning prediction, and explainable evidence fusion.

Its deeper-analysis workflow brings these sources together to produce a risk score, risk level, verdict, evidence-sufficiency classification, and supporting explanations.

The system is designed to handle unavailable evidence and optional model prediction without treating missing information as proof of safety. Its scores are heuristic indicators, and its results are intended for research and demonstration rather than definitive production security decisions.
