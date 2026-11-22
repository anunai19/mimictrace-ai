# MimicTrace AI

**AI-Assisted Website Impersonation and Phishing Detection**

MimicTrace AI is a research-oriented web application designed to help identify potentially deceptive websites by analyzing URL, domain, infrastructure, page content, and visual evidence.

It combines multiple detection signals to provide a more informative assessment than relying on a single URL-based prediction.

## Problem Statement

Phishing and website impersonation attacks use deceptive domains, copied branding, suspicious redirects, and misleading page content to trick users.

A single detection signal may not be sufficient to identify these threats. MimicTrace AI explores a multi-signal approach that combines technical and visual evidence to assess potentially suspicious websites.

## Key Features

- URL analysis for suspicious URL characteristics.
- Domain and DNS intelligence.
- Certificate-related analysis.
- HTML and page-content inspection.
- Brand and visual similarity analysis.
- Evidence-based signal combination.
- Deeper analysis through a separate API endpoint.
- Optional machine-learning URL classification.

## How It Works

The application accepts a website URL and analyzes available signals.

The detection workflow can examine:

1. URL structure and suspicious patterns.
2. Domain and DNS information.
3. Certificate information.
4. Website HTML and page characteristics.
5. Visual and brand-related evidence.
6. Combined evidence to support an overall assessment.

Some checks depend on external network access and the availability of the target website.

## Technology Stack

- Python
- Flask
- HTML, CSS, and JavaScript
- scikit-learn
- NumPy and pandas
- Beautiful Soup
- Requests
- dnspython
- NetworkX
- Pillow

See `requirements.txt` for the project's Python dependencies.

## Project Structure

```text
mimictrace-ai/
├── app/
│   ├── routes.py
│   ├── templates/
│   └── static/
├── detection/
├── intelligence/
├── models/
├── docs/
│   ├── architecture.md
│   └── research_notes.md
├── tests/
├── reports/
├── requirements.txt
├── run.py
└── README.md
```

## Installation and Setup

### Windows (PowerShell)

Clone the repository:

```powershell
git clone YOUR_REPOSITORY_URL
cd mimictrace-ai
```

Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Start the application:

```powershell
python run.py
```

Open the application in your browser:

```text
http://127.0.0.1:5000
```

### Linux and macOS

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd mimictrace-ai
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies and start the application:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000` in your browser.

## API Endpoints

The Flask application currently exposes these primary endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Serves the application interface |
| POST | `/api/analyze` | Performs the primary website analysis |
| POST | `/api/analyze/deeper` | Performs additional analysis |

For exact request fields and response structures, refer to the current Flask route implementation in `app/routes.py`.

## Machine-Learning Model

The machine-learning URL classifier is an optional component.

The application is designed to handle model unavailability gracefully. If the model artifact is absent or cannot be loaded, machine-learning prediction may be reported as unavailable while other detection functionality remains available.

The model artifact is not included in the initial public repository release because its exact training-run provenance has not been conclusively established.

## Dataset Attribution

The research implementation references the PhiUSIIL Phishing URL (Website) dataset from the UCI Machine Learning Repository.

**Citation:**

Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website)* [Dataset]. UCI Machine Learning Repository.

https://doi.org/10.1016/j.cose.2023.103545

Dataset licence: [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

The dataset is not bundled with this initial public repository release.

## Running Tests

Run the test suite from the project root:

```powershell
python -m unittest discover -s tests -v
```

Test results should be verified against the current repository state before reporting them as a release result.

## Research Documentation

Additional technical and research information is available in:

- `docs/architecture.md` — application architecture.
- `docs/research_notes.md` — dataset research, evaluation considerations, limitations, and provenance notes.

## Limitations

- Detection results are assessments, not guarantees.
- A legitimate website may produce suspicious signals, and a phishing website may evade detection.
- External DNS, certificate, and website checks depend on network availability.
- Visual similarity and brand detection can produce false positives and false negatives.
- Machine-learning predictions are optional and depend on the availability of a compatible model artifact.
- The project has not been established as production-ready or independently validated for real-world security operations.

**Use this project as a research and educational tool, not as a substitute for browser security controls or professional security review.**

## Licence

The source-code licence for this repository has **not yet been finalized**.

No repository-level open-source licence is being declared at this stage. The dataset licence described above applies to the referenced UCI dataset and does not automatically determine the licence of this project's original source code.

## Project Status

MimicTrace AI is an ongoing research and development project focused on multi-signal website impersonation and phishing detection.
