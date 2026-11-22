# Independent Dataset Generalization Validation

Review started: 2026-11-15; source follow-up: 2026-11-16. This is a source review and evaluation plan only. No external dataset was downloaded, no training or inference experiment was run, and no model, Flask, or application code was changed.

## Existing model and evaluation constraints

- The saved `models/phishing_url_model.joblib` artifact contains a fitted `StandardScaler` + `LogisticRegression` pipeline, its feature order, dataset metadata, grouped split metadata, and the original evaluation results.
- Current saved-artifact SHA-256: `80B646B4AE1B90EE2A80D0214D2A175A05B0E75562FF1FD85D26AE32CD4FEE3E` (3,393 bytes; last modified 2026-11-15 23:33:46). The hash was recomputed and matches the previously observed value; no model write or retraining was performed.
- Its ten URL-derived features are: `url_length`, `hostname_length`, `path_length`, `dot_count`, `hyphen_count`, `at_symbol_count`, `digit_count`, `uses_https`, `uses_ip_address`, and `suspicious_keyword_count`.
- Model labels are `0 = legitimate` and `1 = phishing`. The source UCI labels were inverted from `0 = phishing` and `1 = legitimate`.
- The training source is UCI PhiUSIIL dataset 967, archive SHA-256 `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a`. The archive contains 235,795 rows before URL deduplication and has no timestamp column.
- `models/evaluate_model.py` is intentionally tied to the training dataset: it calls `prepare_dataset`, requires the archive hash to equal the artifact's training hash, checks the training feature schema, and evaluates the existing grouped holdout. It cannot evaluate an unrelated dataset directly.
- The stored original LogisticRegression holdout result is phishing precision `0.9984`, recall `0.9857`, F1 `0.9920`, and confusion matrix `[[26939, 31], [287, 19817]]`, with labels `[0 = legitimate, 1 = phishing]`. This is one grouped holdout, not an independent or temporal result.

## Candidate source review

### PhishTank verified feed

The official [developer documentation](https://phishtank.org/developer_info.php) describes hourly-updated CSV/XML/JSON feeds. The `online-valid` CSV schema includes `url`, `submission_time`, `verified`, `verification_time`, `online`, `target`, and identifiers. The published feed contains entries with `verified=yes` and `online=yes`; the label is therefore a community-verified phishing URL that was online at the feed snapshot, not an immutable ground truth.

The official [terms page](https://phishtank.org/terms.php) points to the current Cisco End User License Agreement and also contains archived terms. Those archived terms discuss use of PhishTank “Data,” but the current page does not provide a simple standalone open-data license for this feed. Do not assume open redistribution or long-term retention rights; review current terms and confirm the intended academic evaluation use before acquisition. Automated feed downloads require an application key for regular access.

Assessment: strong candidate for timestamped phishing positives if the current terms permit the intended use. The required timestamps and verification fields are documented. A separate, defensible legitimate control set is still needed.

### OpenPhish Academic Use Program

The official [Academic Use Program](https://openphish.com/academic_use.html) offers an approved academic user a real-time phishing feed and a 30-day archive. Access requires an accredited academic affiliation and application from an academic email; access is time-limited (60 days), data use must be non-commercial, attribution is required, and sharing the data with third parties is prohibited. The [terms](https://openphish.com/terms.html) state that the service information is proprietary and provide no general open-data license.

The public program page does not specify the archive's per-record timestamp and verification schema. Confirm those fields and the evaluation/retention terms with OpenPhish before relying on this source. Do not redistribute its records.

Assessment: a plausible independently sourced, recent phishing-positive set if access is granted and record timestamps/labels meet the evaluation requirements. It is not yet a confirmed dataset for this project.

### Tranco historical lists

The [Tranco project](https://tranco-list.eu/) offers daily, reproducible top-domain lists, permanent list identifiers, historical snapshots, and exact update/Last-Modified information. This provides a timestamped sampling frame, not URL-level truth labels: ranking or popularity does not prove that a domain or URL is benign.

Tranco's attribution notes list upstream providers with differing terms, including CC BY 3.0, CC BY-SA 4.0, and CC BY-NC 4.0 sources. No single blanket license for every combined list should be assumed. A Tranco snapshot may help identify candidate benign controls only after independent verification of each control and review of the applicable source terms.

Tranco is domain-level rather than observed-URL data. Passing a bare domain to the current analyzer synthesizes an `https://` root URL, so its scheme/path features would not represent an observed URL. Do not treat that transformation as a comparable benign URL sample.

### Common Crawl URL index

The [Common Crawl URL index](https://index.commoncrawl.org/) provides archived URL records associated with crawl collections, and the [crawl archive list](https://commoncrawl.org/get-started) is dated. This is a timestamped URL corpus, not a benign/phishing-labeled benchmark. Crawl presence does not establish that a URL was safe or legitimate at that time.

Common Crawl's [terms of use](https://commoncrawl.org/terms-of-use) grant limited access/use of its service and warn that crawled content may carry separate website-owner terms; they also disclaim the truth or accuracy of crawled content. The crawl/index should therefore be considered a candidate source for time-bounded URL sampling only, not a source of ground-truth benign labels or a blanket license for underlying page content.

### ISCX-URL-2016 (secondary historical candidate)

The [UNB dataset description](https://www.unb.ca/cic/datasets/url-2016.html) reports phishing URLs sourced from OpenPhish and benign URLs collected from Alexa-ranked sites and filtered through VirusTotal. The page does not document per-record timestamps or a clear dataset license. Its phishing source also overlaps with OpenPhish, and the collection is historical rather than a post-training temporal holdout.

Assessment: potentially useful only as a separately licensed, historical cross-dataset comparison after schema and reuse terms are verified; it does not meet the primary timestamped-test objective as currently documented.

## Compatibility and proposed validation protocol

1. **Freeze the model.** Record the artifact SHA-256 and exact freeze time before collecting any test records. Do not run `models.train_model`, call `.fit`, tune thresholds, or alter the saved artifact. Use only records with source event timestamps after the freeze time for a forward-time claim.
2. **Acquire only after approval.** Select an approved source, confirm its current license/terms and allowed retention, record its citation, access time, version/snapshot ID, and file hash. Keep restricted raw records local and do not redistribute them. A 30-day post-freeze collection window is a candidate design, subject to source access and terms.
3. **Require a defensible binary label.** Map verified phishing records to `1`. Do not label a Tranco rank alone as legitimate; first establish an independently validated benign control set with compatible dates. Report provider verification and `online` status as part of the cohort definition.
4. **Prepare features without fitting.** Validate URL strings and run the existing `detection.url_analyzer.analyze_url(url)["features"]`. Require the exact ten names and artifact order. Let the already-fitted serialized pipeline apply its scaler and predict; do not fit preprocessing or classification on the independent test set. Report invalid/excluded URL counts and reasons.
5. **Deduplicate and check overlap.** Deduplicate normalized exact URLs within the candidate test set. Compare against all URLs in the original UCI archive and report exact URL overlap; exclude exact training URL duplicates from the independent cohort. Also report hostname/registrable-domain overlap with UCI and provide a separate strict unseen-domain result where feasible. Report overlaps between external sources and duplicate/conflicting labels.
6. **Evaluate per source and cohort.** Report sample counts, source/time window, class distribution, phishing precision, recall and F1, and confusion matrix with actual rows/predicted columns and labels `[0 = legitimate, 1 = phishing]`. Derive false positives from `actual legitimate, predicted phishing` and false negatives from `actual phishing, predicted legitimate`.
7. **Analyze errors safely.** Review false-positive and false-negative patterns offline using feature summaries and source/label metadata. Do not visit live phishing URLs. Avoid publishing full active malicious URLs or restricted source records.
8. **Compare with the original holdout.** Present original and independent metrics side by side, including their class distributions, cohort dates, and confusion matrices. Explain that differences in source, time, label policy, and prevalence limit direct comparability. Do not claim generalization until actual independent predictions and counts are produced.

## Initial evaluation-only runner design (before implementation)

The initial design proposed `models/evaluate_external.py`; the runner is now implemented as documented in the final section below. Source-specific schema and use terms remain unresolved until acquisition is separately approved.

- Accept only a locally supplied, already approved and harmonized CSV. Require URL, normalized binary label (`phishing`/`legitimate`), source, source-native label/status, source event timestamp, and snapshot/record identifier fields. Preserve source-native values for provenance; never infer a label from a domain ranking or absence from a threat feed.
- Require the caller to provide the model freeze timestamp and source/version metadata. Reject or separately count records whose event timestamp is not after the freeze time.
- Load the existing artifact read-only, verify the expected feature schema and phishing mapping, generate features using `analyze_url`, arrange columns in serialized feature order, and invoke only the fitted pipeline's `.predict()`.
- Do not import or call any training function; do not call `.fit()`, `.fit_transform()`, or `joblib.dump()`; do not change the artifact or its in-memory fitted parameters. Write any report to a separate, user-selected JSON path, never to the model path.
- Record the artifact SHA-256 before and after the evaluation and fail if it changes. Include source/snapshot/hash, sample and exclusion counts, time window, exact URL overlap, hostname/domain overlap, class distribution, phishing metrics, confusion matrix, and false-positive/false-negative counts in the report.
- Preserve the original UCI holdout metrics as a fixed comparison reference. Do not run external evaluation until source acquisition and legitimate-label provenance are approved.

## Initial review status (before DeepURLBench follow-up)

No candidate has yet been acquired or evaluated. The principal unresolved items are source-use approval/current license terms and a reliable timestamped legitimate control set. No independent-dataset performance metrics or error counts exist. Obtain the user's source and acquisition approval before any download or evaluator implementation.

## References

- [PhishTank developer feed documentation](https://phishtank.org/developer_info.php)
- [PhishTank terms](https://phishtank.org/terms.php)
- [OpenPhish Academic Use Program](https://openphish.com/academic_use.html)
- [OpenPhish terms](https://openphish.com/terms.html)
- [Tranco](https://tranco-list.eu/)
- [Common Crawl URL index](https://index.commoncrawl.org/)
- [Common Crawl terms of use](https://commoncrawl.org/terms-of-use)
- [UNB ISCX-URL-2016](https://www.unb.ca/cic/datasets/url-2016.html)

## Follow-up research — DeepURLBench and legitimate controls

Reviewed the official [DeepURLBench repository](https://github.com/deepinstinct-algo/DeepURLBench), its [README](https://github.com/deepinstinct-algo/DeepURLBench/blob/main/README.md), [LICENSE](https://github.com/deepinstinct-algo/DeepURLBench/blob/main/LICENSE), repository metadata, and the authors' [paper](https://arxiv.org/abs/2501.00356). No parquet data files were downloaded or inspected.

### Provenance, labels, and timestamps

- The paper says the URLs were gathered from public deny-lists and allow-lists during 2020–2023. Labeling is based on VirusTotal vendor verdicts.
- `first_seen` is described as the URL's first appearance in VirusTotal and used as an approximation for when it appeared on the internet. This is a source timestamp, not a guaranteed creation date.
- The paper's heuristic labels phishing/malware URLs only when at least two high-quality vendors unanimously provide non-safe verdicts and the combined quality score exceeds 2.5. URLs not flagged as malicious by those high-quality vendors are assigned benign. It excludes the ambiguous “suspicious” tag and delays labeling by at least two months to allow vendor reputation to build.
- This is substantially better documented than a popularity-based benign proxy, and the maintainers provide a timestamped benign class. However, “benign” means not flagged by the selected vendors, not independently proven safe; false-negative label noise remains possible. Preserve this qualification in any report.
- The paper separates URLs first seen before September 2022 into train/validation and later records into its test set. That is a useful historical temporal cohort, but it does not make this a future test for our model.
- The paper's documented collection period (2020–2023), paper submission (2024-12-31), and latest repository commit (2024-11-27) predate the model artifact's 2026-11-15 serialization-time proxy cutoff. The documented records therefore appear historical relative to the model, not post-cutoff. Because no Parquet rows were inspected and the artifact has no explicit fit timestamp, the maximum `first_seen` value and exact training cutoff are not independently established. This dataset cannot support a forward-in-time claim for the current model.

### Licensing, versioning, and acquisition constraints

- The repository source-code licence is not yet finalized.
- The dataset (datasets/raw/phiusiil_phishing_url_dataset.zip) is licensed under CC BY 4.0, as stated in models/model_utils.py line 21: DATASET_LICENSE = "CC BY 4.0". This means: attribution required, commercial use permitted with credit.
- GitHub's repository API currently classifies the repository license as `Other` / `NOASSERTION`. Treat this metadata disagreement as a verification caveat and review the exact pinned LICENSE before any use.
- The paper describes upstream VirusTotal verdicts and public allow/deny lists. Before acquisition, confirm that the dataset license and the relevant upstream-service terms permit the intended retention and evaluation. Do not redistribute raw records unless those rights are separately established.
- The public repository's latest commit is `bf17c3fef854ff0ea40bcf93e373fc2c6dc30081` (2024-11-27). Its README describes `urls_without_dns` and `urls_with_dns` Parquet directories. The latter adds DNS fields; the former's `url`, `first_seen`, and `label` fields are the closest match for this URL-only model. Pin the commit and hash acquired files if approved. Repository metadata reports a large repository (about 1.68 GB), so storage and retention must be considered before requesting acquisition.

### Compatibility with the existing model and control-set assessment

- DeepURLBench has `benign`, `phishing`, and `malware` classes. For the existing binary task, a proposed evaluation cohort would map `benign -> 0` and `phishing -> 1`, excluding malware rather than silently merging it with phishing.
- Its URL field is compatible with the existing analyzer's ten URL-derived features; DNS columns are unnecessary. The paper says it removes query strings/fragments during URL normalization and removes IP-literal URLs and URLs not beginning with HTTP(S). Those curation choices mean the evaluation will not cover query/fragment signals and will provide little or no coverage of the `uses_ip_address` feature. Report these as cohort limitations.
- The paper's post-September-2022 cohort supplies a timestamped historical benign/phishing sample, making DeepURLBench a plausible **independent historical cross-dataset** evaluation candidate. It is not a post-cutoff temporal holdout for this model.
- No exact-URL or domain overlap with UCI PhiUSIIL has been measured. That requires acquiring and processing the dataset; perform it only after approval. Keep the author's date split intact and report overlap/exclusions separately.

### Attribution

Dataset and paper citation: Schvartzman, I., Sarussi, R., Ashkenazi, M., Kringel, I., Tocker, Y., & Furman Shohet, T. (2025). *A New Dataset and Methodology for Malicious URL Classification*. arXiv:2501.00356 (submitted 2024-12-31). https://doi.org/10.48550/arXiv.2501.00356. Dataset: https://github.com/deepinstinct-algo/DeepURLBench.

Any approved use must credit the authors and dataset repository, link CC BY-NC 4.0, and disclose adaptations. Do not imply that this license resolves additional upstream source terms.

### Updated status and approval gate

DeepURLBench is the best documented timestamped legitimate-control candidate found so far, but its benign labels are vendor non-detections rather than certainty, the license metadata is inconsistent, upstream retention terms need confirmation, and its documented collection period predates the current model cutoff proxy. Since individual Parquet timestamps were not inspected, the maximum record date is not verified. Recommend it only for a non-commercial, independent historical cross-dataset evaluation after license/source-term review and explicit acquisition approval. A second source or a post-cutoff control set is still needed for a true forward-time evaluation.

No dataset was downloaded, no evaluation runner was implemented or executed, no external predictions or metrics were produced, and no model, feature, Flask, or application code was changed. Stop here pending explicit approval for acquisition and, separately, evaluation implementation.

References:

- [DeepURLBench repository](https://github.com/deepinstinct-algo/DeepURLBench)
- [DeepURLBench README](https://github.com/deepinstinct-algo/DeepURLBench/blob/main/README.md)
- [DeepURLBench LICENSE](https://github.com/deepinstinct-algo/DeepURLBench/blob/main/LICENSE)
- Schvartzman et al., [A New Dataset and Methodology for Malicious URL Classification](https://arxiv.org/abs/2501.00356), arXiv:2501.00356, DOI: [10.48550/arXiv.2501.00356](https://doi.org/10.48550/arXiv.2501.00356)

## Research-only decision — 2026-11-16 00:26 (+05:30)

The user selected research only. DeepURLBench is suitable in principle for a separate, retrospective cross-dataset experiment using its post-September-2022 test cohort, with `benign -> 0`, `phishing -> 1`, and malware excluded. This would test cross-source behavior, not future-time performance. Do not interpret the vendor-derived benign label as a guarantee of safety.

Open issues remain: exact maximum `first_seen` values and row-level timestamps have not been verified; the VirusTotal timestamp is only a proxy for first appearance; exact URL/domain overlap with UCI cannot be known without local data; and upstream source terms need review despite the repository's CC BY-NC 4.0 declaration. Required attribution: cite Schvartzman et al. (2025), arXiv:2501.00356, DOI 10.48550/arXiv.2501.00356, link the repository/license, and disclose changes. Non-commercial use only.

At this decision point, dataset acquisition, evaluation-runner implementation, and external evaluation were not approved. The later runner approval and implementation are documented below. The model was re-hashed at this decision point: SHA-256 `80B646B4AE1B90EE2A80D0214D2A175A05B0E75562FF1FD85D26AE32CD4FEE3E` (3,393 bytes). No model, application code, or URL features were changed. No tests were run for that research/documentation-only update.

## Evaluation-only runner implementation — 2026-11-16 00:28 (+05:30)

The user approved implementation only. Dataset acquisition and evaluation against external data remain unapproved and were not performed.

- Added `models/evaluate_external.py`. It loads only the local `models/phishing_url_model.joblib`, verifies the approved SHA-256 before/after loading and prediction, checks the saved feature and label schema, and uses the existing `detection.url_analyzer.analyze_url` to build the same ten URL-only features.
- The runner calls the fitted pipeline's `.predict()` only. It has no training, fit, serialization, or model-write operation.
- It accepts a local, already harmonized CSV with `url`, `label` (`legitimate`/`phishing`), `source`, `source_label`, timezone-qualified `timestamp`, and `snapshot_id`. Each file must describe one source and one snapshot. The caller supplies an explicit timezone-qualified model cutoff because the artifact has no exact fit timestamp.
- Validation rejects malformed URLs, invalid labels/timestamps, missing provenance, and conflicting duplicate URLs. Identical normalized duplicates are deduplicated. It checks exact URL overlap with the original local UCI archive, excludes exact overlaps, calculates offline registrable-domain overlap, and reports unseen-domain and post-cutoff cohorts.
- The separate JSON report includes input/model/reference hashes, class distributions, phishing precision/recall/F1, confusion matrices, false-positive/negative counts, cohort dates, overlap counts, and the original stored UCI holdout metrics for context. It contains no raw URL list and refuses to overwrite an existing report or any input/model path.
- Synthetic tests use mock predictions and temporary files only; they do not load or evaluate DeepURLBench. No external dataset was downloaded, and the runner was not executed on external data.

Verification:

- `.\venv\Scripts\python.exe -m unittest tests.test_evaluate_external -v` — 9 passed.
- `.\venv\Scripts\python.exe -m unittest discover -v` — 35 passed (9 evaluator, 4 model utility, 6 model prediction, 10 route, and 6 URL analyzer tests).
- `.\venv\Scripts\python.exe -m models.evaluate_external --help` — passed; help only, no evaluation.
- Static scan of the runner found no `.fit()`, `.fit_transform()`, or `joblib.dump()` calls.

Wait for separate approval before acquiring external data or running the evaluator against any external dataset.

## Evaluation-only runner safeguards update - 2026-11-16 00:45 (+05:30)

The approved runner improvements are implemented and covered by synthetic tests only:

- Input is limited to 100,000 rows and 50 MiB; CSV reading requests at most one row beyond the row cap to detect overflow.
- A source-specific JSON manifest is required and binds one source and snapshot to native labels and evidence bases. Legitimate labels require independent verification; vendor non-detections and ambiguous/unsupported labels are not accepted as legitimate.
- Exact URL non-overlap and unseen-domain cohorts are separately named. Non-exact domain-overlapping rows have their own metrics cohort. Domain keys are compared to the original UCI grouping rule (`Domain.strip().lower()`), and the report discloses mismatches while using the union of original keys and URL-derived registrable domains for conservative overlap checks.
- URL canonicalization handles IDNA hostnames, trailing dots, default HTTP(S) ports, and percent-encoded unreserved characters; malformed escapes are rejected.
- Synthetic tests verify feature parity, row/byte bounds, mappings, timezone offsets/cutoff boundary, hash mismatch handling, domain-key mismatch reporting, canonicalization, and path collisions.

Manifest schema example (replace the source, snapshot, and native labels only after documenting their provenance):

```json
{
  "source": "approved-source",
  "snapshot_id": "immutable-snapshot-id",
  "label_mapping": {
    "source-native-phishing-label": {
      "target": "phishing",
      "basis": "verified_phishing"
    },
    "source-native-legitimate-label": {
      "target": "legitimate",
      "basis": "independent_verification"
    }
  }
}
```

The manifest does not infer a class from vendor nondetection. Legitimate mappings require independent verification; phishing mappings accept only a verified-phishing or expert-consensus evidence basis.

Final synthetic run: `.\venv\Scripts\python.exe -m unittest tests.test_evaluate_external -v` - 18 passed. CLI help passed. The pinned model hash was reverified as `80B646B4AE1B90EE2A80D0214D2A175A05B0E75562FF1FD85D26AE32CD4FEE3E`. No external dataset was downloaded or evaluated; the full application suite was not run under the synthetic-only restriction.

These safeguards do not establish external-source provenance or prove generalization. The saved model and Flask/frontend code remain unchanged. Await explicit approval before dataset acquisition or external evaluation.

## Dataset qualification review - 2026-11-16 00:48 (+05:30)

Research-only update. Official paper/repository/license pages and official source documentation were reviewed; no dataset files were downloaded, no data rows were inspected, and no external predictions or evaluation were run.

### DeepURLBench label reliability

The paper describes source URLs from public allow-lists and deny-lists collected during 2020-2023 and labels based on VirusTotal vendor assessments. Its published method:

- Builds a high-confidence calibration set from URLs with at least nine matching non-safe vendor detections.
- Defines high-quality vendors as having over 90% detection rate and at least 10% coverage on that calibration set; the paper combines detection rate and coverage into a power-mean-based quality score.
- Assigns phishing or malware only when at least two high-quality vendors unanimously return non-safe verdicts and the summed vendor-quality score exceeds 2.5.
- Assigns `benign` when no high-quality vendor flags the URL as malicious; it discards the ambiguous `suspicious` tag.

This is a documented, stricter heuristic than a simple majority vote, but it is not independent URL-level proof of legitimacy or a manual confirmation of every record. Vendor errors can be correlated; vendor coverage and tag taxonomies can change; and "not flagged by selected vendors" can include false negatives or incomplete observations. The published README schema lists `url`, `first_seen`, and `label` (plus DNS fields in one variant), not row-level vendor evidence, so the source decisions cannot be audited per URL without additional materials. Keep `benign` explicitly described as a vendor-derived proxy, never as guaranteed safe or independently verified legitimate.

### `first_seen` meaning and training-cutoff qualification

The paper states that `first_seen` is the time the URL first appeared in VirusTotal and uses it as an approximation of when it appeared on the internet. It is not a verified URL publication, creation, registration, or first-live time; the time can reflect VirusTotal's own observation and ingestion. The paper also describes a roughly two-month reputation-maturity filter, meaning vendor evidence used for a label may be observed after the stored `first_seen` time. Thus the timestamp and label do not necessarily describe what could have been known at that timestamp.

The paper's post-September-2022 test split is a historical split for the authors' benchmark. The paper describes collection during 2020-2023; the repository's last push is dated 2024-11-27. Both predate this project's model artifact serialization-time proxy, 2026-11-15 23:33:46. The model artifact does not store an exact fit timestamp, and its file time is not proof of the fit time. Therefore:

- Relative to the current 2026-11-15 cutoff proxy, DeepURLBench is not post-cutoff and cannot support a forward-in-time claim.
- The exact maximum row-level `first_seen`, timestamp encoding/timezone, missingness, and exact model fit time remain unverified without separately approved data inspection and training provenance.
- Do not infer a valid post-training test solely from the author's post-September-2022 split or from the `first_seen` field name.

### License and upstream-source restrictions

The repository README and `LICENSE` explicitly state CC BY-NC 4.0. The official license permits sharing/adaptation for non-commercial purposes subject to attribution: retain supplied notices where applicable, credit the creators, link the material and license, and indicate modifications. It does not permit commercial use and does not imply endorsement. The legal code grants only rights the licensor has authority to grant and warns that other rights may still apply.

GitHub's repository API currently reports `license: Other` / `NOASSERTION`; this is an unresolved repository-metadata caveat, not a substitute for reviewing the pinned README and LICENSE. The paper says the source data includes public allow/deny lists and VirusTotal, but does not provide a complete per-record source-rights manifest in the published schema. The repository-level CC license cannot by itself establish the rights to reuse, retain, redistribute, or commercially exploit upstream VirusTotal results or third-party list records. Do not acquire or redistribute until the dataset maintainer's scope and the applicable upstream terms are confirmed. If any CC BY-NC material is used, any commercial project use is out of scope absent separate permission.

### Legitimate-control source assessment

No ready-made source reviewed here provides defensible, time-stamped, URL-level proof that each record is legitimate:

- Tranco supplies reproducible, dated popularity rankings, not URL-level benign labels. Its list combines sources with different terms (including CC BY 3.0, CC BY-SA 4.0, and CC BY-NC 4.0 inputs); popularity, ranking, or absence from a blocklist is not a benign verdict. It can be a sampling frame only, with separate verification and source-rights review.
- CISA's .gov registration process restricts domains to eligible U.S. government organizations and verifies requesters. This can support domain ownership for a narrowly defined control cohort, but it does not certify every path, redirect, or page as benign or uncompromised.
- PhishTank and OpenPhish are potential timestamped phishing-positive sources, not legitimate controls. PhishTank publishes community verification/status fields, while its current terms page points users to Cisco's EULA; archived terms should not be assumed to govern current use. OpenPhish's academic program is non-commercial, time-limited, requires attribution, prohibits third-party sharing, and its public page does not settle the archive's per-record timestamp schema.

Recommended control design, pending approval: construct a small prospective cohort of exact URLs sourced from first-party official organization pages, using an authoritative registry (for example, eligible .gov domain ownership) only as a domain seed. Independently verify each exact URL, redirects, ownership/context, and page status at a recorded UTC observation time; preserve verification evidence and reviewer/source provenance; and use at least two reviewers for ambiguous cases. A URL's current verification time is not a historical creation time. Keep the cohort narrow and disclose selection bias; its false-positive rate will not estimate the rate across all internet URLs. Do not use "not found on a phishing feed," VirusTotal nondetection, or popularity as sole legitimate evidence.

### Current source-label manifest compatibility

The current runner manifest has one `source`, one `snapshot_id`, and a mapping from each native label to a binary `target` plus one `basis`. It requires both targets (`legitimate` and `phishing`), permits only `independent_verification` as the legitimate basis and `verified_phishing`/`expert_consensus` for phishing, and rejects malware/suspicious/unknown/unrated and known nondetection labels.

It therefore cannot faithfully represent DeepURLBench as published:

- Mapping its `benign` source label to `legitimate` with `independent_verification` would misstate the vendor-nondetection evidence; using a vendor-nondetection basis is intentionally rejected.
- `multi_vendor_threshold` is not an allowed evidence basis for the paper's phishing label, and `expert_consensus` should not be used unless it accurately describes the documented row-level evidence.
- The manifest has no `exclude` or third-class target for malware, no explicit proxy-label class, and no required fields for citation, license/version, acquisition/retention terms, per-record evidence, or filtering/exclusion counts. Filtering malware before the runner would also need a separately preserved and reported exclusion record.

Do not force DeepURLBench into the existing binary manifest by relabeling or silently filtering. Before any such evaluation, obtain approval for a source-accurate manifest/report design (or select a source whose labels meet the current contract), and preserve all exclusions and class semantics.

### Decision and approval gate

DeepURLBench may be considered only for a non-commercial, historical cross-dataset study after record-level timestamp/schema checks and source-rights review. It does not presently qualify as a verified legitimate control or as a post-cutoff test. The next defensible route is a separately approved, prospective, manually verified URL control cohort and a confirmed model fit timestamp. No data acquisition, code change, model change, or external evaluation was performed in this research pass.

### Sources reviewed

- [DeepURLBench paper, full text](https://arxiv.org/html/2501.00356v1), Sections 3.1-3.6; [arXiv record](https://arxiv.org/abs/2501.00356)
- DeepURLBench [README at reviewed commit](https://raw.githubusercontent.com/deepinstinct-algo/DeepURLBench/bf17c3fef854ff0ea40bcf93e373fc2c6dc30081/README.md) and [LICENSE at reviewed commit](https://raw.githubusercontent.com/deepinstinct-algo/DeepURLBench/bf17c3fef854ff0ea40bcf93e373fc2c6dc30081/LICENSE)
- [DeepURLBench repository metadata](https://api.github.com/repos/deepinstinct-algo/DeepURLBench) and [latest commit metadata](https://api.github.com/repos/deepinstinct-algo/DeepURLBench/commits/main)
- [CC BY-NC 4.0 deed](https://creativecommons.org/licenses/by-nc/4.0/) and [legal code](https://creativecommons.org/licenses/by-nc/4.0/legalcode.en)
- [Tranco methodology and source attribution](https://tranco-list.eu/)
- [CISA .gov domain requirements](https://get.gov/domains/)
- [PhishTank API information](https://www.phishtank.com/api_info.php) and [current terms notice](https://www.phishtank.org/terms.php)
- [OpenPhish Academic Use Program](https://openphish.com/academic_use.html) and [terms](https://openphish.com/terms.html)

## Verified dataset framework - 2026-11-16 00:56 (+05:30)

Research and protocol design only. DeepURLBench remains rejected for primary binary evaluation. No dataset was acquired, no outside URL was evaluated, and the runner, tests, model, and application were not changed.

### Candidate phishing-positive sources

**PhishTank is the strongest candidate for a timestamped community-verified phishing-positive cohort, contingent on current rights clearance.** Its official developer documentation describes hourly-updated `online-valid` feeds. The CSV includes `url`, `phish_id`, `phish_detail_url`, `submission_time`, `verified`, `verification_time`, `online`, and `target`; the documented feed rows have `verified=yes` and `online=yes`, and timestamps are ISO-8601 with UTC offsets. For a future prospective test, retain the exact feed snapshot and use `verification_time` as the timestamp when the source's phishing label became available; keep `submission_time` and the snapshot retrieval time as separate provenance fields. Community verification is useful evidence but not infallible ground truth; preserve the detail URL/reference and report the label source.

PhishTank's current terms page directs users to Cisco's EULA. It also exposes archived terms, but these should not be treated as the current grant. No clear current, standalone open-data license or permission for this project's retention/redistribution was confirmed. Before any acquisition, obtain current written confirmation of allowed research use, storage duration, derived reports, and any redistribution or commercial restrictions. PhishTank feed downloads require an application key for regular automated access.

**OpenPhish Academic Use is a secondary candidate if the project qualifies and accepts its restrictions.** Its official program describes a real-time phishing feed and a 30-day archive for applicants affiliated with an accredited academic institution; access is approved and time-limited (60 days). It requires attribution including access date, prohibits commercial use, and prohibits sharing data with third parties. Its public materials do not settle the archive's per-record timestamp and label-verification fields. Confirm the schema, event-time semantics, permitted retention, and whether aggregate reports may be shared before deciding whether it can support this study. Written permission may be needed if use would support organizational or commercial operations.

URLhaus is not a phishing-positive substitute: its official description says the service tracks malware URLs. Keep its malware class out of the phishing-positive cohort; if ever used for a separate experiment, mark it as an excluded class under the framework below.

**Recommendation:** ask PhishTank first for current rights clarification because its feed documentation exposes explicit verification and event timestamps. Keep OpenPhish as an alternative only after eligibility and written terms/schema confirmation. Neither source is approved for acquisition by this research decision.

### Prospective legitimate-URL verification protocol

No vendor non-detection, threat-feed absence, domain popularity, TLS certificate, or successful HTTP response alone is sufficient to label a URL legitimate. A future control cohort should be defined as "independently verified first-party URL at observation time," not as universally safe.

1. **Use a narrow, documented sampling frame.** Source exact URLs from the organizations' own official pages or directories. An authoritative ownership registry (for example, CISA's eligible .gov registration) may seed candidate organizations/domains, but is not itself page-level verification. Record the first-party link or directory from which each URL was obtained.
2. **Verify at URL level and at a fixed time.** At an approved collection time, check the exact URL and its redirect chain in an isolated review workflow. Confirm the domain is controlled by the named organization and the page is consistent with that organization's first-party purpose. A domain being registered to a real organization does not prove a specific path is uncompromised.
3. **Require independent review.** Two reviewers independently inspect the evidence and record their decision. Agreement with the ownership/page evidence supports `legitimate_verified`; disagreement, inaccessible content, third-party redirects, uncertain ownership, suspicious content, or any unresolved compromise concern is `uncertain` and excluded. An adjudicator may resolve disagreements only with recorded evidence; otherwise retain the exclusion.
4. **Preserve evidence without assuming permanence.** Store a stable evidence ID, first-party source URL, organization/domain ownership reference, observed redirect chain, reviewer IDs, UTC `verified_at`, and a hash or permitted archival reference for the reviewed evidence. Do not retain page content or personal data unless rights and necessity are separately established.
5. **Treat the label as time-bounded.** A verified page is a legitimate control only at the recorded observation time. Recheck if the evaluation window spans changes. The verification timestamp is not the URL's creation time. Do not infer the broad web false-positive rate from this curated, likely institution-heavy sample; disclose its selection bias and report per-source results.
6. **Keep uncertain/vendor-derived negatives out.** Exclude `benign` labels supported only by no vendor detection (including DeepURLBench's label), `unrated`, `unknown`, `suspicious`, conflicting review outcomes, and missing evidence/time. Count each exclusion by reason.

### Revised source-label manifest and report design (proposal only)

The current runner is intentionally unchanged. Its binary `source`/`snapshot_id` manifest cannot encode source rights, row-level evidence, malware exclusion, and auditable exclusion counts. Before a future run, replace/extend it only with separate approval. Use one immutable source snapshot per `source_id`; preserve source-native fields in each row rather than collapsing them prematurely.

Proposed version-2 structure:

```json
{
  "schema_version": 2,
  "evaluation_id": "approved-evaluation-id",
  "sources": [
    {
      "source_id": "phishing-feed",
      "name": "source name",
      "snapshot_id": "immutable-snapshot-id",
      "source_uri": "official source page",
      "retrieved_at_utc": "required ISO-8601 timestamp",
      "license": {
        "name": "unknown_pending_clearance",
        "terms_uri": "official terms page",
        "commercial_use": "unknown",
        "redistribution": "unknown",
        "retention": {
          "duration": null,
          "conditions": "unknown_pending_clearance"
        },
        "attribution": "requirements to be recorded before acquisition"
      },
      "timestamp_provenance": {
        "field": "verification_time",
        "semantics": "time the source community marked the record verified",
        "timezone": "explicit per-record ISO-8601 offset",
        "normalization": "convert to UTC and preserve raw value",
        "role": "label_available_at"
      },
      "label_mappings": [
        {
          "source_native_label": "verified phishing status",
          "source_native_fields": {"verified": "yes", "online": "yes"},
          "action": "include",
          "binary_target": "phishing",
          "evidence_basis": "community_verified",
          "evidence_reference_fields": ["phish_detail_url"]
        },
        {
          "source_native_label": "malware",
          "action": "exclude",
          "binary_target": null,
          "exclusion_reason": "out_of_scope_class"
        },
        {
          "source_native_label": "uncertain or vendor_nondetection",
          "action": "exclude",
          "binary_target": null,
          "exclusion_reason": "insufficient_legitimate_evidence"
        }
      ]
    }
  ],
  "unmapped_label_policy": "exclude_and_count",
  "missing_evidence_policy": "exclude_and_count"
}
```

The legitimate-control source would have its own `source_id` and snapshot, with `source_native_label: "independently_verified"`, `action: "include"`, `binary_target: "legitimate"`, `evidence_basis: "two_reviewer_url_level_verification"`, evidence references, and a `verified_at` timestamp provenance entry. It must not be encoded as vendor `clean`, `benign`, `unrated`, or nondetection.

Actual exclusion counts are evaluation outputs, not values known when a manifest is authored. The report should include input rows; included rows by source and binary target; and excluded rows by source-native label and reason, including malware, uncertain, vendor-nondetection, missing evidence, missing/invalid timestamp, invalid URL, duplicates/conflicts, exact-URL overlap, and domain overlap. Counts must reconcile to all input rows. The manifest supplies the mapping and exclusion policy; the report records the realized counts and hashes. Unknown/ambiguous labels must never default to either binary class.

### Cutoff limitation and execution gate

The saved model artifact does not record an exact fit timestamp. The 2026-11-15 23:33:46 artifact serialization time remains only a proxy, not a verified training cutoff. Before any forward-time claim, recover a trustworthy fit timestamp from training provenance; otherwise use the serialization time only as an explicitly conservative proxy and require evaluation-label availability/verification times to be strictly later. Source collection dates, submission times, or a retrospective dataset split are not substitutes for per-record event/label timestamps.

Next steps are approval-gated: confirm the model cutoff provenance; obtain the source's current use/retention permission; approve a prospective legitimate-control collection; and separately approve any manifest/runner changes before implementation. DeepURLBench remains unapproved and is not to be acquired. No external evaluation has been performed.

### Additional sources reviewed

- [PhishTank developer feed documentation and CSV fields](https://www.phishtank.com/developer_info.php)
- [PhishTank current terms notice](https://www.phishtank.com/terms.php), which directs users to the [Cisco EULA](https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html)
- [OpenPhish Academic Use Program](https://openphish.com/academic_use.html) and [terms of use](https://openphish.com/terms.html)
- [URLhaus about page](https://urlhaus.abuse.ch/about/) (malware URL feed; not a phishing-positive source)
- [CISA .gov registration requirements](https://get.gov/domains/)

## Original model training provenance audit — 2026-11-16

This was a read-only audit. No training, model loading for prediction, dataset acquisition, external evaluation, or application-code changes were performed.

### Verified implementation and dataset identity

- The local UCI PhiUSIIL archive is `datasets/raw/phiusiil_phishing_url_dataset.zip` (UCI dataset ID 967). Its SHA-256 was recomputed and matches the dataset version/hash embedded in the saved artifact: `0A639FD03AEA6308C5B1C10C92AA23C2CE1505447A9137271865CD0BADC9A59A`. This identifies the local archive bytes; it is not a provider-signed release identifier.
- The training metadata records 235,795 source rows, 235,370 rows after exact-URL deduplication, and 425 removed duplicates. It records source labels `0 = phishing` and `1 = legitimate`, mapped to model targets `0 = legitimate` and `1 = phishing`.
- Training uses the ten URL-derived features implemented by `detection/url_analyzer.py`: `url_length`, `hostname_length`, `path_length`, `dot_count`, `hyphen_count`, `at_symbol_count`, `digit_count`, `uses_https`, `uses_ip_address`, and `suspicious_keyword_count`. They are based on the normalized URL, parsed hostname/path/scheme, URL characters, and the analyzer's fixed suspicious-keyword list (`login`, `verify`, `account`, `secure`, `update`, `password`, `signin`, `banking`).
- `models/train_model.py` compares a most-frequent `DummyClassifier` against a `StandardScaler` + `LogisticRegression` pipeline. The logistic regression configuration includes `class_weight="balanced"`, `max_iter=1000`, and `random_state=42`. The grouped stratified split uses `StratifiedGroupKFold` with five splits, `shuffle=True`, seed 42, and fold 0; grouping is by the dataset's `Domain` field. The recorded split has 188,296 training rows and 47,074 test rows, with no URL or domain overlap. The pipeline is fitted on the training fold and serialized with evaluation, feature, split, and dataset metadata.
- The model artifact hash was rechecked as `80B646B4AE1B90EE2A80D0214D2A175A05B0E75562FF1FD85D26AE32CD4FEE3E`; it remains the previously pinned artifact.

### Training-time evidence and cutoff assessment

- `DEVELOPMENT_LOG.md` records a baseline training/evaluation entry dated 2026-11-15 and the command `.\venv\Scripts\python.exe -m models.train_model --overwrite`. This is day-level project documentation, not an independent execution log with a trusted timestamp.
- The training script does not record fit start/end times. The saved artifact contains dataset, evaluation, feature-name, model, and split metadata, but no training timestamp. The `retrieved_date` of 2026-11-15 is dataset metadata and does not establish when fitting occurred.
- Windows file metadata reports the model artifact was created at 2026-11-15 23:30:37 and last written at 2026-11-15 23:33:46 local time (18:03:46 UTC). These are serialization/file-system times, not verified fit times; they may be affected by copying or synchronization.
- No exact training execution timestamp or independent record of the original `.fit()` call was found in the available project documentation or local session history. Consequently, the model's actual training cutoff cannot be independently established from current evidence. The log date and artifact serialization time are corroborating context only, not a defensible, verified cutoff.

### Remaining provenance gaps and recommendation

- Preserve the local archive SHA-256 as the reproducible identity of the training dataset snapshot, while retaining the distinction between that checksum and an independently authenticated UCI release/version.
- Before making any temporal-generalization claim, recover a trusted training-run record tied to this exact artifact hash, or treat the serialization time only as an explicitly conservative proxy and require evaluation evidence to postdate it. Do not present 2026-11-15 as an independently verified fit cutoff.
- No tests were run because this was a documentation/provenance audit. No external dataset was downloaded or evaluated, and the model was not modified or retrained.

## Evaluation readiness preparation — 2026-11-16 01:03 (+05:30)

Documentation-only preparation. No feeds or datasets were downloaded, no external evaluation was run, and no model, dataset, application, or runner code was changed.

### Integrity and cutoff

- Rechecked the saved model SHA-256: `80B646B4AE1B90EE2A80D0214D2A175A05B0E75562FF1FD85D26AE32CD4FEE3E`. Rechecked the local UCI PhiUSIIL archive SHA-256: `0A639FD03AEA6308C5B1C10C92AA23C2CE1505447A9137271865CD0BADC9A59A`. Both match the previously recorded values.
- The model's exact fit cutoff remains **unverified**. The artifact's 2026-11-15 23:33:46 local serialization time (2026-11-15 18:03:46 UTC) is not a verified training time. Until trusted provenance is recovered, do not call any cohort “post-training” or “post-cutoff.” If a separate decision authorizes the serialization-time proxy, describe results only as post-serialization and state that this does not prove the records postdate fitting.

### Finalized proposed source-specific manifest design (documentation only)

Use schema version 2 with one immutable source snapshot per `source_id`; do not combine sources under one implicit label map. The manifest is a design, not an implemented schema. Each source entry must record:

- **Identity:** `source_id`, source name and official URI, source/version or feed name, immutable `snapshot_id`, snapshot retrieval time in UTC, and SHA-256 of the acquired bytes.
- **Rights and retention:** exact terms URI and review date; permission status for the intended research; commercial-use and redistribution status; permitted retention period and conditions; required deletion date/process; whether derived metrics/reports may be retained or published; required attribution; and a reference to any written clarification. Unknown terms remain `unknown` and block acquisition/use rather than being treated as permission.
- **Native-label mapping:** exact source-native label and required source-native field/value conditions; action (`include` or `exclude`); binary target (`phishing` or `legitimate`, null for excluded records); evidence basis; required evidence-reference fields; and an explicit exclusion reason. Only exact, reviewed mappings are accepted. Unmapped or ambiguous labels default to `exclude_and_count`; they never default to either binary class.
- **Timestamp provenance:** raw source field, documented event meaning, timezone/offset semantics, normalized UTC value while retaining the raw value, and role (for example `label_available_at`, `submission_at`, `observed_at`, or `verified_at`). Feed retrieval time is not a substitute for a row-level event/label timestamp.
- **Record-level audit fields:** source/snapshot IDs, native label and relevant native fields, inclusion action, target or exclusion reason, raw and normalized timestamps, evidence references, and canonicalized URL key. Keep raw source fields in the restricted input snapshot; reports should avoid exposing raw URLs unless rights and privacy review permit it.
- **Reconciled report counts:** input rows, included rows by source and binary target, excluded rows by source-native label and reason, and duplicates/conflicts/overlap counts. Included plus excluded counts must reconcile to all input rows.

The source-specific rules are:

1. **PhishTank candidate:** only records with `verified=yes` and `online=yes` in a pinned `online-valid` snapshot may map to `phishing`, with `verification_time` as the candidate `label_available_at` and `phish_detail_url` as an evidence reference. Preserve `submission_time` and retrieval time separately. This is community verification, not infallible ground truth. The official feed is updated hourly; regular automated downloads require an application key. This mapping remains blocked on rights clearance.
2. **OpenPhish candidate:** no label mapping is approved yet. First obtain access approval, inspect the authorized schema, verify native-label and per-record timestamp semantics, and obtain written clarification on use, retention, and shareable outputs. Do not infer labels or timestamps from feed membership alone.
3. **Legitimate controls:** only an exact URL independently verified under the two-reviewer protocol below may map to `legitimate`. Its native label is `independently_verified`; its evidence basis is `two_reviewer_url_level_verification`; and `verified_at` records the UTC observation/review time. A domain list, popularity rank, TLS, HTTP success, feed absence, or vendor “clean” result alone cannot produce this label.
4. **Always exclude from the phishing-vs-legitimate binary cohort:** malware, vendor non-detections, `benign`/`clean` labels without independent URL-level proof, suspicious/unknown/unrated/ambiguous labels, conflicting or missing evidence, missing/invalid required timestamps, malformed or unsupported URLs, and any source-native label not explicitly mapped. Count each reason separately.

### Final legitimate-URL verification protocol

1. Obtain approval for a narrowly defined sampling frame and record the official first-party source from which each exact URL was selected. CISA `.gov` registration may seed organizations/domains but does not establish that each page is benign.
2. At the planned collection time, inspect the exact URL and its redirect chain in an isolated review process. Confirm ownership using authoritative evidence and confirm the page's content/purpose is consistent with the named first party. A legitimate domain does not establish that every path or redirect is safe.
3. Have two reviewers independently record decisions and evidence. Include only agreement supported by evidence. Disagreement, inaccessible pages, third-party redirects, uncertain ownership, suspicious content, or unresolved compromise concerns are excluded; adjudication requires a documented evidence-based decision.
4. Record a stable evidence ID, first-party source URL, ownership reference, exact URL and redirect chain, reviewer IDs, UTC `verified_at`, and a hash or permitted archival reference. Do not retain page contents or personal data unless necessity and rights are separately established.
5. Treat the label as time-bounded to `verified_at`; it is not a URL creation time. Recheck if the planned evaluation window requires current-state assurance. Report the curated sample's selection bias; do not generalize it as the web-wide benign distribution.
6. Exclude vendor non-detection and uncertainty, even when a vendor or dataset calls the URL benign. Count exclusions by reason.

### Inclusion, overlap, and evaluation rules

- A record is eligible for a cross-dataset cohort only when its URL is supported by a valid explicit native-label mapping, required evidence and timestamp provenance are present, rights are cleared, and URL validation succeeds. The mapping sets only the binary target; it does not assert certainty beyond its stated evidence.
- The exact-URL non-overlap cohort excludes canonicalized URLs present in the UCI reference. Report exact overlaps separately. Within exact-URL non-overlap, report UCI-domain-overlapping records separately from unseen-domain records. Preserve the existing domain-key comparison against the UCI training `Domain.strip().lower()` rule and disclose key mismatches; do not conflate URL non-overlap with domain novelty.
- Deduplicate identical canonical URLs. Exclude all conflicting-label duplicates and count them. Keep exclusion counts by source/label/reason and verify that they reconcile to input rows.
- A temporal “post-training” cohort is blocked until a trusted model fit cutoff is established. If a serialization-time proxy is separately approved, require row-level label-availability/verification time strictly later than that proxy and call the cohort **post-serialization**, not post-training. Submission time, feed snapshot time, and retrospective source split are not substitutes.
- Do not train, fit, calibrate, or modify the saved pipeline. Use the existing feature extractor and saved pipeline's prediction path only. Report phishing precision, recall and F1, confusion matrix with label order `[0 = legitimate, 1 = phishing]`, class distribution, false positives/negatives, exclusions, and separate exact-URL/domain cohorts. Compare with the stored UCI holdout only as context, not as a directly equivalent test.

### Reproducible external-evaluation checklist

1. Obtain separate explicit approval for each source acquisition and for evaluation. Resolve eligibility, current terms, data retention/deletion, and report-sharing rights first.
2. Record source/version, official source and terms URLs, approval reference, snapshot ID, retrieval time, source-file SHA-256, license/retention conditions, and required attribution. Keep restricted source files under approved access/retention controls.
3. Verify model and UCI reference hashes before processing; record the pinned model hash, feature names/order, label order, Python/dependency versions, code revision or source-file hashes, command, and cutoff status. A failed hash check blocks the run.
4. Validate the manifest and every label mapping. Reject unknown mappings, missing evidence, unsupported timestamp semantics, invalid timezone values, and rights states that are not approved. Do not assume nondetection means legitimate.
5. Run URL validation, canonicalization, deduplication/conflict handling, exact-URL overlap checks, and domain-overlap/unseen-domain cohorting. Report all excluded and duplicate counts and reconcile them to the source input.
6. Extract only the existing ten features through the existing analyzer; predict with the saved pipeline only. Confirm no fitting/retraining/serialization path is invoked and that neither the model nor input/reference files can be overwritten by the report path.
7. Record results by source and cohort: class counts, phishing precision/recall/F1, confusion matrix, false positives and false negatives, timestamp range and cutoff qualification, overlap and exclusion counts, and comparison to the original UCI holdout with caveats.
8. Re-run from the same approved snapshots and manifest to confirm deterministic report contents. Independently review label mapping, cutoff wording, source rights, report path/hash metadata, and disclosure/attribution before any permitted publication. Apply source deletion/retention conditions afterward.

### Licensing and retention questions still open

- **PhishTank:** its current terms notice points to the Cisco End User License Agreement; the page also exposes archived terms, which should not be treated as the current grant. No clear current standalone open-data license or project-specific retention permission was established. Before acquisition, request written clarification of permitted academic/non-commercial and any commercial use, storage duration and secure local copies, deletion obligations, use of derived metrics, publication or sharing of reports, redistribution of raw/derived records, attribution, and application-key/feed-use conditions. Its developer page documents an hourly `online-valid` feed and fields including `verification_time`, `submission_time`, `verified`, `online`, `target`, and `phish_detail_url`; the published fields do not answer rights questions.
- **OpenPhish:** its Academic Use Program requires affiliation with an accredited academic institution, an application from an academic email with project description, approval and an available seat. The program offers a real-time feed and 30-day archive, with 60-day access and extensions only by approval. It requires attribution including source URL and access date, prohibits commercial use, and prohibits sharing data with third parties. Its general terms characterize the information as proprietary and restrict disclosure/derivative distribution absent express permission. The archive's per-record label/timestamp semantics and what happens to locally held data after access ends are not documented by the public program page. Confirm eligibility, exact schema, permitted local retention/deletion, use of derived reports, and whether non-identifying aggregate results may be published before applying or acquiring.

Official pages reviewed on 2026-11-16: [PhishTank developer documentation](https://www.phishtank.com/developer_info.php), [PhishTank current terms notice](https://www.phishtank.com/terms.php), [Cisco EULA linked by PhishTank](https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html), [OpenPhish Academic Use](https://openphish.com/academic_use.html), and [OpenPhish terms](https://openphish.com/terms.html). The linked Cisco document was returned as a PDF; no clause-level legal interpretation is asserted here.

### Readiness status and stop condition

The design, inclusion/exclusion rules, legitimate-control protocol, and reproducibility checklist are documented, but no source is cleared for acquisition. PhishTank retention/use rights, OpenPhish eligibility and post-access retention, legitimate-control collection approval, and the model's trusted fit cutoff remain unresolved. No dataset download, external evaluation, model retraining, or application/model/runner modification is authorized or performed. Stop before acquisition or evaluation pending explicit approval.