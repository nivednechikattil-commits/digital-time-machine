# Digital Time Machine — Interactive Digital Forensics & Cyber Incident Reconstruction Platform

> **Hackathon Prototype**  
> **Track 03:** Digital Forensics & Cyber Intelligence  
> *"Digital Time Machine transforms fragmented digital evidence into an interactive, rewindable digital crime scene, helping investigators understand what was recorded, how events may be connected, and where evidence is missing."*

---

## 1. Core Concept & Methodology

In modern cyber incident response, forensic examiners receive fragmented telemetry scattered across endpoints, authentication logs, web proxies, network packet captures, and peripheral USB logs. 

**Digital Time Machine** solves this fragmentation by:
1. **Normalizing Multi-Source Telemetry:** Ingesting CSV and JSON evidence into a unified chronological schema with cryptographic SHA-256 baselining.
2. **Rewinding Time (Temporal Scrubber):** Enabling examiners to rewind and advance through the incident minute-by-minute with playback controls, variable speeds, and strict temporal isolation (the UI never reveals future events before their occurrence).
3. **Reconstructing Digital State:** Simulating active user sessions, filesystem mutations, mounted removable drives, and outbound connections at any exact point in time.
4. **Explainable Event Correlation:** Applying deterministic heuristic rules (Rules A through F) with explicit limitations and supporting event IDs without black-box machine learning.
5. **Ghost Evidence Gap Detection:** Identifying suspicious unrecorded intervals, missing precursor reads before copies, unclosed hardware lifecycles, and unattributed network flows.
6. **Strict Forensic Neutrality:** Enforcing a rigorous UI distinction between **Observed Evidence** (direct recorded logs) and **Inferred Conclusions** (rule deductions).

---

## 2. Technology Stack

- **Backend:** Python 3 (standard library: `sqlite3`, `csv`, `json`, `hashlib`, `datetime`, `urllib`) + `Jinja2` & `MarkupSafe` (with offline zero-dependency WSGI/Flask compatibility layer and standard `Flask` support).
- **Database:** SQLite 3 with parameterized queries, multi-case isolation, and indexes on `(case_id, timestamp)`.
- **Frontend:** HTML5, CSS3 (Professional Dark Navy/Charcoal cyber-forensics design system), Vanilla JavaScript (no external runtime frameworks required), SVG interactive entity relationship graph, and print stylesheet.
- **Testing:** Comprehensive test suite (`unittest` / `pytest`) verifying normalization, parsers, state reconstruction, correlation rules, case isolation, and REST APIs.

---

## 3. Project Structure

```text
digital-time-machine/
├── app.py                      # Main application server & REST API router
├── config.py                   # Central configuration & paths
├── flask_compat.py             # Offline WSGI/Flask compatibility engine
├── requirements.txt            # Python dependencies
├── run_tests.py                # Automated test runner
├── README.md                   # System documentation & demo guide
├── .gitignore                  # Version control ignore rules
├── database/
│   ├── __init__.py
│   ├── db.py                   # SQLite connection & query helpers
│   └── schema.sql              # Database schema with indexes & FK constraints
├── engine/
│   ├── __init__.py
│   ├── normalizer.py           # Timestamp & event schema normalizer
│   ├── state_reconstructor.py  # Point-in-time system state reconstructor
│   ├── correlator.py           # Rule-based correlation engine (Rules A-F)
│   ├── ghost_evidence.py       # Ghost evidence & coverage gap detector
│   ├── graph_generator.py      # Incident relationship entity graph generator
│   ├── investigator.py         # Forensic inquiry Q&A engine
│   ├── evidence_dna.py         # Deep forensic lineage & facts vs inferences
│   ├── stress_tester.py        # Conclusion stress tester & adversarial validator
│   ├── snapshot_service.py     # Investigation Time Machine snapshots & diff engine
│   ├── ai_provider.py          # Configurable AI provider adapter (OpenAI SDK + HTTP fallback)
│   ├── copilot_engine.py       # Grounded prompt builder, injection defense & citation validator
│   └── report_generator.py     # Investigation dossier & report compiler
├── parsers/
│   ├── __init__.py
│   ├── csv_parser.py           # CSV evidence parser with line-by-line validation
│   └── json_parser.py          # JSON, JSON-array, and JSONL parser
├── services/
│   ├── __init__.py
│   ├── case_service.py         # Multi-case lifecycle & metrics aggregator
│   ├── evidence_service.py     # Safe upload, hashing & duplicate prevention
│   └── snapshot_service.py     # Investigation Time Machine snapshots & diff engine
├── data/
│   └── demo/                   # Seeded synthetic training scenario
│       ├── login_events.csv
│       ├── browser_history.csv
│       ├── file_access.csv
│       ├── usb_activity.json
│       ├── network_traffic.json
│       └── scenario_manifest.json
├── templates/                  # Semantic cyber-forensics HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── timeline.html
│   ├── system_state.html
│   ├── evidence.html
│   ├── incident_graph.html
│   ├── ghost_evidence.html
│   ├── investigate.html
│   ├── stress_test.html        # Conclusion Stress Tester workspace
│   ├── time_machine.html       # Investigation Time Machine comparator
│   ├── copilot.html            # Evidence-Grounded AI Investigation Copilot
│   ├── report.html
│   └── settings.html
├── static/
│   ├── css/
│   │   └── style.css           # Dark navy theme & responsive layout
│   └── js/
│       ├── timeline.js         # Interactive playback & scrubber logic
│       ├── state.js            # System state dynamic renderer
│       ├── graph.js            # SVG relationship graph renderer
│       ├── evidence.js         # File upload & validation diagnostics
│       ├── investigate.js      # Inquiry evaluator & notes journal
│       ├── evidence_dna.js     # Evidence DNA modal & gap viewer
│       ├── stress_test.js      # Stress test evaluator & custom hypothesis runner
│       ├── time_machine.js     # Snapshot capture & comparative evolution renderer
│       └── copilot.js          # AI Copilot chat, citations & rate limit handling
└── tests/                      # Automated test suite (100 tests, 0 failures)
    ├── __init__.py
    ├── test_normalizer.py
    ├── test_parsers.py
    ├── test_database.py
    ├── test_state_reconstruction.py
    ├── test_correlator.py
    ├── test_ghost_evidence.py
    ├── test_evidence_service.py
    ├── test_evidence_dna.py
    ├── test_demo_case_e2e.py
    ├── test_stress_tester.py    # Conclusion Stress Tester test suite
    ├── test_time_machine.py     # Investigation Time Machine test suite
    └── test_api.py
```

---

## 4. Setup and Launch Instructions (Ubuntu / Linux)

### Prerequisites
- Python 3.10+ installed.
- Works **100% offline** using Python standard library + Jinja2.

### Launch Application
From the project root:
```bash
# 1. Run the web application
python3 app.py
```

Open your browser and navigate to:
```text
http://127.0.0.1:5000/
```

### Run Automated Tests
```bash
# Execute the full 84-test suite (0 failures, 0 errors)
python3 run_tests.py

# Or with unittest directly:
python3 -m unittest discover tests -v
```


---

## 5. Synthetic Demo Scenario: "The Missing Customer Database"

The application seeds a fictional cyber incident (`CASE-2026-001`):

1. **Authentication:** User `alice` executes two failed password attempts at 10:00:15 and 10:00:45 before a successful logon at 10:01:00 on `workstation-01` (triggers **Rule D: Repeated Failed Logins Followed by Success**).
2. **Suspicious Navigation:** At 10:04:30, `alice` navigates to `http://secure-update-training.internal-demo.local/cust_db_tool.exe`.
3. **Payload Download:** At 10:05:00, `cust_db_tool.exe` is downloaded and written to disk (triggers **Rule A: Suspicious Website Preceding Download**).
4. **Removable Media Connection:** At 10:12:00, a Kingston DataTraveler 3.0 USB drive (`SN-99482710`) is connected to `workstation-01` port 2.
5. **Sensitive File Access & Copy:** At 10:14:15, `customer_database_q3.csv` is read, and at 10:15:30 it is copied to volume `E:\backup\` (triggers **Rule B: File Access Preceding Copy**, and **Rule C: Device Attached Near File-Copy**).
6. **External Network Transfer:** At 10:16:00, an outbound encrypted connection transmits 45.2 MB of data to external host `198.51.100.42:8443` (triggers **Rule E: Download + File Access + Outbound Traffic**).
7. **Coverage Anomaly:** A 40-minute gap in browser navigation is detected between 10:05:00 and 10:45:20, and the USB device was never unmounted in the logs (triggers **Ghost Evidence Gap Detection**).

---

## 6. Correlation Engine Rules (Rules A to F)

| Rule ID | Rule Name | Description | Severity | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| **RULE_A** | Suspicious Web Visit Preceding Download | Navigation to suspicious domain followed by file download within 15 mins | HIGH | Observed Correlation |
| **RULE_B** | File Access Followed by Copy | Read handle on sensitive file followed by copy operation within 15 mins | HIGH | Observed Correlation |
| **RULE_C** | Removable Device Attachment Near Copy | USB insertion proximate (<10m) to recorded file write | CRITICAL | Observed Correlation |
| **RULE_D** | Repeated Failed Logins Then Success | ≥2 authentication failures followed by logon within 30 mins | HIGH | Observed Correlation |
| **RULE_E** | Download + File Access + Network Activity | Payload download followed by sensitive file access and outbound session | CRITICAL | Heuristic Sequence |
| **RULE_F** | Download Lacking Navigation Precursor | File download recorded without preceding browser record in history | MEDIUM | Inferred Gap |

Every correlation finding provides:
- Supporting event identifiers
- Explicit limitations and alternative benign explanations
- Recommended next forensic investigative steps

---

## 7. Forensic Integrity & Legal Caveats

- **Cryptographic Hashing:** The system calculates SHA-256 digests upon ingestion to establish an immutable internal integrity reference. Hashing after receipt verifies subsequent file consistency, not pre-ingestion authenticity.
- **Observed vs. Inferred:** Observed badges indicate raw log records. Inferred badges indicate algorithmic correlations or hypothesized gaps.
- **Forensic Disclaimer:** This tool is an investigative aid for triage. Temporal proximity does not constitute definitive legal proof of malicious intent or unauthorized action.

---

## 8. Hackathon Presentation Walkthrough (3-Minute Demo)

1. **Command Center (`/`):** Point out live derived metrics, total events (16), 0 mock counters, and the 5 top correlation findings.
2. **Rewindable Timeline (`/timeline`):**
   - Click **Restart** to return to 10:00:15.
   - Click **Play** at 1.0x or scrub the time slider manually.
   - Show how the table and system state update dynamically while never revealing future events before their time.
   - Filter by source (`usb` or `file`) or severity (`critical`).
3. **System State (`/state`):** Scrub to `10:15:30` and demonstrate active sessions, mounted USB storage `SN-99482710` on `E:\`, and `customer_database_q3.csv` marked as `COPIED`.
4. **Ghost Evidence (`/ghost`):** Explain how the system objectively highlights the 40-minute browser coverage gap without prematurely assuming malicious anti-forensics.
5. **Incident Graph (`/graph`):** Demonstrate the SVG entity graph linking `alice` → `workstation-01` → `cust_db_tool.exe` → `Kingston USB`. Click nodes and edges to show supporting log IDs.
6. **Investigator Workspace (`/investigate`):** Show automated evaluation of standard questions (e.g. *"What happened immediately before the download?"*) and add a triage note to the chain-of-custody log.
7. **Generate Report (`/report`):** Click **Generate Report** or **Print Dossier** to preview the print-ready forensic dossier.

---

## 9. Feature 1: Conclusion Stress Tester (`/stress-test`)

The **Conclusion Stress Tester** acts as an adversarial verification engine. It evaluates whether incident findings and investigator deductions are genuinely substantiated by recorded digital telemetry or exceed what the evidence establishes.

### Objective & Analytical Categories
Findings are evaluated against deterministic forensic rules without external AI dependencies, assigning transparent analytical assessments:
- **Supported by available evidence:** All sequence stages corroborated by verified independent records.
- **Partially supported:** Single-stream telemetry or minor analytical caveats identified.
- **Requires investigator review:** Uncorroborated event references, potential intent over-claims, or unverified process lineage.
- **Insufficient evidence:** Telemetry does not substantiate the core conclusion (e.g. asserting file copy when only USB connection and access occurred).
- **Contradictory evidence found:** Conflicting records detected in case telemetry (e.g. activity attributed while actor was logged out).

### Adversarial Verification Rules:
1. **USB Copy Over-Claim Detection (Scenario D):** Flags claims asserting "the customer database was copied to a USB device" when logs only record device insertion and file access without a volume write or copy event.
2. **Duplicate Corroboration Detection:** Identifies repeated event IDs or identical log records, preventing duplicate ingestion from masquerading as independent multi-source corroboration.
3. **Chronological & Sequence Integrity:** Validates that precursor events occurred prior to consequential actions and detects inverted timestamps.
4. **Process Lineage Checks:** Warns when network exfiltration is correlated to a downloaded binary solely by temporal proximity without EDR process tree lineage.
5. **Real Database Linking:** Every cited event record links directly to the immutable record in SQLite and the interactive timeline (`/timeline?case_id=...&event_id=...`).

### REST API Endpoints:
- `GET /api/stress-test?case_id=...`: Evaluates all correlation findings for a case.
- `GET /api/stress-test/<finding_id>?case_id=...`: Evaluates a specific finding.
- `POST /api/stress-test/custom`: Evaluates an investigator's proposed custom hypothesis against specified event IDs.

---

## 10. Feature 2: Investigation Time Machine (`/time-machine`)

The **Investigation Time Machine** provides meta-historical tracking for the investigation itself. It preserves immutable snapshots of the analysis state over time and lets examiners understand how new evidence shifts conclusions.

### Core Capabilities:
1. **Immutable Snapshots:** Captures named analysis milestones with timestamp, rule version, evidence file references, finding statuses, investigator notes, and a cryptographic **SHA-256 integrity hash**.
2. **Integrity Tampering Detection:** Re-computes canonical hashes across stored findings and evidence files; immediately flags unauthorized modifications (`✓ SHA-256 OK` vs `⚠ TAMPERED`).
3. **Deep Milestone Comparison:**
   - **Added Findings:** Identifies new conclusions generated by newly ingested evidence.
   - **Changed Findings:** Pinpoints status changes (e.g. `open` → `resolved`) or modified supporting event sets with plain-language forensic attribution.
   - **Removed Findings:** Highlights omitted findings without falsely claiming a hypothesis was disproven.
   - **Unchanged Findings:** Confirms stable analytical conclusions across milestones.
   - **Evidence Provenance Delta:** Compares files added or excluded with SHA-256 hash validation.
   - **Newly Detected Contradictions:** Highlights contradictions introduced by newly added telemetry.
4. **Timeline Integration:** Navigates directly from changed findings in comparison views to supporting events in the interactive incident timeline.

### REST API Endpoints:
- `GET /api/snapshots?case_id=...`: Lists saved snapshots with integrity verification status.
- `POST /api/snapshots`: Captures a new immutable snapshot.
- `GET /api/snapshots/<snapshot_id>`: Retrieves full snapshot state and verifies SHA-256 integrity.
- `GET /api/snapshots/compare?case_id=...&snapshot_a_id=...&snapshot_b_id=...`: Performs deep side-by-side comparison.

---

## 11. Feature 3: Evidence-Grounded AI Investigation Copilot (`/copilot`)

The **Evidence-Grounded AI Investigation Copilot** provides real conversational intelligence for digital forensics examiners while maintaining zero tolerance for hallucinations, prompt injections, or unsubstantiated conclusions.

### Architecture & Grounding Principles
1. **Zero Secret Exposure:** API keys are never exposed to browser frontends, HTML source, logs, or API responses. They remain strictly in server-side environment variables (`OPENAI_API_KEY`).
2. **Offline-Capable Adapter Architecture:** Built on `BaseAIProvider` with `OpenAIProvider`. Attempts the official `openai` SDK if installed and seamlessly falls back to standard Python standard library `urllib.request`. The entire system and test suite operate 100% offline without mandatory pip dependencies or external network calls.
3. **Bounded Parameterized Retrieval:** Queries are strictly bounded to the active `case_id`, retrieving up to 20 chronological telemetry events, correlation findings, ghost evidence coverage gaps, and snapshot diffs. Arbitrary SQL execution or database modifications from the Copilot are completely prohibited.
4. **Adversarial Prompt-Injection Defense:** All retrieved telemetry is treated as untrusted, passive forensic data wrapped inside explicit `<evidence_dataset>` XML boundaries. Any instructions contained within logs or file names (e.g. *"ignore previous instructions"*, *"reveal secrets"*) are treated as malicious artifact text rather than executive prompt commands. Control characters and XML tag escapes are sanitized server-side.
5. **Strict Forensic Grounding Rules:**
   - **Scenario D USB Copy Restraint:** Device connection proximate to file access does not prove a file was transferred. The Copilot explicitly notes missing volume write records.
   - **Distinguishing Facts from Inferences:** Clearly differentiates observed telemetry logs from algorithmic deductions or hypotheses.
   - **Missing Evidence as Unknown:** Unrecorded telemetry is treated as *unknown*, never as proof an action did not occur.
   - **No Intent Attribution:** Never invents or assumes malicious intent without direct forensic evidence.
6. **Server-Side Python Citation Validation:**
   - Every factual claim must cite an event ID in brackets (e.g. `[EVT-010]`).
   - Python extracts citations via regex and verifies each cited ID against actual database records retrieved for that case.
   - Valid citations are enriched with timestamps, actor, object, and clickable links to `/timeline` and `/evidence`.
   - Hallucinated event IDs (e.g. `[EVT-999]`) are intercepted server-side and sanitized to `[Unverified Ref: EVT-999]`, preventing broken links.

### Environment Configuration & Render Deployment
Configure the following environment variables in local development (`.env`) or on your hosting provider (Render, Railway, Fly.io):

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OPENAI_API_KEY` | *(None)* | Secret API key for OpenAI Copilot. If omitted, app operates normally and Copilot reports unconfigured status. |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model identifier (e.g. `gpt-4o-mini`, `gpt-4o`, `gpt-3.5-turbo`). |
| `AI_REQUEST_TIMEOUT`| `25` | Server-side timeout in seconds for upstream AI completion calls. |
| `AI_MAX_OUTPUT_TOKENS` | `1024` | Maximum token ceiling for model generation. |

### REST API Endpoints:
- `GET /copilot?case_id=...`: Interactive Copilot investigator chat UI.
- `GET /api/copilot/status`: Returns provider availability without leaking credentials.
- `POST /api/copilot/chat`: Submits forensic question with recent chat context, returns grounded answer and validated citations.



