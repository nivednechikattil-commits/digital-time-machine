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
│   └── report_generator.py     # Investigation dossier & report compiler
├── parsers/
│   ├── __init__.py
│   ├── csv_parser.py           # CSV evidence parser with line-by-line validation
│   └── json_parser.py          # JSON, JSON-array, and JSONL parser
├── services/
│   ├── __init__.py
│   ├── case_service.py         # Multi-case lifecycle & metrics aggregator
│   └── evidence_service.py     # Safe upload, hashing & duplicate prevention
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
│       └── investigate.js      # Inquiry evaluator & notes journal
└── tests/                      # Automated test suite
    ├── __init__.py
    ├── test_normalizer.py
    ├── test_parsers.py
    ├── test_database.py
    ├── test_state_reconstruction.py
    ├── test_correlator.py
    ├── test_ghost_evidence.py
    ├── test_evidence_service.py
    └── test_api.py
```

---

## 4. Setup and Launch Instructions (Ubuntu / Linux)

### Prerequisites
- Python 3.10+ installed.
- Works **100% offline** without internet access.

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
# Execute the full 34-test suite
python3 run_tests.py

# Or with pytest if installed:
pytest -v
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

