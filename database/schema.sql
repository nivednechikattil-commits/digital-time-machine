-- Digital Time Machine Database Schema
-- SQLite3 compliant with strict parameterization and case isolation

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    status TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS evidence_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_type TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    record_count INTEGER DEFAULT 0,
    valid_count INTEGER DEFAULT 0,
    invalid_count INTEGER DEFAULT 0,
    imported_at TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    object TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'observed',
    details TEXT DEFAULT '{}',
    is_inferred INTEGER DEFAULT 0,
    PRIMARY KEY (case_id, id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS correlation_findings (
    id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    supporting_event_ids TEXT NOT NULL,
    explanation TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    confidence TEXT NOT NULL,
    limitations TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    PRIMARY KEY (case_id, id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    author TEXT DEFAULT 'Investigator',
    note TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

-- Indexes for high-performance timeline scrubbing and filtering
CREATE INDEX IF NOT EXISTS idx_events_case_timestamp ON events(case_id, timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_events_case_source ON events(case_id, source);
CREATE INDEX IF NOT EXISTS idx_events_case_actor ON events(case_id, actor);
CREATE INDEX IF NOT EXISTS idx_events_case_type ON events(case_id, event_type);
CREATE INDEX IF NOT EXISTS idx_evidence_files_case ON evidence_files(case_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_case_sha256 ON evidence_files(case_id, sha256_hash);
CREATE INDEX IF NOT EXISTS idx_findings_case ON correlation_findings(case_id);

-- Investigation Time Machine: Immutable analysis snapshots and integrity tracking
CREATE TABLE IF NOT EXISTS investigation_snapshots (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    name TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    integrity_hash TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS snapshot_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence TEXT,
    supporting_event_ids TEXT,
    explanation TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES investigation_snapshots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS snapshot_evidence_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL,
    evidence_file_id INTEGER,
    filename TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    record_count INTEGER,
    FOREIGN KEY (snapshot_id) REFERENCES investigation_snapshots(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_snapshots_case ON investigation_snapshots(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshot_findings ON snapshot_findings(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_snapshot_evidence ON snapshot_evidence_refs(snapshot_id);



