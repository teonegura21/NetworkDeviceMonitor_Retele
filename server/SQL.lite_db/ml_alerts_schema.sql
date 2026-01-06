-- Add ML tracking to Loguri table
ALTER TABLE Loguri ADD COLUMN ml_analyzed BOOLEAN DEFAULT 0;
ALTER TABLE Loguri ADD COLUMN ml_score REAL;

-- Create Alerts table
CREATE TABLE IF NOT EXISTS Alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    rule_id TEXT NOT NULL,
    ml_score REAL,
    severity INTEGER DEFAULT 4,
    state TEXT DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    assigned_to TEXT,
    notes TEXT,
    FOREIGN KEY (event_id) REFERENCES Loguri(id)
);

-- Index for fast queries
CREATE INDEX IF NOT EXISTS idx_alerts_state ON Alerts(state);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON Alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_loguri_ml ON Loguri(ml_analyzed);
