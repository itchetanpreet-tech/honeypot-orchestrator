import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_DIR = path.join(__dirname, '..', 'database');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const DB_PATH = path.join(DB_DIR, 'honeypot.db');

export const db = new DatabaseSync(DB_PATH);

db.exec(`
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  target TEXT NOT NULL,
  protocol TEXT NOT NULL,
  event_type TEXT NOT NULL,
  username TEXT,
  password TEXT,
  payload TEXT,
  status TEXT,
  attack_type TEXT,
  confidence REAL,
  severity TEXT,
  severity_score INTEGER,
  session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

CREATE TABLE IF NOT EXISTS honeypots (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE'
);
`);

// Seed default honeypots if empty
const count = db.prepare('SELECT COUNT(*) AS c FROM honeypots').get().c;
if (count === 0) {
  const insert = db.prepare('INSERT INTO honeypots (id, name, protocol, status) VALUES (?, ?, ?, ?)');
  insert.run('SSH-01', 'SSH Honeypot', 'SSH', 'ACTIVE');
  insert.run('HTTP-01', 'HTTP Honeypot', 'HTTP', 'ACTIVE');
  insert.run('DB-01', 'Database Honeypot', 'DB', 'ACTIVE');
}

export function insertEvent(evt) {
  const stmt = db.prepare(`
    INSERT INTO events
      (timestamp, source_ip, target, protocol, event_type, username, password, payload, status,
       attack_type, confidence, severity, severity_score, session_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const info = stmt.run(
    evt.timestamp, evt.source_ip, evt.target, evt.protocol, evt.event_type,
    evt.username ?? null, evt.password ?? null, evt.payload ?? null, evt.status ?? null,
    evt.attack_type ?? null, evt.confidence ?? null, evt.severity ?? null,
    evt.severity_score ?? 0, evt.session_id ?? evt.source_ip
  );
  return info.lastInsertRowid;
}

export function getEvents({ limit = 100, offset = 0, source_ip, attack_type, severity } = {}) {
  let query = 'SELECT * FROM events WHERE 1=1';
  const params = [];
  if (source_ip) { query += ' AND source_ip = ?'; params.push(source_ip); }
  if (attack_type) { query += ' AND attack_type = ?'; params.push(attack_type); }
  if (severity) { query += ' AND severity = ?'; params.push(severity); }
  query += ' ORDER BY id DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  return db.prepare(query).all(...params);
}

export function getAllEvents() {
  return db.prepare('SELECT * FROM events ORDER BY id ASC').all();
}

export function getHoneypots() {
  const hps = db.prepare('SELECT * FROM honeypots').all();
  return hps.map(hp => {
    const c = db.prepare('SELECT COUNT(*) AS c FROM events WHERE target = ?').get(hp.id).c;
    return { ...hp, attacks: c };
  });
}
