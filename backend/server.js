import http from 'node:http';
import { URL } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { db, insertEvent, getEvents, getAllEvents, getHoneypots } from './db.js';
import { classifyEventRules, buildAttackChain } from './threatEngine.js';
import { generateReport } from './reportGenerator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 4000;

// ML Integration - check if ML server is available
let mlAvailable = false;
let mlCheckDone = false;

async function checkMLHealth() {
    if (mlCheckDone) return mlAvailable;
    try {
        const response = await fetch('http://localhost:5000/health');
        mlAvailable = response.ok;
        mlCheckDone = true;
        console.log(`[ML] Server status: ${mlAvailable ? '✅ Available' : '❌ Unavailable'}`);
    } catch (e) {
        mlAvailable = false;
        mlCheckDone = true;
        console.log('[ML] Server unavailable, using rule-based classifier');
    }
    return mlAvailable;
}

async function classifyWithML(features) {
    try {
        const response = await fetch('http://localhost:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ features })
        });
        if (!response.ok) throw new Error('ML server error');
        const data = await response.json();
        return {
            attack_type: data.attack_type,
            confidence: data.confidence,
            source: 'ML'
        };
    } catch (e) {
        return null;
    }
}

function extractFeatures(evt, recentEvents = []) {
    const payload = evt.payload || '';
    const failedAttempts = recentEvents.filter(
        e => e.event_type === 'LOGIN_ATTEMPT' && e.status === 'failed'
    ).length;
    const requestCount = recentEvents.length;

    return [
        requestCount,
        failedAttempts,
        payload.length,
        evt.protocol === 'SSH' ? 1 : 0,
        evt.protocol === 'HTTP' ? 1 : 0,
        evt.protocol === 'DB' ? 1 : 0,
        evt.event_type === 'LOGIN_ATTEMPT' ? 1 : 0,
        /union\s+select|or\s+'?1'?=?'?1|drop\s+table|;\s*select/i.test(payload) ? 1 : 0,
        /<script|onerror\s*=|javascript:|<img[^>]+onerror/i.test(payload) ? 1 : 0,
        /;\s*(?:cat|ls|whoami|wget|curl|nc|bash|sh)\b|\|\s*(?:cat|ls|whoami)\b|`.*`/i.test(payload) ? 1 : 0
    ];
}

function send(res, status, body) {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    });
    res.end(JSON.stringify(body));
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => (data += chunk));
        req.on('end', () => {
            if (!data) return resolve({});
            try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
        });
    });
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (req.method === 'OPTIONS') return send(res, 204, {});

    // Serve static JS files from frontend folder
    if (req.method === 'GET' && url.pathname.endsWith('.js')) {
        const filePath = path.join(__dirname, '..', 'frontend', url.pathname);
        try {
            const content = fs.readFileSync(filePath);
            res.writeHead(200, { 'Content-Type': 'application/javascript' });
            return res.end(content);
        } catch (err) {
            return send(res, 404, { error: 'File not found: ' + url.pathname });
        }
    }

    // Serve the static frontend dashboard
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const htmlPath = path.join(__dirname, '..', 'frontend', 'index.html');
        try {
            const html = fs.readFileSync(htmlPath);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            return res.end(html);
        } catch (err) {
            console.error('Frontend file not found:', htmlPath);
            return send(res, 404, { error: 'Frontend not found' });
        }
    }

    try {
        // POST /api/events
        if (req.method === 'POST' && url.pathname === '/api/events') {
            const body = await readBody(req);
            const timestamp = body.timestamp || new Date().toISOString();
            const source_ip = body.source_ip || 'unknown';

            const recent = getAllEvents().filter(e => e.source_ip === source_ip).slice(-200);
            const evt = { ...body, timestamp, source_ip };

            // Try ML classification first
            await checkMLHealth();
            let mlResult = null;
            if (mlAvailable) {
                const features = extractFeatures(evt, recent);
                mlResult = await classifyWithML(features);
            }

            let attack_type, confidence, severity, severity_score, source;
            if (mlResult && mlResult.attack_type) {
                // Use ML result
                const ruleResult = classifyEventRules(evt, recent);
                attack_type = mlResult.attack_type;
                confidence = mlResult.confidence;
                severity = ruleResult.severity;
                severity_score = ruleResult.severity_score;
                source = 'ML';
                console.log(`[ML] ${source_ip}: ${attack_type} (${severity})`);
            } else {
                // Fallback to rules
                const ruleResult = classifyEventRules(evt, recent);
                attack_type = ruleResult.attack_type;
                confidence = ruleResult.confidence;
                severity = ruleResult.severity;
                severity_score = ruleResult.severity_score;
                source = 'RULES';
                console.log(`[RULES] ${source_ip}: ${attack_type} (${severity})`);
            }

            const id = insertEvent({ ...evt, attack_type, confidence, severity, severity_score, session_id: source_ip });
            return send(res, 201, { id, attack_type, confidence, severity, severity_score, source });
        }

        // GET /api/events
        if (req.method === 'GET' && url.pathname === '/api/events') {
            const limit = Number(url.searchParams.get('limit') || 200);
            const source_ip = url.searchParams.get('source_ip') || undefined;
            const attack_type = url.searchParams.get('attack_type') || undefined;
            const severity = url.searchParams.get('severity') || undefined;
            return send(res, 200, getEvents({ limit, source_ip, attack_type, severity }));
        }

        // GET /api/stats
        if (req.method === 'GET' && url.pathname === '/api/stats') {
            const all = getAllEvents();
            const byType = {};
            const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
            const bucket = {};
            const sources = new Set();

            for (const e of all) {
                byType[e.attack_type] = (byType[e.attack_type] || 0) + 1;
                if (e.severity) bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
                sources.add(e.source_ip);
                const d = new Date(e.timestamp);
                const key = isNaN(d) ? 'unknown' : `${d.getHours()}:${String(Math.floor(d.getMinutes() / 5) * 5).padStart(2, '0')}`;
                bucket[key] = (bucket[key] || 0) + 1;
            }

            return send(res, 200, {
                total_events: all.length,
                total_attackers: sources.size,
                critical_threats: bySeverity.CRITICAL,
                by_type: byType,
                by_severity: bySeverity,
                timeline: Object.entries(bucket).map(([time, count]) => ({ time, count })),
            });
        }

        // GET /api/sessions
        if (req.method === 'GET' && url.pathname === '/api/sessions') {
            const all = getAllEvents();
            const grouped = {};
            for (const e of all) {
                grouped[e.source_ip] = grouped[e.source_ip] || [];
                grouped[e.source_ip].push(e);
            }
            const sessions = Object.entries(grouped).map(([ip, events]) => {
                const maxScore = Math.max(...events.map(e => e.severity_score || 0));
                const { chain, likely_next } = buildAttackChain(events);
                return {
                    source_ip: ip,
                    event_count: events.length,
                    first_seen: events[0].timestamp,
                    last_seen: events[events.length - 1].timestamp,
                    max_severity_score: maxScore,
                    attack_chain: chain,
                    likely_next_action: likely_next,
                    events: events.slice(-20),
                };
            }).sort((a, b) => b.max_severity_score - a.max_severity_score);
            return send(res, 200, sessions);
        }

        // GET /api/report/:source_ip
        if (req.method === 'GET' && url.pathname.startsWith('/api/report/')) {
            const ip = decodeURIComponent(url.pathname.replace('/api/report/', ''));
            const events = getAllEvents().filter(e => e.source_ip === ip);
            const report = generateReport(events);
            if (!report) return send(res, 404, { error: 'No events for this source' });
            return send(res, 200, report);
        }

        // GET /api/honeypots
        if (req.method === 'GET' && url.pathname === '/api/honeypots') {
            return send(res, 200, getHoneypots());
        }

        return send(res, 404, { error: 'Not found' });
    } catch (err) {
        console.error(err);
        return send(res, 500, { error: err.message });
    }
});

server.listen(PORT, () => {
    console.log(`🛡️  Honeypot Orchestrator backend running at http://localhost:${PORT}`);
    console.log(`   Dashboard:  http://localhost:${PORT}/`);
    console.log(`   API:        http://localhost:${PORT}/api/events`);
});
