// threatEngine.js — Real-time attack classification + severity scoring
// Now with ML integration!

import { predictWithML, extractFeatures, checkMLHealth } from './mlClient.js';

const SQLI_PATTERNS = [/union\s+select/i, /'\s*or\s*'?1'?=?'?1/i, /--\s*$/, /drop\s+table/i, /;\s*select/i];
const XSS_PATTERNS = [/<script/i, /onerror\s*=/i, /javascript:/i, /<img[^>]+onerror/i];
const CMD_PATTERNS = [/;\s*(cat|ls|whoami|wget|curl|nc|bash|sh)\b/i, /\|\s*(cat|ls|whoami)\b/i, /`.*`/];

// Cache ML health status
let mlHealthy = false;
let mlCheckDone = false;

export async function classifyEventML(evt, recentBySourceIp = []) {
    // Check if ML server is healthy (only once)
    if (!mlCheckDone) {
        const health = await checkMLHealth();
        mlHealthy = health.healthy;
        mlCheckDone = true;
        console.log(`[ML] Server status: ${mlHealthy ? '✅ Healthy' : '❌ Unavailable'}`);
    }

    // If ML is healthy, use it for prediction
    if (mlHealthy) {
        try {
            const features = extractFeatures(evt, recentBySourceIp);
            const result = await predictWithML(features);
            
            if (result.success) {
                const severity_score = scoreThreatML(result.attack_type, recentBySourceIp, evt);
                const severity = scoreToSeverity(severity_score);
                
                return {
                    attack_type: result.attack_type,
                    confidence: result.confidence,
                    severity,
                    severity_score,
                    source: 'ML'
                };
            }
        } catch (err) {
            console.warn('[ML] Prediction failed, falling back to rules:', err.message);
        }
    }

    // Fallback to rule-based classification
    const ruleResult = classifyEventRules(evt, recentBySourceIp);
    return { ...ruleResult, source: 'RULES' };
}

// Original rule-based classifier (renamed)
export function classifyEventRules(evt, recentBySourceIp = []) {
    const payload = evt.payload || '';
    const failedAttemptsFromIp = recentBySourceIp.filter(
        e => e.event_type === 'LOGIN_ATTEMPT' && e.status === 'failed'
    ).length;
    const requestCountFromIp = recentBySourceIp.length;

    let attack_type = 'Reconnaissance';
    let confidence = 0.6;

    if (evt.protocol === 'SSH' && evt.event_type === 'LOGIN_ATTEMPT') {
        if (failedAttemptsFromIp >= 3) {
            attack_type = 'Brute Force';
            confidence = Math.min(0.99, 0.7 + failedAttemptsFromIp * 0.03);
        } else {
            attack_type = 'Credential Attack';
            confidence = 0.65;
        }
    } else if (evt.protocol === 'HTTP') {
        if (SQLI_PATTERNS.some(p => p.test(payload))) {
            attack_type = 'SQL Injection';
            confidence = 0.95;
        } else if (XSS_PATTERNS.some(p => p.test(payload))) {
            attack_type = 'XSS';
            confidence = 0.93;
        } else if (CMD_PATTERNS.some(p => p.test(payload))) {
            attack_type = 'Command Injection';
            confidence = 0.9;
        } else if (/\/(admin|config|\.env|\.git|api\/keys)/i.test(evt.target || '')) {
            attack_type = 'Suspicious HTTP';
            confidence = 0.75;
        } else if (requestCountFromIp >= 5) {
            attack_type = 'Scanning';
            confidence = 0.8;
        } else {
            attack_type = 'Reconnaissance';
            confidence = 0.55;
        }
    } else if (evt.protocol === 'DB') {
        attack_type = SQLI_PATTERNS.some(p => p.test(payload)) ? 'SQL Injection' : 'Suspicious HTTP';
        confidence = 0.85;
    } else if (evt.event_type === 'PORT_SCAN') {
        attack_type = 'Scanning';
        confidence = 0.9;
    }

    const severity_score = scoreThreatRules({ attack_type, failedAttemptsFromIp, requestCountFromIp, evt });
    const severity = scoreToSeverity(severity_score);

    return { attack_type, confidence: Number(confidence.toFixed(2)), severity, severity_score };
}

// ML-based severity scoring
function scoreThreatML(attack_type, recentBySourceIp, evt) {
    const failedAttemptsFromIp = recentBySourceIp.filter(
        e => e.event_type === 'LOGIN_ATTEMPT' && e.status === 'failed'
    ).length;
    const requestCountFromIp = recentBySourceIp.length;

    let score = 0;
    if (requestCountFromIp > 10) score += 20;
    if (['SSH', 'DB'].includes(evt.protocol)) score += 20;
    if (failedAttemptsFromIp >= 3) score += 15;
    if (['SQL Injection', 'XSS', 'Command Injection'].includes(attack_type)) score += 25;
    if (attack_type === 'Brute Force' || attack_type === 'Credential Attack') score += 20;
    return Math.max(0, Math.min(100, score));
}

// Rule-based severity scoring (original)
function scoreThreatRules({ attack_type, failedAttemptsFromIp, requestCountFromIp, evt }) {
    let score = 0;
    if (requestCountFromIp > 10) score += 20;
    if (['SSH', 'DB'].includes(evt.protocol)) score += 20;
    if (failedAttemptsFromIp >= 3) score += 15;
    if (['SQL Injection', 'XSS', 'Command Injection'].includes(attack_type)) score += 25;
    if (attack_type === 'Brute Force' || attack_type === 'Credential Attack') score += 20;
    return Math.max(0, Math.min(100, score));
}

function scoreToSeverity(score) {
    if (score >= 76) return 'CRITICAL';
    if (score >= 51) return 'HIGH';
    if (score >= 26) return 'MEDIUM';
    return 'LOW';
}

// Attack-chain stage classification
const STAGE_MAP = {
    'Reconnaissance': 'RECON',
    'Scanning': 'DISCOVERY',
    'Credential Attack': 'CREDENTIAL ATTACK',
    'Brute Force': 'CREDENTIAL ATTACK',
    'SQL Injection': 'ACCESS ATTEMPT',
    'XSS': 'ACCESS ATTEMPT',
    'Command Injection': 'COMMAND EXECUTION',
    'Suspicious HTTP': 'DISCOVERY',
};
const NEXT_STAGE = {
    'RECON': 'DISCOVERY',
    'DISCOVERY': 'CREDENTIAL ATTACK',
    'CREDENTIAL ATTACK': 'ACCESS ATTEMPT',
    'ACCESS ATTEMPT': 'COMMAND EXECUTION',
    'COMMAND EXECUTION': 'DATA EXFILTRATION (predicted)',
};

export function buildAttackChain(events) {
    const stages = events.map(e => STAGE_MAP[e.attack_type] || 'RECON');
    const uniqueOrdered = [...new Set(stages)];
    const currentStage = uniqueOrdered[uniqueOrdered.length - 1] || 'RECON';
    return {
        chain: uniqueOrdered,
        likely_next: NEXT_STAGE[currentStage] || 'UNKNOWN',
    };
}                           