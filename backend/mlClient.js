// mlClient.js — ML Model API Client for Honeypot Orchestrator
// Calls Python ML microservice for predictions

const ML_SERVER_URL = process.env.ML_SERVER_URL || 'http://localhost:5000';

/**
 * Call ML model to predict attack type
 * @param {Array} features - Array of 10 feature values
 * @returns {Promise<Object>} Prediction result
 */
export async function predictWithML(features) {
    try {
        const response = await fetch(`${ML_SERVER_URL}/predict`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ features })
        });

        if (!response.ok) {
            throw new Error(`ML Server error: ${response.status}`);
        }

        const data = await response.json();
        return {
            success: true,
            attack_type: data.attack_type,
            confidence: data.confidence,
            features_used: data.features_used
        };
    } catch (error) {
        console.error('ML Prediction failed:', error.message);
        return {
            success: false,
            error: error.message,
            attack_type: null,
            confidence: 0
        };
    }
}

/**
 * Check if ML server is healthy
 * @returns {Promise<Object>} Health status
 */
export async function checkMLHealth() {
    try {
        const response = await fetch(`${ML_SERVER_URL}/health`);
        if (!response.ok) return { healthy: false };
        const data = await response.json();
        return { 
            healthy: true, 
            classes: data.classes,
            features: data.features 
        };
    } catch (error) {
        return { healthy: false, error: error.message };
    }
}

/**
 * Extract features from event for ML prediction
 * @param {Object} evt - Event object
 * @param {Array} recentEvents - Recent events from same IP
 * @returns {Array} Feature array (10 values)
 */
export function extractFeatures(evt, recentEvents = []) {
    const payload = evt.payload || '';
    const failedAttempts = recentEvents.filter(
        e => e.event_type === 'LOGIN_ATTEMPT' && e.status === 'failed'
    ).length;
    const requestCount = recentEvents.length;

    return [
        requestCount,                                    // request_count
        failedAttempts,                                  // failed_attempts
        payload.length,                                  // payload_length
        evt.protocol === 'SSH' ? 1 : 0,                  // is_ssh
        evt.protocol === 'HTTP' ? 1 : 0,                 // is_http
        evt.protocol === 'DB' ? 1 : 0,                   // is_db
        evt.event_type === 'LOGIN_ATTEMPT' ? 1 : 0,      // has_login
        hasSQLiPattern(payload) ? 1 : 0,                 // has_sqli_pattern
        hasXSSPattern(payload) ? 1 : 0,                  // has_xss_pattern
        hasCmdPattern(payload) ? 1 : 0                   // has_cmd_pattern
    ];
}

// Pattern detection helpers
function hasSQLiPattern(text) {
    return /union\s+select|or\s+'?1'?=?'?1|drop\s+table|;\s*select/i.test(text);
}

function hasXSSPattern(text) {
    return /<script|onerror\s*=|javascript:|<img[^>]+onerror/i.test(text);
}

function hasCmdPattern(text) {
    return /;\s*(?:cat|ls|whoami|wget|curl|nc|bash|sh)\b|\|\s*(?:cat|ls|whoami)\b|`.*`/i.test(text);
}