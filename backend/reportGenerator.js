const RECOMMENDATIONS = {
  'Brute Force': ['Enable multi-factor authentication', 'Restrict SSH exposure to trusted IPs', 'Apply login rate limiting', 'Monitor authentication logs for repeated failures'],
  'Credential Attack': ['Enforce strong password policy', 'Enable account lockout after failed attempts', 'Enable MFA'],
  'SQL Injection': ['Use parameterized queries / prepared statements', 'Deploy a Web Application Firewall', 'Sanitize and validate all inputs'],
  'XSS': ['Sanitize user input and encode output', 'Apply a strict Content-Security-Policy', 'Use HttpOnly cookies'],
  'Command Injection': ['Never pass unsanitized input to shell commands', 'Use allow-lists for permitted commands', 'Run services with least-privilege accounts'],
  'Scanning': ['Rate-limit and monitor port scanning behaviour', 'Deploy network intrusion detection', 'Restrict unused ports/services'],
  'Reconnaissance': ['Monitor unusual access patterns', 'Reduce exposed service banners/fingerprints'],
  'Suspicious HTTP': ['Review and restrict sensitive endpoints (/admin, /config)', 'Add authentication to internal endpoints'],
};

export function generateReport(sessionEvents) {
  if (!sessionEvents.length) return null;
  const sourceIp = sessionEvents[0].source_ip;
  const attackCounts = {};
  let maxScore = 0;
  let dominantType = null;

  for (const e of sessionEvents) {
    attackCounts[e.attack_type] = (attackCounts[e.attack_type] || 0) + 1;
    if ((e.severity_score || 0) > maxScore) maxScore = e.severity_score || 0;
  }
  dominantType = Object.entries(attackCounts).sort((a, b) => b[1] - a[1])[0][0];

  const threatLevel = maxScore >= 76 ? 'CRITICAL' : maxScore >= 51 ? 'HIGH' : maxScore >= 26 ? 'MEDIUM' : 'LOW';
  const recs = RECOMMENDATIONS[dominantType] || ['Continue monitoring this source.'];
  const first = sessionEvents[0].timestamp;
  const last = sessionEvents[sessionEvents.length - 1].timestamp;

  const objectiveMap = {
    'Brute Force': 'Credential compromise via automated password guessing.',
    'Credential Attack': 'Unauthorized account access.',
    'SQL Injection': 'Database compromise or data exfiltration.',
    'XSS': 'Client-side session hijacking or credential theft.',
    'Command Injection': 'Remote code execution / full host compromise.',
    'Scanning': 'Service and vulnerability discovery ahead of a targeted attack.',
    'Reconnaissance': 'Information gathering for a future attack.',
    'Suspicious HTTP': 'Discovery of exposed administrative interfaces.',
  };

  return {
    source_ip: sourceIp,
    threat_level: threatLevel,
    dominant_attack_type: dominantType,
    total_events: sessionEvents.length,
    window: { first, last },
    narrative:
      `Threat Level: ${threatLevel}\n\n` +
      `Attack Type: ${dominantType}\n\n` +
      `Observed Activity: ${sessionEvents.length} events were detected from source ${sourceIp} between ${first} and ${last}, ` +
      `spanning ${Object.keys(attackCounts).length} distinct technique(s): ${Object.entries(attackCounts).map(([k, v]) => `${k} (${v})`).join(', ')}.\n\n` +
      `Attacker Behavior: The activity pattern is consistent with ${dominantType.toLowerCase()}, ` +
      `suggesting a deliberate, automated or semi-automated probing effort rather than incidental traffic.\n\n` +
      `Potential Objective: ${objectiveMap[dominantType] || 'Unclear objective; continue monitoring.'}\n\n` +
      `Recommended Actions:\n${recs.map(r => `• ${r}`).join('\n')}`,
    recommendations: recs,
  };
}
