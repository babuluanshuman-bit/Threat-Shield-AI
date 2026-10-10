/**
 * CYBERGUARD COPILOT - AI SOC Analyst Service
 * Powered by Google Gemini 2.0 / 1.5 Flash API
 * Provides dynamic, real-time threat intelligence and reasoning grounded in live SOC telemetry.
 */

import { Threat, Incident, SecurityPosture } from '../types/cyberguard';
import { SocMetrics } from '../data/mockCyberData';

export const DEFAULT_GEMINI_KEY = (import.meta.env.VITE_GEMINI_API_KEY as string) || '';
const STORAGE_KEY = 'CYBERGUARD_GEMINI_KEY';

export interface SocContextData {
  metrics: SocMetrics;
  threats: Threat[];
  incidents: Incident[];
  selectedIncident?: Incident | null;
  posture: SecurityPosture;
}

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  isAiGenerated?: boolean;
  actionButton?: {
    label: string;
    actionType: 'tab' | 'simulation';
    target: string;
  };
}

export function getStoredGeminiKey(): string {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && saved.trim().length > 10) {
      return saved.trim();
    }
  } catch {
    // localStorage might fail in restricted environments
  }
  return DEFAULT_GEMINI_KEY;
}

export function setStoredGeminiKey(key: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, key.trim());
  } catch {
    // ignore
  }
}

/**
 * Builds real-time SOC system instructions to inject into Gemini prompt
 */
function buildSocSystemInstruction(soc: SocContextData): string {
  const criticalThreats = soc.threats.filter((t) => t.severity === 'CRITICAL');
  const highThreats = soc.threats.filter((t) => t.severity === 'HIGH');
  const activeIncidents = soc.incidents.filter((i) => i.status !== 'RESOLVED');
  const selectedInc = soc.selectedIncident || activeIncidents[0] || soc.incidents[0];

  const criticalsSummary = criticalThreats
    .map(
      (t) =>
        `• [CRITICAL] "${t.title}" (Risk: ${t.riskScore}/100, Source: ${t.source} -> Target: ${t.target}, Status: ${t.status})`
    )
    .join('\n');

  const highSummary = highThreats
    .slice(0, 3)
    .map((t) => `• [HIGH] "${t.title}" (Risk: ${t.riskScore}/100, Status: ${t.status})`)
    .join('\n');

  return `You are CYBERGUARD COPILOT, an elite autonomous Security Operations Center (SOC) AI Analyst and Cyber Threat Intelligence reasoning assistant.
You possess deep expertise in cyber incident triage, threat hunting, MITRE ATT&CK tactics, network forensics, phishing identification, malware analysis, identity defense, and autonomous SOAR playbooks.

CURRENT LIVE SOC TELEMETRY CONTEXT:
- Protected Identities/Users: ${soc.metrics.protectedUsers.toLocaleString()}
- Threats Detected Today: ${soc.metrics.threatsDetected}
- Blocked Threats (SOAR): ${soc.metrics.blockedThreats}
- Enterprise Security Posture Score: ${soc.posture?.overallScore ?? soc.metrics.securityScore}/100
- Active / Open Incidents: ${activeIncidents.length} (${soc.incidents.length} total recorded)
- Active Critical Threats (${criticalThreats.length}):
${criticalsSummary || 'None currently active.'}
- High-Risk Threats (${highThreats.length}):
${highSummary || 'None currently active.'}
${
  selectedInc
    ? `- Current Highlighted Incident: [${selectedInc.id}] "${selectedInc.title}" | Target: ${selectedInc.affectedUser} | Severity: ${selectedInc.severity} (${selectedInc.riskScore}/100) | Status: ${selectedInc.status}`
    : ''
}

OPERATIONAL GUIDELINES:
1. Provide authoritative, concise, actionable cybersecurity analysis.
2. Ground explanations directly in the live SOC telemetry above when relevant to the user query.
3. If the user asks about threats, incidents, suspicious URLs/domains, identity compromise, or posture, give concrete forensic explanations, indicators of compromise (IoCs), and MITRE techniques.
4. Format responses cleanly using GitHub-flavored Markdown (concise bullet points, headers with ###, bold keywords, and backticked technical indicators).
5. If the user asks for remediation advice, list prioritized containment steps (e.g., Revoke tokens, DNS sinkhole, Quarantine mailbox, Reset MFA).
6. Maintain an alert, professional SOC Analyst tone. Keep answers punchy and easy to scan during active cyber triage.`;
}

/**
 * Detects relevant actions to suggest as quick-action buttons below the assistant response
 */
export function detectSuggestedAction(
  query: string,
  responseText: string
): { label: string; actionType: 'tab' | 'simulation'; target: string } | undefined {
  const q = query.toLowerCase();
  const r = responseText.toLowerCase();

  if (q.includes('simulation') || q.includes('simulate') || q.includes('phishing attack') || q.includes('test defense')) {
    return {
      label: '⚡ Launch Live Phishing Simulation',
      actionType: 'simulation',
      target: 'scenario-phishing',
    };
  }

  if (q.includes('ransomware') || q.includes('payload') || q.includes('exfiltration')) {
    return {
      label: '🛡️ Simulate Ransomware Incursion',
      actionType: 'simulation',
      target: 'scenario-ransomware',
    };
  }

  if (q.includes('url') || q.includes('domain') || q.includes('link') || q.includes('phish') || r.includes('url scanner')) {
    return {
      label: '🔗 Open URL & Website Analyzer',
      actionType: 'tab',
      target: 'url-scanner',
    };
  }

  if (q.includes('deepfake') || q.includes('media') || q.includes('synthetic') || q.includes('voice') || q.includes('image') || q.includes('video')) {
    return {
      label: '🖼️ Open Deepfake & AI Image Scanner',
      actionType: 'tab',
      target: 'media-scanner',
    };
  }

  if (q.includes('incident') || q.includes('inc-') || q.includes('triage') || r.includes('incident center')) {
    return {
      label: '🚨 Open SOC Command Center',
      actionType: 'tab',
      target: 'dashboard',
    };
  }

  if (q.includes('posture') || q.includes('score') || q.includes('hygiene') || q.includes('compliance')) {
    return {
      label: '📊 Open Security Posture Scorecard',
      actionType: 'tab',
      target: 'posture',
    };
  }

  if (q.includes('file') || q.includes('entropy') || q.includes('hash') || q.includes('malware sample')) {
    return {
      label: '📁 Open File Forensic Scanner',
      actionType: 'tab',
      target: 'file-scanner',
    };
  }

  if (q.includes('network') || q.includes('c2') || q.includes('dns') || q.includes('ip') || q.includes('traffic')) {
    return {
      label: '📡 Open Network Threat Radar',
      actionType: 'tab',
      target: 'network-threat',
    };
  }

  if (q.includes('user') || q.includes('credential') || q.includes('identity') || q.includes('mfa') || q.includes('login') || q.includes('takeover')) {
    return {
      label: '🛡️ View SOC Command Center',
      actionType: 'tab',
      target: 'dashboard',
    };
  }

  return undefined;
}

/**
 * Queries the Google Gemini API with fallback across endpoints and models
 */
export async function queryGeminiCopilot(
  userPrompt: string,
  soc: SocContextData,
  apiKeyOverride?: string
): Promise<{ text: string; source: 'gemini' | 'offline_soc_knowledge'; modelUsed?: string }> {
  const cleanKey = (apiKeyOverride || getStoredGeminiKey()).trim();

  const systemInstructionText = buildSocSystemInstruction(soc);

  // Payload for Gemini Generative Language API
  const requestBody = {
    systemInstruction: {
      parts: [{ text: systemInstructionText }],
    },
    contents: [
      {
        role: 'user',
        parts: [{ text: userPrompt }],
      },
    ],
    generationConfig: {
      temperature: 0.35,
      maxOutputTokens: 1200,
    },
  };

  // We test the fast gemini-flash-lite-latest first, followed by gemini-flash-latest
  const endpoints = [
    // Vite Proxy endpoint (prevents CORS and header manipulation)
    `/api/gemini/v1beta/models/gemini-flash-lite-latest:generateContent?key=${encodeURIComponent(cleanKey)}`,
    // Direct Google Generative Language API endpoint
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-lite-latest:generateContent?key=${encodeURIComponent(cleanKey)}`,
    // Fallback model
    `/api/gemini/v1beta/models/gemini-flash-latest:generateContent?key=${encodeURIComponent(cleanKey)}`,
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${encodeURIComponent(cleanKey)}`,
  ];

  for (const url of endpoints) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': cleanKey,
        },
        body: JSON.stringify(requestBody),
      });

      if (response.ok) {
        const data = await response.json();
        const candidate = data.candidates?.[0];
        const text = candidate?.content?.parts?.[0]?.text;
        if (text && text.trim().length > 0) {
          return {
            text: text.trim(),
            source: 'gemini',
            modelUsed: data.modelVersion || 'gemini-flash-lite',
          };
        }
      } else {
        // If 403 / 400 with invalid key, check next endpoint or fallback
        const errText = await response.text().catch(() => '');
        console.warn(`[CYBERGUARD Copilot] Gemini API attempt failed (${response.status}):`, errText);
      }
    } catch (err) {
      console.warn(`[CYBERGUARD Copilot] Network fetch failed on ${url}:`, err);
    }
  }

  // Fallback to sophisticated local SOC expert reasoning if network / quota blocked
  return {
    text: generateEnhancedSocFallback(userPrompt, soc),
    source: 'offline_soc_knowledge',
  };
}

/**
 * Intelligent local SOC fallback when Gemini API is offline or key quota exhausted
 */
function generateEnhancedSocFallback(query: string, soc: SocContextData): string {
  const q = query.toLowerCase();
  const criticals = soc.threats.filter((t) => t.severity === 'CRITICAL');
  const highs = soc.threats.filter((t) => t.severity === 'HIGH');
  const activeInc = soc.selectedIncident || soc.incidents[0];

  if (q.includes('critical') || q.includes('threat')) {
    return (
      `### 🚨 Critical Threat Telemetry (${criticals.length} Active Vectors)\n\n` +
      criticals
        .map(
          (t, i) =>
            `**${i + 1}. ${t.title}** (Risk: ${t.riskScore}/100 | ${t.severity})\n` +
            `- **Vector:** \`${t.source}\` → \`${t.target}\`\n` +
            `- **Primary Finding:** ${t.indicators[0]?.finding || 'Malicious Payload Signature'}\n` +
            `- **SOAR Containment:** ${t.status}\n`
        )
        .join('\n') +
      `\n> **Analyst Note:** Autonomous SOAR playbooks have actively quarantined high-risk vectors. Review the incident center for detailed forensic traces.`
    );
  }

  if (q.includes('incident') || q.includes('inc-')) {
    return (
      `### 🛡️ Incident Forensics: ${activeInc.id}\n\n` +
      `**Title:** ${activeInc.title}\n` +
      `**Threat Type:** ${activeInc.threatType} | **Severity:** ${activeInc.severity} (Score: ${activeInc.riskScore}/100)\n` +
      `**Target Identity:** \`${activeInc.affectedUser}\`\n\n` +
      `**Telemetry Milestones:**\n` +
      activeInc.timeline.map((t) => `• \`${t.time}\`: ${t.event}`).join('\n') +
      `\n\n**Autonomous Response:** ${activeInc.responseActions.filter((a) => a.executed).length} SOAR mitigations executed with ${activeInc.status} containment status.`
    );
  }

  if (q.includes('user') || q.includes('identity') || q.includes('risk') || q.includes('travel')) {
    return (
      `### 👤 High-Risk Identity & Credential Telemetry\n\n` +
      `1. **Priya Sharma (DevOps Lead)** — Risk: **96/100 (CRITICAL)**\n` +
      `   - *Signals:* 5 consecutive brute-force failures + Berlin IP proxy jump.\n` +
      `   - *Mitigation:* Active sessions revoked; FIDO2 hardware challenge enforced.\n\n` +
      `2. **Alex Morgan (Treasury Analyst)** — Risk: **78/100 (HIGH)**\n` +
      `   - *Signals:* Targeted with urgent spear-phishing wire spoof.\n` +
      `   - *Mitigation:* Mail payload quarantined; credential replay blocked.\n\n` +
      `3. **Kavita Patel (HR Operations)** — Risk: **68/100 (HIGH)**\n` +
      `   - *Signals:* Impossible travel anomaly (Bhubaneswar → Berlin in 4m).`
    );
  }

  if (q.includes('recommend') || q.includes('action') || q.includes('remediat') || q.includes('playbook')) {
    return (
      `### ⚡ SOAR Recommended Response Playbook\n\n` +
      `For ongoing credential compromise and phishing vectors:\n` +
      `1. **Instant Session Revocation:** Terminate all OAuth and Kerberos tokens in IdP.\n` +
      `2. **Edge DNS Sinkhole:** Ingest malicious C2 domains into boundary firewalls.\n` +
      `3. **Hardware Key Enforcement:** Step up authentication to WebAuthn / FIDO2 tokens.\n` +
      `4. **Forensic Snapshot:** Preserve endpoint memory dumps for post-incident RCA.\n\n` +
      `You can trigger a live simulation in the CyberGuard dashboard to test perimeter resilience.`
    );
  }

  if (q.includes('posture') || q.includes('score') || q.includes('status')) {
    return (
      `### 📊 Enterprise Security Posture: ${soc.posture.overallScore}/100\n\n` +
      `- **Web Perimeter:** 91/100 (Strong)\n` +
      `- **SOAR Readiness:** 88/100 (Autonomous playbooks active)\n` +
      `- **Identity & MFA:** 84/100 (FIDO2 migration underway)\n` +
      `- **Email & DMARC:** 76/100 (DMARC quarantine active)\n` +
      `- **Threat Exposure:** 68/100 (Phishing activity elevated)\n\n` +
      `**Remediation Impact:** Completing 3 pending action items will lift enterprise posture by **+13 points**.`
    );
  }

  return (
    `### 🛡️ SOC Telemetry Assessment\n\n` +
    `CYBERGUARD COPILOT is actively monitoring **${soc.metrics.protectedUsers.toLocaleString()} identities** with **${soc.metrics.threatsDetected} threats detected** today. ` +
    `Overall enterprise posture stands at **${soc.metrics.securityScore}/100** with **${criticals.length} critical threats** actively quarantined.\n\n` +
    `**You can ask me to:**\n` +
    `• Investigate specific threats or malicious URLs\n` +
    `• Analyze active security incidents and MITRE tactics\n` +
    `• Inspect high-risk users and credential anomalies\n` +
    `• Recommend SOAR containment playbooks`
  );
}
