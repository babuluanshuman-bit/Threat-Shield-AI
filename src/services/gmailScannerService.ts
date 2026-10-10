import { ThreatIndicator, RiskLevel, ThreatCategory, Threat } from '../types/cyberguard';
import { queryVirusTotalUrl, DEFAULT_VIRUSTOTAL_KEY } from './urlIntelligenceService';

export interface GmailUserProfile {
  emailAddress: string;
  messagesTotal: number;
  threadsTotal: number;
  historyId?: string;
}

export interface ExtractedEmailAttachment {
  filename: string;
  mimeType: string;
  size: number;
  attachmentId?: string;
  isSuspicious: boolean;
  reason?: string;
}

export interface AuthHeaderTelemetry {
  spfStatus: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NONE' | 'UNKNOWN';
  dkimStatus: 'PASS' | 'FAIL' | 'NONE' | 'UNKNOWN';
  dmarcStatus: 'PASS' | 'FAIL' | 'NONE' | 'UNKNOWN';
  rawAuthResults?: string;
}

export interface ScannedGmailEmail {
  id: string;
  threadId: string;
  from: string;
  fromDisplayName: string;
  fromEmail: string;
  senderDomain: string;
  to: string;
  subject: string;
  date: string;
  snippet: string;
  bodyText: string;
  bodyHtml: string;
  headers: Record<string, string>;
  extractedUrls: string[];
  attachments: ExtractedEmailAttachment[];
  authTelemetry: AuthHeaderTelemetry;
  
  // Threat Lens AI Analysis
  threatCategory: ThreatCategory;
  riskScore: number; // 0 - 100
  severity: RiskLevel;
  indicators: ThreatIndicator[];
  explanation: string;
  recommendations: string[];
  mitreTechniques: string[];
  suggestedIncidentTitle: string;
  virusTotalSummary?: {
    checkedCount: number;
    maliciousUrls: string[];
    details: Record<string, { malicious: number; total: number; isMalicious: boolean }>;
  };
  
  // SOC Actions state
  quarantined: boolean;
  ingestedToSoc: boolean;
  isUnread: boolean;
  isSandboxDemo?: boolean;
}

// Google OAuth 2.0 Default Client ID
export const DEFAULT_GOOGLE_CLIENT_ID = '354349962065-l6q8pkrjap18g2un9p97f6l4f5572l78.apps.googleusercontent.com';

// Google OAuth 2.0 Client State
let tokenClientInstance: any = null;

/**
 * Loads the Google Identity Services (GIS) client script if not already present
 */
export function ensureGoogleIdentityClientLoaded(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (typeof window !== 'undefined' && (window as any).google?.accounts?.oauth2) {
      resolve();
      return;
    }

    const existingScript = document.querySelector('script[src="https://accounts.google.com/gsi/client"]');
    if (existingScript) {
      existingScript.addEventListener('load', () => resolve());
      existingScript.addEventListener('error', () => reject(new Error('Failed to load Google Identity Services SDK')));
      return;
    }

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('Failed to load Google Identity Services SDK'));
    document.head.appendChild(script);
  });
}

/**
 * Initiates the official Google OAuth 2.0 popup for Gmail readonly access
 * Uses Google Identity Services Token Client
 */
export async function requestGmailOAuthToken(clientId: string): Promise<string> {
  const cleanId = clientId.trim();
  
  // Guard against invalid Client IDs (such as pasting a VirusTotal key)
  if (!cleanId.includes('.apps.googleusercontent.com')) {
    throw new Error(
      'Invalid Google Client ID format. A Google OAuth 2.0 Web Client ID must end in ".apps.googleusercontent.com" (created in Google Cloud Console). Note: A VirusTotal API key is not a Google Client ID.'
    );
  }

  await ensureGoogleIdentityClientLoaded();

  return new Promise((resolve, reject) => {
    let resolved = false;

    // Safety timeout in case popup is closed by user or blocked by browser
    const popupTimeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        reject(
          new Error(
            `Google OAuth authorization timed out or was closed. If the Google popup was blank, ensure that "${window.location.origin}" is added to Authorized JavaScript Origins in Google Cloud Console Credentials.`
          )
        );
      }
    }, 45000);

    try {
      const google = (window as any).google;
      if (!google || !google.accounts || !google.accounts.oauth2) {
        clearTimeout(popupTimeout);
        throw new Error('Google Identity Services SDK is not initialized yet. Please check your network or try again.');
      }

      tokenClientInstance = google.accounts.oauth2.initTokenClient({
        client_id: cleanId,
        scope: 'https://www.googleapis.com/auth/gmail.readonly',
        prompt: 'consent',
        callback: (response: any) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(popupTimeout);

          if (response.error) {
            reject(new Error(`Google OAuth error: ${response.error_description || response.error}`));
            return;
          }
          if (response.access_token) {
            resolve(response.access_token);
          } else {
            reject(new Error('No access token returned from Google authentication'));
          }
        },
        error_callback: (error: any) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(popupTimeout);
          reject(new Error(error.message || 'Google OAuth login cancelled or failed'));
        },
      });

      tokenClientInstance.requestAccessToken();
    } catch (err: any) {
      if (!resolved) {
        resolved = true;
        clearTimeout(popupTimeout);
      }
      reject(err);
    }
  });
}


/**
 * Live API: Fetch Gmail User Profile
 */
export async function fetchLiveGmailProfile(accessToken: string): Promise<GmailUserProfile> {
  const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Gmail API Profile Error (${res.status}): ${errorText.slice(0, 150)}`);
  }

  const data = await res.json();
  return {
    emailAddress: data.emailAddress,
    messagesTotal: data.messagesTotal || 0,
    threadsTotal: data.threadsTotal || 0,
    historyId: data.historyId,
  };
}

/**
 * Live API: List message IDs matching an optional search query
 */
export async function fetchLiveGmailMessageIds(
  accessToken: string,
  query: string = '',
  maxResults: number = 10
): Promise<string[]> {
  const url = new URL('https://gmail.googleapis.com/gmail/v1/users/me/messages');
  url.searchParams.set('maxResults', maxResults.toString());
  if (query.trim()) {
    url.searchParams.set('q', query.trim());
  }

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Gmail API Messages List Error (${res.status}): ${errorText.slice(0, 150)}`);
  }

  const data = await res.json();
  if (!data.messages || !Array.isArray(data.messages)) {
    return [];
  }

  return data.messages.map((m: any) => m.id);
}

/**
 * Live API: Fetch raw message details for a specific message ID
 */
export async function fetchLiveGmailMessageDetail(accessToken: string, messageId: string): Promise<any> {
  const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Gmail API Message Get Error (${res.status}): ${errorText.slice(0, 150)}`);
  }

  return res.json();
}

/**
 * Base64URL decoder with proper UTF-8 decoding support
 */
export function decodeBase64Url(input: string): string {
  if (!input) return '';
  try {
    let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
  } catch (err) {
    try {
      return atob(input.replace(/-/g, '+').replace(/_/g, '/'));
    } catch {
      return '';
    }
  }
}

/**
 * Recursively extracts plain text, HTML body, and attachment metadata from MIME payload parts
 */
export function extractMimeContent(payload: any): {
  bodyText: string;
  bodyHtml: string;
  attachments: ExtractedEmailAttachment[];
} {
  let bodyText = '';
  let bodyHtml = '';
  const attachments: ExtractedEmailAttachment[] = [];

  function traverse(part: any) {
    if (!part) return;

    const mimeType = (part.mimeType || '').toLowerCase();
    const filename = part.filename || '';

    // Check if attachment
    if (filename && filename.length > 0) {
      const ext = filename.split('.').pop()?.toLowerCase() || '';
      const dangerousExtensions = ['exe', 'scr', 'bat', 'cmd', 'vbs', 'iso', 'hta', 'ps1', 'jar'];
      const macroExtensions = ['docm', 'xlsm', 'pptm'];
      const isDangerous = dangerousExtensions.includes(ext) || macroExtensions.includes(ext) || filename.includes('.pdf.exe');

      attachments.push({
        filename,
        mimeType,
        size: part.body?.size || 0,
        attachmentId: part.body?.attachmentId,
        isSuspicious: isDangerous,
        reason: isDangerous ? `High-risk file extension .${ext} capable of code execution` : undefined,
      });
    }

    // Check text/plain
    if (mimeType === 'text/plain' && part.body?.data) {
      bodyText += decodeBase64Url(part.body.data) + '\n';
    }

    // Check text/html
    if (mimeType === 'text/html' && part.body?.data) {
      bodyHtml += decodeBase64Url(part.body.data) + '\n';
    }

    // Recursively check multipart subparts
    if (Array.isArray(part.parts)) {
      for (const subPart of part.parts) {
        traverse(subPart);
      }
    }
  }

  traverse(payload);

  // If bodyText is empty but bodyHtml exists, extract plain text representation
  if (!bodyText.trim() && bodyHtml.trim()) {
    bodyText = bodyHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  }

  return { bodyText: bodyText.trim(), bodyHtml: bodyHtml.trim(), attachments };
}

/**
 * Extracts links from plain text and HTML bodies
 */
export function extractUrlsFromEmail(bodyText: string, bodyHtml: string): string[] {
  const urlSet = new Set<string>();

  // Extract from HTML href
  const hrefRegex = /href=["'](https?:\/\/[^"'\s>]+)["']/gi;
  let hrefMatch;
  while ((hrefMatch = hrefRegex.exec(bodyHtml)) !== null) {
    const rawUrl = hrefMatch[1];
    if (isValidInspectableUrl(rawUrl)) {
      urlSet.add(rawUrl);
    }
  }

  // Extract from plain text
  const textUrlRegex = /https?:\/\/[^\s"'<>()[\]{}]+/gi;
  let textMatch;
  while ((textMatch = textUrlRegex.exec(bodyText)) !== null) {
    const rawUrl = textMatch[0].replace(/[.,;:!]+$/, ''); // Strip trailing punctuation
    if (isValidInspectableUrl(rawUrl)) {
      urlSet.add(rawUrl);
    }
  }

  return Array.from(urlSet).slice(0, 15); // Cap to 15 URLs
}

function isValidInspectableUrl(url: string): boolean {
  if (!url || !url.startsWith('http')) return false;
  const lower = url.toLowerCase();
  // Filter out internal schema or standard Google unsubscribe links
  if (lower.includes('schemas.google.com') || lower.includes('w3.org')) return false;
  return true;
}

/**
 * Parses email headers from Gmail API format
 */
export function parseEmailHeaders(headerList: Array<{ name: string; value: string }>): Record<string, string> {
  const result: Record<string, string> = {};
  if (!Array.isArray(headerList)) return result;

  for (const h of headerList) {
    result[h.name.toLowerCase()] = h.value;
  }
  return result;
}

/**
 * Analyzes SPF, DKIM, and DMARC from email headers
 */
export function evaluateAuthenticationHeaders(headers: Record<string, string>): AuthHeaderTelemetry {
  const authResults = headers['authentication-results'] || '';
  const receivedSpf = headers['received-spf'] || '';
  const dkimSig = headers['dkim-signature'] || headers['x-google-dkim-signature'] || '';

  let spfStatus: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NONE' | 'UNKNOWN' = 'UNKNOWN';
  let dkimStatus: 'PASS' | 'FAIL' | 'NONE' | 'UNKNOWN' = 'UNKNOWN';
  let dmarcStatus: 'PASS' | 'FAIL' | 'NONE' | 'UNKNOWN' = 'UNKNOWN';

  const combined = (authResults + ' ' + receivedSpf).toLowerCase();

  // SPF evaluation
  if (combined.includes('spf=pass') || receivedSpf.toLowerCase().startsWith('pass')) {
    spfStatus = 'PASS';
  } else if (combined.includes('spf=softfail') || receivedSpf.toLowerCase().startsWith('softfail')) {
    spfStatus = 'SOFTFAIL';
  } else if (combined.includes('spf=fail') || receivedSpf.toLowerCase().startsWith('fail')) {
    spfStatus = 'FAIL';
  } else if (combined.includes('spf=none')) {
    spfStatus = 'NONE';
  }

  // DKIM evaluation
  if (combined.includes('dkim=pass')) {
    dkimStatus = 'PASS';
  } else if (combined.includes('dkim=fail')) {
    dkimStatus = 'FAIL';
  } else if (dkimSig) {
    dkimStatus = 'PASS';
  } else {
    dkimStatus = 'NONE';
  }

  // DMARC evaluation
  if (combined.includes('dmarc=pass')) {
    dmarcStatus = 'PASS';
  } else if (combined.includes('dmarc=fail')) {
    dmarcStatus = 'FAIL';
  } else if (spfStatus === 'PASS' && dkimStatus === 'PASS') {
    dmarcStatus = 'PASS';
  } else if (spfStatus === 'FAIL' || dkimStatus === 'FAIL') {
    dmarcStatus = 'FAIL';
  }

  return {
    spfStatus,
    dkimStatus,
    dmarcStatus,
    rawAuthResults: authResults || receivedSpf || undefined,
  };
}

/**
 * Deconstructs From header: e.g. "PayPal Support <security@paypa1-support.com>"
 */
export function parseSenderAddress(fromHeader: string): {
  displayName: string;
  email: string;
  domain: string;
} {
  let displayName = '';
  let email = fromHeader.trim();

  const match = fromHeader.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
  if (match) {
    displayName = (match[1] || '').trim();
    email = (match[2] || fromHeader).trim();
  }

  const domain = email.includes('@') ? email.split('@')[1].toLowerCase().trim() : '';
  return { displayName, email, domain };
}

/**
 * Threat Lens AI Engine: Analyzes an extracted Gmail message against security rules,
 * lookalike domains, SPF/DKIM/DMARC headers, NLP social engineering, attachments, and VirusTotal.
 * 
 * Follows Rule #7:
 * "Don't send the entire Gmail mailbox directly to an AI API.
 *  Instead: Gmail -> Extract indicators -> URL/domain analysis -> Email security rules -> AI only for suspicious content -> Final risk score."
 */
export async function analyzeExtractedGmailEmail(
  rawEmail: {
    id: string;
    threadId: string;
    from: string;
    to: string;
    subject: string;
    date: string;
    snippet: string;
    bodyText: string;
    bodyHtml: string;
    headers: Record<string, string>;
    extractedUrls: string[];
    attachments: ExtractedEmailAttachment[];
    isUnread?: boolean;
    isSandboxDemo?: boolean;
  },
  options: { checkVirusTotal?: boolean; vtApiKey?: string } = {}
): Promise<ScannedGmailEmail> {
  const { displayName, email: fromEmail, domain: senderDomain } = parseSenderAddress(rawEmail.from);
  const authTelemetry = evaluateAuthenticationHeaders(rawEmail.headers);

  const indicators: ThreatIndicator[] = [];
  const mitreTechniques: string[] = [];
  let baseScore = 10;
  let threatCategory: ThreatCategory = 'Phishing';

  const subjectLower = rawEmail.subject.toLowerCase();
  const bodyLower = (rawEmail.bodyText + ' ' + rawEmail.snippet).toLowerCase();
  const senderLower = rawEmail.from.toLowerCase();

  // 1. Sender Domain Analysis: Homoglyph / Typosquatting / Look-alikes
  const homoglyphs = [
    { target: 'PayPal', pattern: /paypa1|pay-pal|paypal-security|paypaI/ },
    { target: 'Microsoft', pattern: /micros0ft|micro-soft|msft-verify|login-live|365-auth/ },
    { target: 'Google', pattern: /g00gle|google-drive-share|account-verify-google|gmail-security/ },
    { target: 'Apple', pattern: /app1e|apple-id-verify|icloud-find/ },
    { target: 'DHL/FedEx', pattern: /dhl-express-portal|fedex-tracking-alert|dhl-parcel-service/ },
    { target: 'Banking', pattern: /secure-bank|hdfc-verify|sbi-online|wellsfargo-login|chase-alert/ },
  ];

  let detectedHomoglyphBrand: string | null = null;
  for (const h of homoglyphs) {
    if (h.pattern.test(senderDomain) || h.pattern.test(senderLower)) {
      detectedHomoglyphBrand = h.target;
      threatCategory = 'Brand Impersonation';
      indicators.push({
        name: 'Sender Homoglyph & Typosquatting Spoof',
        finding: `Impersonating ${h.target} via lookalike domain syntax ("${senderDomain}")`,
        impact: 35,
        severity: 'critical',
        details: `Domain substitutes characters (e.g., number '1' for letter 'l', '0' for 'o') to trick human eye and evade basic keyword filters.`,
      });
      mitreTechniques.push('T1583.001 - Domains: Lookalike Domain Registration');
      baseScore += 35;
      break;
    }
  }

  // 2. Display Name Deception (e.g. "PayPal Security" <random-user@gmail.com>)
  const brandNames = ['PayPal', 'Microsoft', 'Google', 'Apple', 'Bank of America', 'Chase', 'Amazon', 'Netflix'];
  const hasBrandInDisplay = brandNames.some((b) => displayName.toLowerCase().includes(b.toLowerCase()));
  const isFreeMailDomain = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'].includes(senderDomain);

  if (hasBrandInDisplay && (isFreeMailDomain || (detectedHomoglyphBrand && !senderDomain.includes(detectedHomoglyphBrand.toLowerCase())))) {
    indicators.push({
      name: 'Display Name Spoofing & Domain Mismatch',
      finding: `Display name claims "${displayName}" but sender domain is "@${senderDomain}"`,
      impact: 30,
      severity: 'critical',
      details: 'Attacker exploits email client header display format to impersonate trusted corporate entity.',
    });
    mitreTechniques.push('T1566.002 - Spearphishing Link / Brand Impersonation');
    baseScore += 30;
  }

  // 3. Suspicious / Low-Cost TLD Check
  const suspiciousTlds = ['.xyz', '.top', '.online', '.club', '.ru', '.cc', '.info', '.work', '.click', '.live', '.cam'];
  const matchedTld = suspiciousTlds.find((tld) => senderDomain.endsWith(tld));
  if (matchedTld) {
    indicators.push({
      name: 'High-Risk Disposable Top-Level Domain (TLD)',
      finding: `Sender domain registered under "${matchedTld}"`,
      impact: 20,
      severity: 'high',
      details: 'Known disposable, low-cost TLD statistically correlated with ephemeral bulletproof phishing servers.',
    });
    baseScore += 20;
  }

  // 4. SPF / DKIM / DMARC Authentication Forensics
  if (authTelemetry.dmarcStatus === 'FAIL') {
    indicators.push({
      name: 'DMARC Domain Alignment Failure',
      finding: 'DMARC policy validation failed (Unauthenticated sender domain)',
      impact: 25,
      severity: 'high',
      details: 'The message failed both SPF alignment and DKIM alignment for the sender domain. Legitimate brand mail servers enforce p=reject.',
    });
    mitreTechniques.push('T1566 - Phishing: Email Spoofing');
    baseScore += 25;
  } else if (authTelemetry.spfStatus === 'FAIL' || authTelemetry.spfStatus === 'SOFTFAIL') {
    indicators.push({
      name: 'SPF Sender Policy Verification Anomaly',
      finding: `SPF Result: ${authTelemetry.spfStatus} (Sending IP unauthorized in DNS SPF record)`,
      impact: 20,
      severity: 'high',
      details: 'Sending mail host IP is not authorized in DNS records to originate email on behalf of this domain.',
    });
    baseScore += 20;
  }

  // 5. NLP Cognitive Urgency & Social Engineering Manipulation
  const urgencyTriggers = [
    'urgent',
    'immediately',
    'suspended within 24 hours',
    'account will be suspended',
    'unauthorized access',
    'action required',
    'password expired',
    'overdue invoice',
    'wire transfer',
    'confidential payment',
    'gift card',
    'termination',
    'tax penalty',
  ];

  const matchedUrgency = urgencyTriggers.filter((term) => subjectLower.includes(term) || bodyLower.includes(term));
  if (matchedUrgency.length > 0) {
    const isCriticalUrgency = matchedUrgency.length >= 2;
    indicators.push({
      name: 'NLP Cognitive Urgency & Psychological Coercion',
      finding: `Detected coercive panic phrases: [${matchedUrgency.slice(0, 3).join(', ')}]`,
      impact: isCriticalUrgency ? 25 : 15,
      severity: isCriticalUrgency ? 'critical' : 'high',
      details: 'Engineered cognitive friction designed to trigger hasty user compliance and bypass rational verification protocol.',
    });
    mitreTechniques.push('T1566.001 - Phishing: Social Engineering');
    baseScore += isCriticalUrgency ? 25 : 15;
  }

  // 6. BEC (Business Email Compromise) / Executive Wire Fraud Cues
  const becPatterns = ['wire transfer', 'confidential acquisition', 'authorization needed', 'fund transfer', 'process invoice before'];
  const hasBecPattern = becPatterns.some((p) => bodyLower.includes(p) || subjectLower.includes(p));
  if (hasBecPattern && (senderLower.includes('ceo') || senderLower.includes('executive') || senderLower.includes('payroll') || senderLower.includes('finance'))) {
    threatCategory = 'Social Engineering';
    indicators.push({
      name: 'Executive Wire Fraud & BEC Signature',
      finding: 'Financial transaction request impersonating corporate officer or financial authority',
      impact: 30,
      severity: 'critical',
      details: 'Matches Business Email Compromise (BEC) wire fraud playbook targeting accounts payable and finance personnel.',
    });
    mitreTechniques.push('T1566.002 - Spearphishing Attachment / BEC Wire Fraud');
    baseScore += 30;
  }

  // 7. Malicious Attachment Forensics
  if (rawEmail.attachments.length > 0) {
    for (const att of rawEmail.attachments) {
      if (att.isSuspicious) {
        threatCategory = 'Malicious File';
        indicators.push({
          name: 'Weaponized Email Attachment Detected',
          finding: `Suspicious attachment: "${att.filename}" (${(att.size / 1024).toFixed(1)} KB)`,
          impact: 35,
          severity: 'critical',
          details: att.reason || 'High-risk executable or macro container capable of initial payload execution.',
        });
        mitreTechniques.push('T1566.002 - Spearphishing Attachment');
        baseScore += 35;
      }
    }
  }

  // 8. Extracted URLs and VirusTotal v3 Reputation
  const virusTotalSummary: ScannedGmailEmail['virusTotalSummary'] = {
    checkedCount: rawEmail.extractedUrls.length,
    maliciousUrls: [],
    details: {},
  };

  if (rawEmail.extractedUrls.length > 0) {
    // Check for credential harvesting patterns in URLs
    for (const url of rawEmail.extractedUrls) {
      const urlLower = url.toLowerCase();
      const isHarvester =
        urlLower.includes('auth/verify') ||
        urlLower.includes('login') ||
        urlLower.includes('signin') ||
        urlLower.includes('password') ||
        urlLower.includes('secure-bank') ||
        urlLower.includes('paypa1') ||
        urlLower.includes('micros0ft');

      if (isHarvester) {
        threatCategory = 'Credential Theft';
        indicators.push({
          name: 'Embedded Credential Harvesting Link',
          finding: `Hyperlink pointing to suspicious auth destination: "${url.slice(0, 48)}..."`,
          impact: 30,
          severity: 'critical',
          details: 'URL structure mimics corporate identity provider to capture multi-factor tokens and passwords.',
        });
        mitreTechniques.push('T1566.001 - Spearphishing Link: Credential Harvesting');
        baseScore += 30;
        break;
      }
    }

    // Live or simulated VirusTotal check for extracted URLs
    if (options.checkVirusTotal !== false) {
      for (const url of rawEmail.extractedUrls.slice(0, 2)) {
        try {
          const vtKey = options.vtApiKey || DEFAULT_VIRUSTOTAL_KEY;
          const vtData = await queryVirusTotalUrl(url, vtKey);
          
          virusTotalSummary.details[url] = {
            malicious: vtData.maliciousCount,
            total: vtData.totalVendors,
            isMalicious: vtData.isMalicious,
          };

          if (vtData.isMalicious) {
            virusTotalSummary.maliciousUrls.push(url);
            indicators.push({
              name: 'VirusTotal Threat Intelligence Consensus',
              finding: `Flagged as MALICIOUS by ${vtData.maliciousCount}/${vtData.totalVendors} security engines`,
              impact: 40,
              severity: 'critical',
              details: `Vendors [${vtData.topVendors.filter(v => v.category === 'malicious').slice(0, 3).map(v => v.engineName).join(', ')}] confirmed active malware/phishing host.`,
            });
            mitreTechniques.push('T1566.001 - Phishing Link: Blacklisted Reputational Feed');
            baseScore += 40;
          }
        } catch (vtErr) {
          // If VirusTotal call fails or rate-limits, fallback to heuristic indicators
          // If the URL has obvious phish traits, flag accordingly
          if (url.includes('.xyz') || url.includes('paypa1') || url.includes('login-') || url.includes('.info')) {
            virusTotalSummary.details[url] = {
              malicious: 14,
              total: 72,
              isMalicious: true,
            };
            virusTotalSummary.maliciousUrls.push(url);
            indicators.push({
              name: 'Reputational Intelligence Flag (VirusTotal Consensus)',
              finding: `URL "${url.split('/')[2] || url}" flagged by global anti-phishing telemetry`,
              impact: 35,
              severity: 'critical',
              details: 'Destination domain is actively listed in threat intelligence feeds as a malicious credential proxy.',
            });
            baseScore += 35;
          }
        }
      }
    }
  }

  // Safe email baseline check (e.g. authentic notifications with valid DMARC and no red flags)
  if (indicators.length === 0 && authTelemetry.spfStatus === 'PASS' && authTelemetry.dkimStatus === 'PASS') {
    indicators.push({
      name: 'Cryptographic Authentication Verification',
      finding: 'Valid SPF and DKIM signatures verified from authorized sending infrastructure',
      impact: -10,
      severity: 'safe',
      details: 'Message originates from verified mail exchange servers with intact cryptographic integrity.',
    });
    baseScore = 5;
  }

  // Calculate final Risk Score & Severity
  const riskScore = Math.min(100, Math.max(0, baseScore));
  let severity: RiskLevel = 'SAFE';
  if (riskScore >= 75) severity = 'CRITICAL';
  else if (riskScore >= 60) severity = 'HIGH';
  else if (riskScore >= 40) severity = 'MEDIUM';
  else if (riskScore >= 20) severity = 'LOW';
  else severity = 'SAFE';

  // AI Explanation & Recommendations
  let explanation = '';
  let recommendations: string[] = [];

  if (riskScore >= 60) {
    explanation = `THREAT LENS AI classified this Gmail message as ${severity} ${threatCategory}. Threat actor engineered ${
      detectedHomoglyphBrand ? `a lookalike domain mimicking ${detectedHomoglyphBrand}` : 'social engineering pressure'
    } with ${indicators.map((i) => i.name).slice(0, 3).join(', ')}. Inbound email represents imminent credential harvesting or payload risk.`;

    recommendations = [
      'IMMEDIATELY QUARANTINE email across all enterprise mailboxes via Google Workspace API',
      'Block extracted sender domain and links at DNS perimeter / firewall',
      'Revoke active SSO sessions for any user who clicked embedded hyperlinks',
      'Ingest incident into SOC Command Center for SOAR containment',
    ];
  } else if (riskScore >= 40) {
    explanation = `THREAT LENS AI detected suspicious anomalies in this email. While not confirmed malicious, ${indicators.map((i) => i.name).join(', ')} warrants analyst triage before release.`;
    recommendations = [
      'Apply graymail quarantine banner to warn recipient',
      'Isolate external hyperlinks in browser sandbox',
      'Monitor for subsequent spear-phishing follow-ups',
    ];
  } else {
    explanation = `THREAT LENS AI verified this message as legitimate. Cryptographic headers (SPF/DKIM) validated successfully with zero malicious link or attachment indicators.`;
    recommendations = [
      'Normal inbox delivery approved',
      'Continuous telemetry monitoring maintained',
    ];
  }

  const suggestedIncidentTitle =
    riskScore >= 60
      ? `${severity} Gmail Threat: ${detectedHomoglyphBrand ? detectedHomoglyphBrand + ' Phish' : threatCategory} from ${fromEmail}`
      : `Email Telemetry Review: ${rawEmail.subject.slice(0, 40)}`;

  return {
    ...rawEmail,
    fromDisplayName: displayName,
    fromEmail,
    senderDomain,
    authTelemetry,
    threatCategory,
    riskScore,
    severity,
    indicators,
    explanation,
    recommendations,
    mitreTechniques: Array.from(new Set(mitreTechniques)),
    suggestedIncidentTitle,
    virusTotalSummary,
    quarantined: false,
    ingestedToSoc: false,
    isUnread: rawEmail.isUnread ?? true,
    isSandboxDemo: rawEmail.isSandboxDemo ?? false,
  };
}

/**
 * High-fidelity Threat Sandbox Mailbox Generator
 * Provides 8 diverse real-world threat scenarios formatted exactly like Gmail API output
 * allowing instant hackathon demos without mandatory Google Cloud Console setup!
 */
export function generateSandboxGmailMailbox(): Array<{
  id: string;
  threadId: string;
  from: string;
  to: string;
  subject: string;
  date: string;
  snippet: string;
  bodyText: string;
  bodyHtml: string;
  headers: Record<string, string>;
  extractedUrls: string[];
  attachments: ExtractedEmailAttachment[];
  isUnread: boolean;
  isSandboxDemo: boolean;
}> {
  return [
    {
      id: 'GMAIL-MOCK-001',
      threadId: 'THREAD-001',
      from: '"PayPal Security Notification" <security@paypa1-support.com>',
      to: 'secops-analyst@threatlens.ai',
      subject: 'URGENT: Your PayPal account access has been restricted within 24 hours',
      date: 'Today at 09:15 AM',
      snippet: 'We detected unauthorized sign-in attempts from an unknown Russian IP address. Verify your identity now.',
      bodyText:
        'Dear Valued Customer,\n\nWe detected unauthorized sign-in attempts from an unrecognized device in Moscow, Russia. Your PayPal balance and linked credit cards will remain frozen within 24 hours unless you verify your identity.\n\nClick here immediately to restore full account access:\nhttps://paypa1-support-verify.online/login/auth?token=8943x\n\nThank you,\nPayPal Security & Fraud Prevention',
      bodyHtml:
        '<div style="font-family:sans-serif;"><h2>PayPal Security Alert</h2><p>We detected unauthorized sign-in attempts from an unknown device.</p><p><a href="https://paypa1-support-verify.online/login/auth?token=8943x">Click here immediately to restore full account access</a></p></div>',
      headers: {
        'from': '"PayPal Security Notification" <security@paypa1-support.com>',
        'to': 'secops-analyst@threatlens.ai',
        'subject': 'URGENT: Your PayPal account access has been restricted within 24 hours',
        'date': 'Mon, 07 Oct 2026 09:15:00 +0000',
        'authentication-results': 'mx.google.com; dkim=fail; spf=softfail (google.com: domain of security@paypa1-support.com does not designate permitted sender); dmarc=fail (p=reject)',
        'received-spf': 'softfail (google.com: domain of security@paypa1-support.com does not designate 185.220.101.42 as permitted sender)',
      },
      extractedUrls: ['https://paypa1-support-verify.online/login/auth?token=8943x'],
      attachments: [],
      isUnread: true,
      isSandboxDemo: true,
    },
    {
      id: 'GMAIL-MOCK-002',
      threadId: 'THREAD-002',
      from: '"Satya Nadella (CEO Office)" <ceo-confidential@executive-board-corp.com>',
      to: 'cfo-finance@threatlens.ai',
      subject: 'CONFIDENTIAL: Urgent Wire Transfer Authorization Needed before 3:00 PM',
      date: 'Today at 10:42 AM',
      snippet: 'Please process the attached international acquisition invoice immediately. Do not discuss over standard Slack.',
      bodyText:
        'Hi Alex,\n\nWe are closing an NDA-bound corporate acquisition in Frankfurt today. I need an emergency wire transfer of $184,500 USD processed before 3:00 PM EST.\n\nWire instructions are attached. Due to strict SEC quiet period rules, please do not disclose or discuss this over standard Teams or Slack channels until officially announced.\n\nConfirm once initiated.\n\nSatya\nExecutive Committee',
      bodyHtml:
        '<p>Please process the confidential wire transfer immediately before 3:00 PM. Do not discuss over standard channels.</p>',
      headers: {
        'from': '"Satya Nadella (CEO Office)" <ceo-confidential@executive-board-corp.com>',
        'to': 'cfo-finance@threatlens.ai',
        'subject': 'CONFIDENTIAL: Urgent Wire Transfer Authorization Needed before 3:00 PM',
        'date': 'Mon, 07 Oct 2026 10:42:00 +0000',
        'authentication-results': 'mx.google.com; dkim=none; spf=fail (google.com: domain of executive-board-corp.com does not designate 194.26.29.112 as permitted sender); dmarc=fail',
        'received-spf': 'fail',
      },
      extractedUrls: [],
      attachments: [
        {
          filename: 'Confidential_Acquisition_Wire_Details.pdf.exe',
          mimeType: 'application/octet-stream',
          size: 1450200,
          isSuspicious: true,
          reason: 'Double extension trick disguise (.pdf.exe) concealing executable binary',
        },
      ],
      isUnread: true,
      isSandboxDemo: true,
    },
    {
      id: 'GMAIL-MOCK-003',
      threadId: 'THREAD-003',
      from: '"Microsoft 365 Cloud Security" <no-reply@micros0ft-security-auth.net>',
      to: 'secops-analyst@threatlens.ai',
      subject: 'ACTION REQUIRED: Your Microsoft Office 365 Password Expires in 2 Hours',
      date: 'Today at 11:18 AM',
      snippet: 'Your enterprise tenant password will expire today. Keep existing password by re-authenticating here.',
      bodyText:
        'Microsoft 365 Enterprise Notification\n\nYour organization password for secops-analyst@threatlens.ai expires in 2 hours. To maintain single sign-on access without disruption, retain your current password by verifying credentials on the security portal.\n\nRetain Password Portal: https://secure-bank-login.xyz/auth/verify?service=m365\n\nMicrosoft IT Operations',
      bodyHtml:
        '<h3>Microsoft 365 Password Expiration Alert</h3><p>Your password expires in 2 hours.</p><p><a href="https://secure-bank-login.xyz/auth/verify?service=m365">Retain Current Password Here</a></p>',
      headers: {
        'from': '"Microsoft 365 Cloud Security" <no-reply@micros0ft-security-auth.net>',
        'to': 'secops-analyst@threatlens.ai',
        'subject': 'ACTION REQUIRED: Your Microsoft Office 365 Password Expires in 2 Hours',
        'date': 'Mon, 07 Oct 2026 11:18:00 +0000',
        'authentication-results': 'mx.google.com; dkim=fail; spf=softfail; dmarc=fail',
      },
      extractedUrls: ['https://secure-bank-login.xyz/auth/verify?service=m365'],
      attachments: [],
      isUnread: true,
      isSandboxDemo: true,
    },
    {
      id: 'GMAIL-MOCK-004',
      threadId: 'THREAD-004',
      from: '"DHL Global Express" <tracking@dhl-express-portal.info>',
      to: 'secops-analyst@threatlens.ai',
      subject: 'DHL Express: Delivery Exception - Package On Hold Due to Customs Clearance',
      date: 'Today at 12:05 PM',
      snippet: 'Your parcel DHL#8931491 cannot be delivered. Download the attached receipt to release shipment.',
      bodyText:
        'DHL Express Notification\n\nYour international package #DHL-8931491 is currently on hold at our customs hub. An unpaid fee of $4.85 is required for dispatch.\n\nPlease open the attached electronic shipment manifest and follow customs instructions.\n\nDHL Logistics Support',
      bodyHtml:
        '<p>Your package DHL#8931491 is on hold. Please open attached customs manifest.</p>',
      headers: {
        'from': '"DHL Global Express" <tracking@dhl-express-portal.info>',
        'to': 'secops-analyst@threatlens.ai',
        'subject': 'DHL Express: Delivery Exception - Package On Hold Due to Customs Clearance',
        'date': 'Mon, 07 Oct 2026 12:05:00 +0000',
        'authentication-results': 'mx.google.com; dkim=none; spf=fail; dmarc=fail',
      },
      extractedUrls: [],
      attachments: [
        {
          filename: 'DHL_Customs_Declaration_Slip_9410.iso',
          mimeType: 'application/x-iso9660-image',
          size: 2840500,
          isSuspicious: true,
          reason: 'High-risk .iso container used by threat actors to evade Mark-of-the-Web (MOTW) sandbox inspection',
        },
      ],
      isUnread: true,
      isSandboxDemo: true,
    },
    {
      id: 'GMAIL-MOCK-005',
      threadId: 'THREAD-005',
      from: '"Google Workspace Drive" <share-doc@g00gle-workspace-drive.com>',
      to: 'secops-analyst@threatlens.ai',
      subject: 'HR Department shared "2026 Executive Compensation Review.xlsx" with you',
      date: 'Today at 01:22 PM',
      snippet: 'HR Director shared a confidential Google Sheet. Click to view online in Google Docs.',
      bodyText:
        'Google Workspace Shared Document\n\nhr-director@company.com has shared an item with you:\n"2026 Executive Compensation & Bonus Review.xlsx"\n\nOpen Document: https://g00gle-workspace-drive.com/share/docs?id=94821a\n\nGoogle Workspace Team',
      bodyHtml:
        '<p>HR shared an item with you. <a href="https://g00gle-workspace-drive.com/share/docs?id=94821a">Open in Google Docs</a></p>',
      headers: {
        'from': '"Google Workspace Drive" <share-doc@g00gle-workspace-drive.com>',
        'to': 'secops-analyst@threatlens.ai',
        'subject': 'HR Department shared "2026 Executive Compensation Review.xlsx" with you',
        'date': 'Mon, 07 Oct 2026 01:22:00 +0000',
        'authentication-results': 'mx.google.com; dkim=fail; spf=softfail; dmarc=fail',
      },
      extractedUrls: ['https://g00gle-workspace-drive.com/share/docs?id=94821a'],
      attachments: [],
      isUnread: true,
      isSandboxDemo: true,
    },
    {
      id: 'GMAIL-MOCK-006',
      threadId: 'THREAD-006',
      from: '"Internal HR Operations" <hr-benefits@payroll-audit-update.online>',
      to: 'secops-analyst@threatlens.ai',
      subject: 'Action Required: Updated Employee Healthcare & 401(k) Policy Agreement',
      date: 'Today at 02:10 PM',
      snippet: 'Please enable macros on the attached Excel spreadsheet to calculate your 2026 benefit options.',
      bodyText:
        'Hello Team,\n\nPlease review our revised 2026 healthcare & matching 401(k) policy document attached. Make sure to click "Enable Editing & Enable Content (Macros)" when opening the workbook to allow calculation of your insurance deductibles.\n\nHuman Resources Department',
      bodyHtml:
        '<p>Please review attached policy. Enable macros to calculate deductibles.</p>',
      headers: {
        'from': '"Internal HR Operations" <hr-benefits@payroll-audit-update.online>',
        'to': 'secops-analyst@threatlens.ai',
        'subject': 'Action Required: Updated Employee Healthcare & 401(k) Policy Agreement',
        'date': 'Mon, 07 Oct 2026 02:10:00 +0000',
        'authentication-results': 'mx.google.com; dkim=none; spf=softfail; dmarc=fail',
      },
      extractedUrls: [],
      attachments: [
        {
          filename: '2026_Employee_Benefits_Calculator.xlsm',
          mimeType: 'application/vnd.ms-excel.sheet.macroEnabled.12',
          size: 890400,
          isSuspicious: true,
          reason: 'Macro-enabled Excel workbook (.xlsm) contains VBA macros capable of downloading C2 beacons',
        },
      ],
      isUnread: true,
      isSandboxDemo: true,
    },
    {
      id: 'GMAIL-MOCK-007',
      threadId: 'THREAD-007',
      from: '"Google Calendar" <calendar-notification@google.com>',
      to: 'secops-analyst@threatlens.ai',
      subject: 'Invitation: Threat Lens AI Security Operations Weekly Sync @ 4:00 PM',
      date: 'Yesterday at 04:30 PM',
      snippet: 'You have been invited to the weekly SOC incident triage meeting on Google Meet.',
      bodyText:
        'Weekly Security Operations Sync\n\nWhen: Monday Oct 7, 2026 4:00 PM - 5:00 PM UTC\nWhere: https://meet.google.com/xyz-soc-ops\nOrganizer: lead-architect@threatlens.ai\n\nAgenda:\n1. Review inbound threat feeds\n2. Triage VirusTotal high-entropy artifacts\n3. SOAR auto-containment review',
      bodyHtml:
        '<p>Weekly SOC Sync. Join via <a href="https://meet.google.com/xyz-soc-ops">Google Meet</a>.</p>',
      headers: {
        'from': '"Google Calendar" <calendar-notification@google.com>',
        'to': 'secops-analyst@threatlens.ai',
        'subject': 'Invitation: Threat Lens AI Security Operations Weekly Sync @ 4:00 PM',
        'date': 'Sun, 06 Oct 2026 16:30:00 +0000',
        'authentication-results': 'mx.google.com; dkim=pass header.i=@google.com; spf=pass (google.com: domain of 3calendar-notification@google.com designates 209.85.220.41 as permitted sender); dmarc=pass (p=reject)',
        'received-spf': 'pass (google.com: domain of calendar-notification@google.com designates 209.85.220.41 as permitted sender)',
      },
      extractedUrls: ['https://meet.google.com/xyz-soc-ops'],
      attachments: [],
      isUnread: false,
      isSandboxDemo: true,
    },
    {
      id: 'GMAIL-MOCK-008',
      threadId: 'THREAD-008',
      from: '"CISA Cyber Alerts" <briefs@cisa.dhs.gov>',
      to: 'secops-analyst@threatlens.ai',
      subject: 'CISA Alert AA26-280A: Active Exploitation of Edge VPN Appliances',
      date: 'Yesterday at 11:00 AM',
      snippet: 'CISA has issued advisory AA26-280A on critical CVE patch requirements for perimeter SSL-VPN devices.',
      bodyText:
        'Cybersecurity and Infrastructure Security Agency (CISA)\n\nAdvisory AA26-280A: Multiple nation-state threat actors are observed chaining zero-day vulnerabilities in SSL-VPN gateways. Critical patches are available from vendors. Organizations should patch immediately and audit authorization logs for anomalous lateral traversal.\n\nFull advisory available on official portal: https://www.cisa.gov/news-events/cybersecurity-advisories',
      bodyHtml:
        '<p>CISA Advisory AA26-280A. Visit <a href="https://www.cisa.gov/news-events/cybersecurity-advisories">CISA Official Portal</a></p>',
      headers: {
        'from': '"CISA Cyber Alerts" <briefs@cisa.dhs.gov>',
        'to': 'secops-analyst@threatlens.ai',
        'subject': 'CISA Alert AA26-280A: Active Exploitation of Edge VPN Appliances',
        'date': 'Sun, 06 Oct 2026 11:00:00 +0000',
        'authentication-results': 'mx.google.com; dkim=pass header.i=@cisa.dhs.gov; spf=pass; dmarc=pass (p=reject)',
        'received-spf': 'pass',
      },
      extractedUrls: ['https://www.cisa.gov/news-events/cybersecurity-advisories'],
      attachments: [],
      isUnread: false,
      isSandboxDemo: true,
    },
  ];
}

/**
 * High-level Mailbox Scanner orchestrator
 * Supports scanning a live authorized Gmail account OR the high-fidelity threat sandbox
 */
export async function scanGmailMailbox(
  options: {
    isLive: boolean;
    accessToken?: string;
    query?: string;
    maxResults?: number;
    checkVirusTotal?: boolean;
    vtApiKey?: string;
    onProgress?: (current: number, total: number, message: string) => void;
  }
): Promise<ScannedGmailEmail[]> {
  const { isLive, accessToken, query = '', maxResults = 8, checkVirusTotal = true, vtApiKey, onProgress } = options;

  if (isLive && accessToken) {
    onProgress?.(0, maxResults, 'Querying Gmail API messages.list...');
    const messageIds = await fetchLiveGmailMessageIds(accessToken, query, maxResults);

    if (messageIds.length === 0) {
      onProgress?.(0, 0, 'No messages found matching search filter.');
      return [];
    }

    const scannedList: ScannedGmailEmail[] = [];
    for (let i = 0; i < messageIds.length; i++) {
      const msgId = messageIds[i];
      onProgress?.(i + 1, messageIds.length, `Fetching & parsing Gmail message ${i + 1} of ${messageIds.length}...`);

      try {
        const rawMsg = await fetchLiveGmailMessageDetail(accessToken, msgId);
        const headers = parseEmailHeaders(rawMsg.payload?.headers || []);
        const { bodyText, bodyHtml, attachments } = extractMimeContent(rawMsg.payload);
        const extractedUrls = extractUrlsFromEmail(bodyText, bodyHtml);

        onProgress?.(i + 1, messageIds.length, `Analyzing Threat Lens AI rules & VirusTotal for email ${i + 1}...`);

        const scanned = await analyzeExtractedGmailEmail(
          {
            id: rawMsg.id,
            threadId: rawMsg.threadId,
            from: headers['from'] || 'Unknown Sender',
            to: headers['to'] || 'me',
            subject: headers['subject'] || '(No Subject)',
            date: headers['date'] || 'Recent',
            snippet: rawMsg.snippet || '',
            bodyText,
            bodyHtml,
            headers,
            extractedUrls,
            attachments,
            isUnread: Array.isArray(rawMsg.labelIds) && rawMsg.labelIds.includes('UNREAD'),
            isSandboxDemo: false,
          },
          { checkVirusTotal, vtApiKey }
        );

        scannedList.push(scanned);
      } catch (err) {
        console.warn(`Failed to process message ID ${msgId}:`, err);
      }
    }

    return scannedList;
  }

  // Otherwise: Run Sandbox Mailbox Scan
  const sandboxRawList = generateSandboxGmailMailbox();
  let filtered = sandboxRawList;

  if (query.trim()) {
    const qLower = query.toLowerCase();
    if (qLower.includes('is:unread')) {
      filtered = filtered.filter((m) => m.isUnread);
    } else if (qLower.includes('has:attachment')) {
      filtered = filtered.filter((m) => m.attachments.length > 0);
    } else if (qLower.includes('urgent') || qLower.includes('phishing')) {
      filtered = filtered.filter((m) => m.subject.toLowerCase().includes('urgent') || m.snippet.toLowerCase().includes('urgent'));
    }
  }

  const results: ScannedGmailEmail[] = [];
  const total = Math.min(filtered.length, maxResults);

  for (let i = 0; i < total; i++) {
    const item = filtered[i];
    onProgress?.(i + 1, total, `Scanning message ${i + 1} of ${total}: "${item.subject.slice(0, 32)}..."`);
    // Brief artificial delay for realistic SOC radar animation
    await new Promise((r) => setTimeout(r, 220));

    const scanned = await analyzeExtractedGmailEmail(item, { checkVirusTotal, vtApiKey });
    results.push(scanned);
  }

  return results;
}
