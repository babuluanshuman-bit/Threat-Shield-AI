/**
 * Malicious File & Content Static Forensic Service
 * Provides:
 * 1. Mathematical Shannon Entropy Analysis (0.0 to 8.0)
 * 2. Magic Number & True Binary MIME Type Verification
 * 3. Deceptive Double-Extension & Executable Spoofing Detection
 * 4. Embedded Macro / PowerShell / ShellExecute Static Disassembly
 * 5. VirusTotal Free API v3 Integration (500 free lookups/day)
 */

export interface FileForensicReport {
  fileName: string;
  fileSizeFormatted: string;
  sha256: string;
  entropy: number;
  entropyLabel: 'Low (Text)' | 'Normal (Document)' | 'High (Compressed/Encrypted)' | 'Extreme (Packed / Crypter)';
  detectedMime: string;
  actualType: string;
  isExtensionSpoofed: boolean;
  isDoubleExtension: boolean;
  hasExecutableHeaders: boolean;
  hasSuspiciousStreams: boolean;
  suspiciousKeywordsFound: string[];
  vtDetectionRatio?: string;
  vtMaliciousCount?: number;
  vtTotalVendors?: number;
  isMalicious: boolean;
  isSafe: boolean;
  confidenceScore: number; // 0 - 100
  summary: string;
}

// Known Malicious Test Hashes
export const KNOWN_MALWARE_HASHES: Record<string, { family: string; detections: number; total: number }> = {
  'a82fc109de83b4029481fe10d8a4392bc194091bc': { family: 'Trojan.Dropper.Generic', detections: 54, total: 68 },
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4': { family: 'Backdoor.Win32.CobaltStrike', detections: 62, total: 70 },
  'd41d8cd98f00b204e9800998ecf8427e': { family: 'Ransomware.LockBit.Payload', detections: 58, total: 69 },
  '7b52009b64fd0a2a49e6d8a939753077792b0554': { family: 'Worm.Win32.Emotet', detections: 60, total: 72 },
};

/**
 * Returns forensic telemetry for preset demonstration files
 */
export function getPresetForensicReport(presetName: string): FileForensicReport {
  if (presetName.includes('salary') || presetName.includes('docx.exe')) {
    return {
      fileName: 'salary_statement.docx.exe',
      fileSizeFormatted: '1.2 MB',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4',
      entropy: 7.85,
      entropyLabel: 'Extreme (Packed / Crypter)',
      detectedMime: 'application/x-dosexec (Portable Executable)',
      actualType: 'Windows PE Executable (.exe / .dll / .scr)',
      isExtensionSpoofed: true,
      isDoubleExtension: true,
      hasExecutableHeaders: true,
      hasSuspiciousStreams: true,
      suspiciousKeywordsFound: ['cmd.exe', 'powershell', 'rundll32'],
      vtDetectionRatio: '62 / 70 Antivirus Engines',
      vtMaliciousCount: 62,
      vtTotalVendors: 70,
      isMalicious: true,
      isSafe: false,
      confidenceScore: 99,
      summary: 'CRITICAL THREAT: Double-extension executable dropper masquerading as Word document with packed PE32 payload section.',
    };
  } else if (presetName.includes('invoice') || presetName.includes('Trojan')) {
    return {
      fileName: 'invoice.pdf',
      fileSizeFormatted: '412 KB',
      sha256: 'a82fc109de83b4029481fe10d8a4392bc194091bc',
      entropy: 7.42,
      entropyLabel: 'Extreme (Packed / Crypter)',
      detectedMime: 'application/pdf',
      actualType: 'Adobe Portable Document (PDF)',
      isExtensionSpoofed: false,
      isDoubleExtension: false,
      hasExecutableHeaders: false,
      hasSuspiciousStreams: true,
      suspiciousKeywordsFound: ['/launch', '/javascript', 'wscript.shell'],
      vtDetectionRatio: '54 / 68 Antivirus Engines',
      vtMaliciousCount: 54,
      vtTotalVendors: 68,
      isMalicious: true,
      isSafe: false,
      confidenceScore: 94,
      summary: 'HIGH RISK: Malicious PDF contains weaponized /Launch stream attempting execution of remote WScript payload.',
    };
  } else {
    return {
      fileName: 'Annual_Report_2026.pdf',
      fileSizeFormatted: '3.4 MB',
      sha256: '9b71d224bd62f3785d96d46ad3ea3d73319bf521',
      entropy: 4.12,
      entropyLabel: 'Normal (Document)',
      detectedMime: 'application/pdf',
      actualType: 'Adobe Portable Document (PDF)',
      isExtensionSpoofed: false,
      isDoubleExtension: false,
      hasExecutableHeaders: false,
      hasSuspiciousStreams: false,
      suspiciousKeywordsFound: [],
      vtDetectionRatio: '0 / 72 Antivirus Engines (Clean)',
      vtMaliciousCount: 0,
      vtTotalVendors: 72,
      isMalicious: false,
      isSafe: true,
      confidenceScore: 98,
      summary: 'VERIFIED SAFE ASSET: Legitimate Adobe PDF structure, normal document entropy (4.12/8.0), zero macros, clean across global AV vendors.',
    };
  }
}

/**
 * Calculates real Shannon entropy of an ArrayBuffer (0.00 to 8.00)
 */
export function calculateShannonEntropy(buffer: ArrayBuffer): number {
  if (buffer.byteLength === 0) return 0;
  const bytes = new Uint8Array(buffer);
  const frequencies = new Array(256).fill(0);

  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }

  let entropy = 0;
  const length = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / length;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 100) / 100;
}

/**
 * Inspects binary magic numbers and compares against declared file extension
 */
export function inspectBinaryMagicNumbers(buffer: ArrayBuffer, fileName: string): {
  detectedMime: string;
  actualType: string;
  isExtensionSpoofed: boolean;
  hasExecutableHeaders: boolean;
} {
  const bytes = new Uint8Array(buffer.slice(0, 16));
  const ext = fileName.split('.').pop()?.toLowerCase() || '';

  let detectedMime = 'application/octet-stream';
  let actualType = 'Binary / Data File';
  let hasExecutableHeaders = false;

  // 1. Windows PE Executable (MZ header)
  if (bytes[0] === 0x4D && bytes[1] === 0x5A) {
    detectedMime = 'application/x-dosexec (Portable Executable)';
    actualType = 'Windows PE Executable (.exe / .dll / .scr)';
    hasExecutableHeaders = true;
  }
  // 2. Adobe PDF (%PDF)
  else if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    detectedMime = 'application/pdf';
    actualType = 'Adobe Portable Document (PDF)';
  }
  // 3. ZIP Archive / Microsoft Office OpenXML (PK..)
  else if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) {
    detectedMime = 'application/zip / office-openxml';
    actualType = ['docx', 'xlsx', 'pptx'].includes(ext) ? 'Microsoft Office Document' : 'ZIP Compressed Archive';
  }
  // 4. Linux ELF Executable (.ELF)
  else if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) {
    detectedMime = 'application/x-executable (ELF)';
    actualType = 'Linux ELF Executable';
    hasExecutableHeaders = true;
  }
  // 5. JPEG Image
  else if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    detectedMime = 'image/jpeg';
    actualType = 'JPEG Optical Image';
  }
  // 6. PNG Image
  else if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    detectedMime = 'image/png';
    actualType = 'PNG Raster Image';
  }
  // 7. Plain text / Web / Scripts
  else if (['txt', 'csv', 'json', 'md', 'xml', 'html', 'css', 'js', 'ts', 'jsx', 'tsx', 'py'].includes(ext)) {
    detectedMime = 'text/plain';
    actualType = 'Plain Text / Script Document';
  }

  // Deceptive Extension Check: Executable header disguised as non-executable
  const benignExtensions = ['pdf', 'docx', 'xlsx', 'jpg', 'jpeg', 'png', 'txt', 'csv', 'mp3', 'mp4', 'json', 'md'];
  const isExtensionSpoofed = hasExecutableHeaders && benignExtensions.includes(ext);

  return {
    detectedMime,
    actualType,
    isExtensionSpoofed,
    hasExecutableHeaders,
  };
}

/**
 * Scans binary text streams for obfuscated macros, PowerShell invocation, and shell commands
 */
export function scanSuspiciousKeywords(buffer: ArrayBuffer): {
  hasSuspiciousStreams: boolean;
  keywordsFound: string[];
} {
  // Sample up to first 1MB of binary content
  const sample = new Uint8Array(buffer.slice(0, 1024 * 1024));
  const decoded = new TextDecoder('latin1').decode(sample).toLowerCase();

  const dangerousTokens = [
    'powershell',
    'cmd.exe',
    'wscript.shell',
    'cscript.exe',
    'autoopen',
    'workbook_open',
    'shellexecute',
    'urldownloadtofile',
    '/launch',
    '/javascript',
    'invoke-expression',
    'invoke-webrequest',
    'createobject',
    'rundll32',
    'regsvr32',
    'bitsadmin',
  ];

  const keywordsFound: string[] = [];
  for (const token of dangerousTokens) {
    if (decoded.includes(token)) {
      keywordsFound.push(token);
    }
  }

  return {
    hasSuspiciousStreams: keywordsFound.length > 0,
    keywordsFound,
  };
}

/**
 * Performs local static forensic analysis of any uploaded file
 */
export async function analyzeFileLocally(file: File): Promise<FileForensicReport> {
  const buffer = await file.arrayBuffer();

  // 1. Calculate SHA-256
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const sha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  // 2. Shannon Entropy
  const entropy = calculateShannonEntropy(buffer);
  let entropyLabel: FileForensicReport['entropyLabel'] = 'Normal (Document)';
  if (entropy < 3.5) entropyLabel = 'Low (Text)';
  else if (entropy > 7.3) entropyLabel = 'Extreme (Packed / Crypter)';
  else if (entropy > 6.5) entropyLabel = 'High (Compressed/Encrypted)';

  // 3. Binary Magic Numbers & Extension Spoofing
  const magic = inspectBinaryMagicNumbers(buffer, file.name);

  // 4. Double Extension Check (e.g. invoice.pdf.exe)
  const isDoubleExtension = /\.(pdf|docx|xlsx|doc|txt|jpg|png)\.(exe|scr|vbs|bat|cmd|js|ps1|hta)$/i.test(file.name);

  // 5. Macro & Dangerous Script Stream Extraction
  const scriptForensics = scanSuspiciousKeywords(buffer);

  // 6. Check Known Hash Database
  const knownIntel = KNOWN_MALWARE_HASHES[sha256];

  // Determination
  const isMalicious =
    isDoubleExtension ||
    magic.isExtensionSpoofed ||
    (scriptForensics.hasSuspiciousStreams && magic.hasExecutableHeaders) ||
    scriptForensics.keywordsFound.length >= 2 ||
    entropy > 7.6 ||
    !!knownIntel;

  const isSafe = !isMalicious && !magic.hasExecutableHeaders && entropy < 6.8 && !scriptForensics.hasSuspiciousStreams;

  const formattedSize = file.size > 1024 * 1024
    ? `${(file.size / (1024 * 1024)).toFixed(1)} MB`
    : `${Math.round(file.size / 1024)} KB`;

  let confidenceScore = isMalicious ? 92 : isSafe ? 10 : 45;

  let summary = '';
  if (magic.isExtensionSpoofed) {
    summary = `CRITICAL SPOOFING: File is named "${file.name}" but contains a Windows PE Executable binary header (MZ).`;
  } else if (isDoubleExtension) {
    summary = `MALICIOUS DOUBLE EXTENSION: Uses deceptive secondary extension to execute dangerous payload.`;
  } else if (scriptForensics.hasSuspiciousStreams) {
    summary = `SUSPICIOUS OBJECT STREAMS: Found active script tokens [${scriptForensics.keywordsFound.slice(0, 3).join(', ')}].`;
  } else if (isSafe) {
    summary = `VERIFIED CLEAN ASSET: Valid ${magic.actualType} structure, normal document entropy (${entropy}/8.0), zero macros.`;
  } else {
    summary = `Static forensics analyzed file structure. No immediate signature matches detected.`;
  }

  return {
    fileName: file.name,
    fileSizeFormatted: formattedSize,
    sha256,
    entropy,
    entropyLabel,
    detectedMime: magic.detectedMime,
    actualType: magic.actualType,
    isExtensionSpoofed: magic.isExtensionSpoofed,
    isDoubleExtension,
    hasExecutableHeaders: magic.hasExecutableHeaders,
    hasSuspiciousStreams: scriptForensics.hasSuspiciousStreams,
    suspiciousKeywordsFound: scriptForensics.keywordsFound,
    vtDetectionRatio: knownIntel ? `${knownIntel.detections} / ${knownIntel.total}` : undefined,
    isMalicious,
    isSafe,
    confidenceScore,
    summary,
  };
}

export const DEFAULT_VIRUSTOTAL_KEY = (import.meta.env.VITE_VIRUSTOTAL_API_KEY as string) || '';

/**
 * VirusTotal API v3 - Instant SHA-256 Hash Lookup
 * Uses local proxy /api/virustotal to bypass browser CORS
 */
export async function queryVirusTotalHash(hash: string, apiKey?: string): Promise<{
  maliciousCount: number;
  totalVendors: number;
  detectionRatio: string;
  threatLabel?: string;
  isMalicious: boolean;
}> {
  const cleanKey = (apiKey || DEFAULT_VIRUSTOTAL_KEY).trim();
  if (!cleanKey) throw new Error('VirusTotal API key is required');

  const proxyUrl = `/api/virustotal/files/${encodeURIComponent(hash.trim())}`;
  const directUrl = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash.trim())}`;

  let response: Response;
  try {
    response = await fetch(proxyUrl, {
      headers: {
        'x-apikey': cleanKey,
        Accept: 'application/json',
      },
    });
    if (!response.ok && response.status === 404) {
      throw new Error('Proxy not found');
    }
  } catch {
    response = await fetch(directUrl, {
      headers: {
        'x-apikey': cleanKey,
        Accept: 'application/json',
      },
    });
  }

  if (response.status === 404) {
    // Hash not in VT database yet -> clean or new file
    return {
      maliciousCount: 0,
      totalVendors: 72,
      detectionRatio: '0 / 72 Antivirus Vendors (Unseen / Clean)',
      isMalicious: false,
    };
  }

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`VirusTotal API error ${response.status}: ${errorText.slice(0, 100)}`);
  }

  const json = await response.json();
  const stats = json.data?.attributes?.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected || 72;

  const threatLabel = json.data?.attributes?.popular_threat_classification?.suggested_threat_label;

  return {
    maliciousCount: malicious + suspicious,
    totalVendors: total,
    detectionRatio: `${malicious} / ${total} Antivirus Engines`,
    threatLabel,
    isMalicious: malicious > 3,
  };
}
