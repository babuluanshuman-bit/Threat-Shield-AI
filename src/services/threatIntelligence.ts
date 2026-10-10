import { ThreatIntelligenceRecord } from '../types/cyberguard';

export interface ThreatCampaign {
  id: string;
  name: string;
  threatActor: string;
  targetedSector: string;
  firstDetected: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  activeIoCs: number;
  attackVector: string;
  description: string;
}

export const INITIAL_CAMPAIGNS: ThreatCampaign[] = [
  {
    id: 'CMP-2026-09',
    name: 'Operation PhishVault',
    threatActor: 'FIN-Phish-99 (Advanced Cyber Syndicate)',
    targetedSector: 'Banking & Financial Institutions',
    firstDetected: '2026-09-28',
    severity: 'CRITICAL',
    activeIoCs: 42,
    attackVector: 'Credential harvesting via typosquatted domains & SMS lures',
    description: 'High-volume spear-phishing campaign leveraging brand spoofing of major retail banks with reverse proxy credential bypass.',
  },
  {
    id: 'CMP-2026-11',
    name: 'RedOctopus C2 Grid',
    threatActor: 'APT-37 Nexus',
    targetedSector: 'Cloud Infrastructure & Enterprise SSO',
    firstDetected: '2026-10-01',
    severity: 'CRITICAL',
    activeIoCs: 28,
    attackVector: 'OAuth token replay & impossible travel account hijacking',
    description: 'Targeted account takeover using session hijacking tokens and rapid multi-region residential proxy rotation.',
  },
  {
    id: 'CMP-2026-14',
    name: 'DeepFace Impersonation Wave',
    threatActor: 'SyntheticCraft Labs',
    targetedSector: 'Executive C-Suite & Financial Approvers',
    firstDetected: '2026-10-03',
    severity: 'HIGH',
    activeIoCs: 15,
    attackVector: 'AI-generated voice and video wire transfer coercion',
    description: 'Diffusion-model generated synthetic avatars impersonating executive staff in WhatsApp video calls and social engineering messages.',
  },
];

export const INITIAL_IOCS: ThreatIntelligenceRecord[] = [
  {
    id: 'IOC-8821',
    type: 'URL',
    value: 'https://secure-bank-login.xyz/auth/verify',
    threatType: 'Credential Phishing Form',
    confidence: 99,
    reportedBy: 'CyberGuard Live Telemetry',
    firstSeen: '12 mins ago',
    status: 'Active',
    severity: 'CRITICAL',
  },
  {
    id: 'IOC-8822',
    type: 'Domain',
    value: 'micros0ft-security-login.com',
    threatType: 'Typosquatting & Impersonation',
    confidence: 96,
    reportedBy: 'Brand Protection Shield',
    firstSeen: '2 hours ago',
    status: 'Takedown In Progress',
    severity: 'CRITICAL',
  },
  {
    id: 'IOC-8823',
    type: 'IP',
    value: '185.220.101.5',
    threatType: 'Known C2 Beaconing Node',
    confidence: 94,
    reportedBy: 'Global Threat Exchange',
    firstSeen: '4 hours ago',
    status: 'Active',
    severity: 'CRITICAL',
  },
  {
    id: 'IOC-8824',
    type: 'Hash',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    threatType: 'Trojanized PDF Invoice Dropper',
    confidence: 98,
    reportedBy: 'VirusTotal Intelligence',
    firstSeen: '6 hours ago',
    status: 'Under Investigation',
    severity: 'HIGH',
  },
  {
    id: 'IOC-8825',
    type: 'Domain',
    value: 'paypa1-support-verify.online',
    threatType: 'Look-alike Domain / Phishing',
    confidence: 95,
    reportedBy: 'DNS Anomaly Radar',
    firstSeen: '1 day ago',
    status: 'Active',
    severity: 'CRITICAL',
  },
  {
    id: 'IOC-8826',
    type: 'IP',
    value: '194.26.29.112',
    threatType: 'Brute Force & Credential Stuffing Proxy',
    confidence: 91,
    reportedBy: 'SOC Ingestion Pipeline',
    firstSeen: '1 day ago',
    status: 'Active',
    severity: 'HIGH',
  },
];

export const checkThreatIntel = (input: string): ThreatIntelligenceRecord | null => {
  const normalized = input.toLowerCase().trim();
  const match = INITIAL_IOCS.find(
    (ioc) =>
      normalized.includes(ioc.value.toLowerCase()) ||
      ioc.value.toLowerCase().includes(normalized)
  );
  return match || null;
};
