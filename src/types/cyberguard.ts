export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatCategory = 
  | 'Phishing'
  | 'Brand Impersonation'
  | 'Account Takeover'
  | 'Deepfake Media'
  | 'Malicious URL'
  | 'Impossible Travel'
  | 'Brute Force'
  | 'Network Anomaly'
  | 'Malicious File'
  | 'Social Engineering'
  | 'Credential Theft';

export type ThreatSource = 
  | 'URL'
  | 'Email'
  | 'SMS'
  | 'WhatsApp'
  | 'Social Media'
  | 'Network'
  | 'Authentication'
  | 'File'
  | 'Media'
  | 'Browser';

export interface ThreatIndicator {
  name: string;
  finding: string;
  impact: number; // e.g. +25, +30, -5
  severity: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  details?: string;
}

export interface Threat {
  id: string;
  timestamp: string;
  source: ThreatSource;
  target: string;
  category: ThreatCategory;
  riskScore: number; // 0 - 100
  severity: RiskLevel;
  title: string;
  summary: string;
  status: 'DETECTED' | 'ANALYZING' | 'BLOCKED' | 'QUARANTINED' | 'CONTAINED' | 'MITIGATED';
  indicators: ThreatIndicator[];
  explanation: string;
  recommendations: string[];
  metadata?: Record<string, any>;
  assignedIncidentId?: string;
}

export interface IncidentTimelineEvent {
  id: string;
  time: string;
  event: string;
  status?: string;
  type?: 'detection' | 'analysis' | 'response' | 'containment';
}

export interface ResponseActionItem {
  id: string;
  action: string;
  executed: boolean;
  executedAt?: string;
  user?: string;
  status?: 'pending' | 'success' | 'failed';
}

export interface Incident {
  id: string; // e.g. INC-2026-0142
  title: string;
  threatType: ThreatCategory;
  severity: RiskLevel;
  riskScore: number;
  status: 'DETECTED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  affectedUser: string;
  source: string;
  detectionTime: string;
  timeline: IncidentTimelineEvent[];
  evidence: ThreatIndicator[];
  aiRecommendation: string;
  responseActions: ResponseActionItem[];
  mitigationNotes?: string;
}

export interface AttackSimulationStep {
  id: string;
  title: string;
  phase: 'INPUT' | 'INGEST' | 'AI_ANALYSIS' | 'INDICATORS' | 'RISK_SCORE' | 'RECOMMENDATION' | 'RESPONSE' | 'CONTAINMENT';
  description: string;
  status: 'pending' | 'active' | 'completed';
  timestamp?: string;
  logDetail?: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  category: ThreatCategory;
  initialPayload: any;
  steps: AttackSimulationStep[];
  resultingThreat: Threat;
  resultingIncident: Incident;
}

export interface PostureCategory {
  name: string;
  score: number;
  weight: number;
  status: 'healthy' | 'warning' | 'critical';
}

export interface SecurityPosture {
  overallScore: number;
  categories: Record<string, number>;
  recommendations: Array<{
    id: string;
    title: string;
    category: string;
    impact: string;
    remediated: boolean;
  }>;
}

export interface AuthenticationEvent {
  id: string;
  timestamp: string;
  user: string;
  userEmail: string;
  ip: string;
  location: string;
  device: string;
  status: 'SUCCESS' | 'FAILED';
  riskScore: number;
  severity: RiskLevel;
  anomalyReason?: string;
}

export interface NetworkEvent {
  id: string;
  timestamp: string;
  srcIp: string;
  destIp: string;
  port: number;
  protocol: 'TCP' | 'UDP' | 'HTTPS' | 'DNS';
  connectionsPerMin: number;
  normalBaseline: number;
  trafficVolumeMb: number;
  riskScore: number;
  severity: RiskLevel;
  threatType: string;
}

export interface ThreatIntelligenceRecord {
  id: string;
  type: 'IP' | 'Domain' | 'URL' | 'Hash' | 'Campaign';
  value: string;
  threatType: string;
  confidence: number; // 0-100%
  reportedBy: string;
  firstSeen: string;
  status: 'Active' | 'Under Investigation' | 'Takedown In Progress' | 'Neutralized';
  severity: RiskLevel;
}

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  suggestedActions?: string[];
  incidentRef?: string;
  threatRef?: string;
}

export interface SecurityNotification {
  id: string;
  title: string;
  message: string;
  severity: RiskLevel;
  timestamp: string;
  read: boolean;
  incidentId?: string;
  threatId?: string;
  actionTaken?: string;
}
