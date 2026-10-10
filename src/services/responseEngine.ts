import { Incident, ResponseActionItem, Threat } from '../types/cyberguard';

export interface AutomatedResponseResult {
  threatId: string;
  incidentId: string;
  executedActions: ResponseActionItem[];
  auditLog: Array<{
    timestamp: string;
    action: string;
    target: string;
    status: 'SUCCESS' | 'EXECUTED';
  }>;
}

export const executeAutomatedPlaybook = (
  threat: Threat,
  customIncidentId?: string
): AutomatedResponseResult => {
  const now = new Date();
  const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const incidentId = customIncidentId || `INC-2026-${Math.floor(1000 + Math.random() * 9000)}`;

  const defaultActionTemplates: Record<string, string[]> = {
    'Phishing': [
      'BLOCK URL across Global DNS & Web Filter Proxies',
      'QUARANTINE Phishing Email from all inboxes',
      'ALERT Recipient with Security Threat Advisory',
      'REVOKE Sessions for compromised user accounts',
      'CREATE Official SOC Incident Record',
      'SUBMIT Takedown request to Domain Registrar'
    ],
    'Brand Impersonation': [
      'BLOCK Malicious Domain at Boundary Firewalls',
      'REPORT Phishing & Trademark Infringement',
      'ALERT Internal Users of active spoofing campaign',
      'CREATE Brand Abuse Incident Record'
    ],
    'Account Takeover': [
      'REVOKE All Active OAuth & SSO Sessions',
      'FORCE Immediate Enterprise Password Reset',
      'ENFORCE Step-Up MFA Challenge',
      'LOCK High-Privilege Account Access',
      'ALERT Tier-3 SOC Security Analyst'
    ],
    'Impossible Travel': [
      'TERMINATE Anomalous Foreign Session',
      'CHALLENGE User with Hardware MFA Token',
      'NOTIFY Employee of foreign geolocation access',
      'LOG Geolocation Anomaly to Security Event Log'
    ],
    'Network Anomaly': [
      'ISOLATE Infected Host from internal VLAN',
      'BLOCK Destination C2 IP at Perimeter Firewall',
      'TRIGGER Memory & Process Forensics Scan',
      'ALERT Network Operations & Incident Team'
    ],
    'Deepfake Media': [
      'QUARANTINE Media File from collaboration channels',
      'WARN Financial Approvers of Synthetic Audio/Video lure',
      'INITIATE Out-of-band identity verification protocol',
      'REGISTER Media Fingerprint to Synthetic Registry'
    ],
    'Malicious File': [
      'QUARANTINE File across all endpoint drives',
      'BLOCK SHA-256 Hash across EDR fleet',
      'TERMINATE Child PowerShell / CMD processes',
      'NOTIFY Affected user and IT Support'
    ],
    'Social Engineering': [
      'BLOCK Originating Sender Phone Number & Handle',
      'WARN Internal Chat Channels of Active Lure',
      'ADD Extracted URL to Perimeter Blacklist',
      'CREATE Security Incident Record'
    ]
  };

  const actionStrings = defaultActionTemplates[threat.category] || defaultActionTemplates['Phishing'];

  const executedActions: ResponseActionItem[] = actionStrings.map((action, idx) => ({
    id: `ACT-${Date.now()}-${idx}`,
    action,
    executed: true,
    executedAt: timeStr,
    user: 'CyberGuard Autonomous SOAR',
    status: 'success',
  }));

  const auditLog = actionStrings.map((action) => ({
    timestamp: timeStr,
    action,
    target: threat.target,
    status: 'SUCCESS' as const,
  }));

  return {
    threatId: threat.id,
    incidentId,
    executedActions,
    auditLog,
  };
};

export const createIncidentFromThreat = (
  threat: Threat,
  incidentId: string,
  executedActions: ResponseActionItem[]
): Incident => {
  const now = new Date();
  const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  return {
    id: incidentId,
    title: threat.title,
    threatType: threat.category,
    severity: threat.severity,
    riskScore: threat.riskScore,
    status: 'CONTAINED',
    affectedUser: threat.metadata?.user || (threat.source === 'Email' ? 'alex.morgan@cyberguard.internal' : 'siddharth.m@enterprise.internal'),
    source: `${threat.source} Detection Gateway`,
    detectionTime: threat.timestamp,
    timeline: [
      { id: '1', time: threat.timestamp, event: `${threat.source} input ingested by CyberGuard Gateway`, type: 'detection' },
      { id: '2', time: threat.timestamp, event: `AI Multi-Modal Engine flagged ${threat.severity} risk (${threat.riskScore}/100)`, type: 'analysis' },
      ...executedActions.map((act, i) => ({
        id: `tl-${i + 3}`,
        time: act.executedAt || timeStr,
        event: act.action,
        type: 'response' as const,
        status: 'SUCCESS',
      })),
      { id: 'tl-contained', time: timeStr, event: 'Automated Containment Verified — Zero Lateral Propagation', type: 'containment' },
    ],
    evidence: threat.indicators,
    aiRecommendation: threat.explanation,
    responseActions: executedActions,
    mitigationNotes: `Automated SOAR playbook executed flawlessly. Host & credentials isolated. Risk score contained from ${threat.riskScore}/100 to Safe baseline.`,
  };
};
