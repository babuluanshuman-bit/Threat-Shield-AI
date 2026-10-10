import React, { createContext, useContext, useState, useEffect } from 'react';
import {
  Threat,
  Incident,
  AuthenticationEvent,
  NetworkEvent,
  SecurityPosture,
  SecurityNotification,
  ThreatCategory,
  RiskLevel
} from '../types/cyberguard';
import {
  INITIAL_SOC_METRICS,
  INITIAL_THREATS,
  INITIAL_INCIDENTS,
  INITIAL_AUTH_EVENTS,
  INITIAL_NETWORK_EVENTS,
  INITIAL_POSTURE,
  INITIAL_NOTIFICATIONS,
  SocMetrics
} from '../data/mockCyberData';
import { ATTACK_SCENARIOS } from '../data/attackScenarios';
import { executeAutomatedPlaybook, createIncidentFromThreat } from '../services/responseEngine';
import confetti from 'canvas-confetti';

interface CyberGuardContextType {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  metrics: SocMetrics;
  threats: Threat[];
  incidents: Incident[];
  selectedIncident: Incident | null;
  setSelectedIncident: (inc: Incident | null) => void;
  authEvents: AuthenticationEvent[];
  networkEvents: NetworkEvent[];
  notifications: SecurityNotification[];
  unreadNotificationCount: number;
  posture: SecurityPosture;
  auditLogs: Array<{ timestamp: string; action: string; target: string; status: string }>;
  isDemoMode: boolean;
  toggleDemoMode: () => void;
  
  // Modals & Drawers
  copilotOpen: boolean;
  setCopilotOpen: (v: boolean) => void;
  searchOpen: boolean;
  setSearchOpen: (v: boolean) => void;
  notificationsOpen: boolean;
  setNotificationsOpen: (v: boolean) => void;
  simulationModalOpen: boolean;
  setSimulationModalOpen: (v: boolean) => void;
  activeScenarioId: string;
  setActiveScenarioId: (id: string) => void;

  // Mobile Sidebar Drawer
  mobileSidebarOpen: boolean;
  setMobileSidebarOpen: (v: boolean) => void;

  // Real-Time Alert Banner
  liveAlert: Threat | null;
  dismissLiveAlert: () => void;

  // Core Actions
  ingestNewThreat: (threat: Threat) => void;
  executeSOAR: (threat: Threat) => Incident;
  updateIncidentStatus: (id: string, status: Incident['status']) => void;
  remediatePostureItem: (id: string) => void;
  markNotificationRead: (id: string) => void;
  markAllNotificationsRead: () => void;
  triggerLiveAttackDemo: (scenarioId?: string) => void;
}

const CyberGuardContext = createContext<CyberGuardContextType | undefined>(undefined);

export const CyberGuardProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [metrics, setMetrics] = useState<SocMetrics>(INITIAL_SOC_METRICS);
  const [threats, setThreats] = useState<Threat[]>(INITIAL_THREATS);
  const [incidents, setIncidents] = useState<Incident[]>(INITIAL_INCIDENTS);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(INITIAL_INCIDENTS[0]);
  const [authEvents, setAuthEvents] = useState<AuthenticationEvent[]>(INITIAL_AUTH_EVENTS);
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>(INITIAL_NETWORK_EVENTS);
  const [notifications, setNotifications] = useState<SecurityNotification[]>(INITIAL_NOTIFICATIONS);
  const [posture, setPosture] = useState<SecurityPosture>(INITIAL_POSTURE);
  const [auditLogs, setAuditLogs] = useState<Array<{ timestamp: string; action: string; target: string; status: string }>>([
    { timestamp: '10:23 AM', action: 'URL BLOCKED in perimeter firewall & DNS', target: 'secure-bank-login.xyz', status: 'SUCCESS' },
    { timestamp: '10:23 AM', action: 'EMAIL QUARANTINED across all mailboxes', target: 'security@paypa1-support.com', status: 'SUCCESS' },
    { timestamp: '10:25 AM', action: 'SESSION REVOKED across enterprise IdP', target: 'alex.morgan', status: 'SUCCESS' },
    { timestamp: '09:45 AM', action: 'REVOKE ALL SESSIONS globally', target: 'priya.sharma', status: 'SUCCESS' },
  ]);

  const [isDemoMode, setIsDemoMode] = useState<boolean>(true);
  const [copilotOpen, setCopilotOpen] = useState<boolean>(false);
  const [searchOpen, setSearchOpen] = useState<boolean>(false);
  const [notificationsOpen, setNotificationsOpen] = useState<boolean>(false);
  const [simulationModalOpen, setSimulationModalOpen] = useState<boolean>(false);
  const [activeScenarioId, setActiveScenarioId] = useState<string>('scenario-phishing');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState<boolean>(false);
  const [liveAlert, setLiveAlert] = useState<Threat | null>(null);

  // Global Keyboard Shortcut: Ctrl + K or Cmd + K opens Global Search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSearchOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const unreadNotificationCount = notifications.filter((n) => !n.read).length;

  const toggleDemoMode = () => {
    setIsDemoMode((prev) => !prev);
  };

  const dismissLiveAlert = () => {
    setLiveAlert(null);
  };

  const ingestNewThreat = (threat: Threat) => {
    setThreats((prev) => [threat, ...prev]);

    setMetrics((prev) => ({
      ...prev,
      threatsDetected: prev.threatsDetected + 1,
      criticalThreats: threat.severity === 'CRITICAL' ? prev.criticalThreats + 1 : prev.criticalThreats,
      phishingThreats: threat.category === 'Phishing' ? prev.phishingThreats + 1 : prev.phishingThreats,
      impersonationThreats: threat.category === 'Brand Impersonation' ? prev.impersonationThreats + 1 : prev.impersonationThreats,
    }));

    // Trigger notification
    const newNotif: SecurityNotification = {
      id: `notif-${Date.now()}`,
      title: `${threat.severity} Threat Detected: ${threat.category}`,
      message: threat.summary,
      severity: threat.severity,
      timestamp: 'Just now',
      read: false,
      threatId: threat.id,
      incidentId: threat.assignedIncidentId,
    };
    setNotifications((prev) => [newNotif, ...prev]);

    // If High or Critical, show Live Alert banner
    if (threat.severity === 'CRITICAL' || threat.severity === 'HIGH') {
      setLiveAlert(threat);
    }
  };

  const executeSOAR = (threat: Threat): Incident => {
    const { incidentId, executedActions, auditLog: newAuditLogs } = executeAutomatedPlaybook(threat);
    const newIncident = createIncidentFromThreat(threat, incidentId, executedActions);

    // Update Threat status
    setThreats((prev) =>
      prev.map((t) => (t.id === threat.id ? { ...t, status: 'CONTAINED', assignedIncidentId: incidentId } : t))
    );

    // Add Incident
    setIncidents((prev) => [newIncident, ...prev]);
    setSelectedIncident(newIncident);

    // Update Metrics
    setMetrics((prev) => ({
      ...prev,
      blockedThreats: prev.blockedThreats + 1,
      activeIncidents: prev.activeIncidents + 1,
      securityScore: Math.min(99, prev.securityScore + 1),
    }));

    // Append Audit Logs
    setAuditLogs((prev) => [...newAuditLogs, ...prev]);

    // Push notification
    const notif: SecurityNotification = {
      id: `notif-${Date.now()}`,
      title: `SOAR Playbook Executed: ${incidentId}`,
      message: `Automated containment executed for ${threat.category}. Threat isolated.`,
      severity: 'SAFE',
      timestamp: 'Just now',
      read: false,
      incidentId,
      actionTaken: 'CONTAINED',
    };
    setNotifications((prev) => [notif, ...prev]);

    // Dismiss any active alert banner for this threat
    setLiveAlert(null);

    // Trigger celebration confetti
    try {
      confetti({
        particleCount: 50,
        spread: 60,
        origin: { y: 0.8 },
        colors: ['#00f0ff', '#10b981', '#3b82f6'],
      });
    } catch (e) {
      // ignore in tests
    }

    return newIncident;
  };

  const updateIncidentStatus = (id: string, status: Incident['status']) => {
    setIncidents((prev) => {
      const updated = prev.map((inc) => {
        if (inc.id === id) {
          const newEvent = {
            id: `timeline-${Date.now()}`,
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            event: `Status updated to ${status} by SOC Operator`,
            type: status === 'RESOLVED' ? ('containment' as const) : ('analysis' as const),
            status: 'SUCCESS',
          };
          return {
            ...inc,
            status,
            timeline: [newEvent, ...inc.timeline],
          };
        }
        return inc;
      });

      const activeCount = updated.filter((i) => i.status !== 'RESOLVED').length;
      setMetrics((m) => ({ ...m, activeIncidents: activeCount }));

      return updated;
    });

    setSelectedIncident((prev) => {
      if (prev && prev.id === id) {
        const newEvent = {
          id: `timeline-${Date.now()}`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          event: `Status updated to ${status} by SOC Operator`,
          type: status === 'RESOLVED' ? ('containment' as const) : ('analysis' as const),
          status: 'SUCCESS',
        };
        return {
          ...prev,
          status,
          timeline: [newEvent, ...prev.timeline],
        };
      }
      return prev;
    });
  };

  const remediatePostureItem = (id: string) => {
    setPosture((prev) => {
      const updatedRecs = prev.recommendations.map((r) =>
        r.id === id ? { ...r, remediated: true } : r
      );
      const newScore = Math.min(100, prev.overallScore + 4);
      return {
        ...prev,
        overallScore: newScore,
        recommendations: updatedRecs,
      };
    });

    setMetrics((prev) => ({
      ...prev,
      securityScore: Math.min(100, prev.securityScore + 3),
    }));
  };

  const markNotificationRead = (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  };

  const markAllNotificationsRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const triggerLiveAttackDemo = (scenarioId = 'scenario-phishing') => {
    setActiveScenarioId(scenarioId);
    setSimulationModalOpen(true);
  };

  return (
    <CyberGuardContext.Provider
      value={{
        activeTab,
        setActiveTab,
        metrics,
        threats,
        incidents,
        selectedIncident,
        setSelectedIncident,
        authEvents,
        networkEvents,
        notifications,
        unreadNotificationCount,
        posture,
        auditLogs,
        isDemoMode,
        toggleDemoMode,
        copilotOpen,
        setCopilotOpen,
        searchOpen,
        setSearchOpen,
        notificationsOpen,
        setNotificationsOpen,
        simulationModalOpen,
        setSimulationModalOpen,
        activeScenarioId,
        setActiveScenarioId,
        mobileSidebarOpen,
        setMobileSidebarOpen,
        liveAlert,
        dismissLiveAlert,
        ingestNewThreat,
        executeSOAR,
        updateIncidentStatus,
        remediatePostureItem,
        markNotificationRead,
        markAllNotificationsRead,
        triggerLiveAttackDemo,
      }}
    >
      {children}
    </CyberGuardContext.Provider>
  );
};

export const useCyberGuard = (): CyberGuardContextType => {
  const context = useContext(CyberGuardContext);
  if (!context) {
    throw new Error('useCyberGuard must be used within a CyberGuardProvider');
  }
  return context;
};
