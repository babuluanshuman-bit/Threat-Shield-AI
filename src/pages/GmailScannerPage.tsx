import React, { useState, useEffect } from 'react';
import { useCyberGuard } from '../context/CyberGuardContext';
import {
  ScannedGmailEmail,
  scanGmailMailbox,
  requestGmailOAuthToken,
  fetchLiveGmailProfile,
  GmailUserProfile,
  DEFAULT_GOOGLE_CLIENT_ID,
} from '../services/gmailScannerService';
import { Threat } from '../types/cyberguard';
import { RiskGauge } from '../components/common/RiskGauge';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import { GmailOAuthModal } from '../components/gmail/GmailOAuthModal';
import { EmailForensicModal } from '../components/gmail/EmailForensicModal';
import {
  Mail,
  Shield,
  Zap,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ExternalLink,
  Key,
  Search,
  Filter,
  Download,
  Ban,
  FileCode,
  Globe,
  Radio,
  Sparkles,
  Info,
  Check,
  ChevronRight,
  UserCheck,
  LogOut,
  SlidersHorizontal,
  RefreshCw
} from 'lucide-react';

export const GmailScannerPage: React.FC = () => {
  const { ingestNewThreat, executeSOAR } = useCyberGuard();

  // OAuth & Connection State
  const [clientId, setClientId] = useState<string>(() => {
    const stored = localStorage.getItem('CYBERGUARD_GOOGLE_CLIENT_ID');
    if (stored && stored.includes('.apps.googleusercontent.com')) {
      return stored;
    }
    return (import.meta.env.VITE_GOOGLE_CLIENT_ID as string) || DEFAULT_GOOGLE_CLIENT_ID;
  });
  const [accessToken, setAccessToken] = useState<string>(() => {
    return localStorage.getItem('CYBERGUARD_GOOGLE_ACCESS_TOKEN') || '';
  });
  const [userProfile, setUserProfile] = useState<GmailUserProfile | null>(null);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isSandboxMode, setIsSandboxMode] = useState<boolean>(true);
  const [emailInputHint, setEmailInputHint] = useState<string>('secops-analyst@threatlens.ai');

  // Scanner State
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number; message: string }>({
    current: 0,
    total: 0,
    message: '',
  });
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterQueryPreset, setFilterQueryPreset] = useState<string>('all');
  const [activeFilterTab, setActiveFilterTab] = useState<'all' | 'malicious' | 'suspicious' | 'safe'>('all');
  const [emails, setEmails] = useState<ScannedGmailEmail[]>([]);

  // Modals
  const [showConfigModal, setShowConfigModal] = useState<boolean>(false);
  const [selectedForensicEmail, setSelectedForensicEmail] = useState<ScannedGmailEmail | null>(null);

  // Auto-connect to live account if token exists, or start in sandbox mode
  useEffect(() => {
    if (accessToken) {
      fetchLiveGmailProfile(accessToken)
        .then((profile) => {
          setUserProfile(profile);
          setIsConnected(true);
          setIsSandboxMode(false);
          runScan({ isLive: true, token: accessToken, query: '' });
        })
        .catch(() => {
          // Token expired or invalid
          localStorage.removeItem('CYBERGUARD_GOOGLE_ACCESS_TOKEN');
          setAccessToken('');
          setIsConnected(false);
          setIsSandboxMode(true);
          runScan({ isLive: false, query: '' });
        });
    } else {
      // Default to high-fidelity sandbox mailbox on first load
      runScan({ isLive: false, query: '' });
    }
  }, []);

  const runScan = async (params: { isLive: boolean; token?: string; query?: string }) => {
    setIsScanning(true);
    setScanProgress({ current: 0, total: 8, message: 'Initializing Threat Lens AI Mailbox Engine...' });

    try {
      const results = await scanGmailMailbox({
        isLive: params.isLive,
        accessToken: params.token || accessToken,
        query: params.query || '',
        maxResults: 8,
        checkVirusTotal: true,
        onProgress: (current, total, message) => {
          setScanProgress({ current, total, message });
        },
      });

      setEmails(results);
    } catch (err: any) {
      console.error('Mailbox scan error:', err);
    } finally {
      setIsScanning(false);
      setScanProgress({ current: 0, total: 0, message: '' });
    }
  };

  // Google OAuth 2.0 Flow
  const handleConnectGoogle = async () => {
    // If no valid Google Cloud Client ID is configured, open the permission consent dialog
    if (!clientId.trim() || !clientId.includes('.apps.googleusercontent.com')) {
      setShowConfigModal(true);
      return;
    }

    try {
      setIsScanning(true);
      setScanProgress({ current: 0, total: 1, message: 'Opening Google OAuth 2.0 Authorization Window...' });

      const token = await requestGmailOAuthToken(clientId);
      localStorage.setItem('CYBERGUARD_GOOGLE_ACCESS_TOKEN', token);
      setAccessToken(token);

      const profile = await fetchLiveGmailProfile(token);
      setUserProfile(profile);
      setIsConnected(true);
      setIsSandboxMode(false);

      await runScan({ isLive: true, token, query: '' });
    } catch (err: any) {
      console.error('OAuth connection error:', err);
      setShowConfigModal(true);
      alert(`Google OAuth Notice: ${err.message || 'Authentication could not complete.'}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleInstantAuthorize = (email: string) => {
    const targetEmail = (email || emailInputHint || 'secops-analyst@threatlens.ai').trim();
    setUserProfile({
      emailAddress: targetEmail,
      messagesTotal: 8,
      threadsTotal: 8,
    });
    setIsConnected(true);
    setIsSandboxMode(false);
    runScan({ isLive: false, query: '' });
  };

  const handleDisconnect = () => {
    localStorage.removeItem('CYBERGUARD_GOOGLE_ACCESS_TOKEN');
    setAccessToken('');
    setUserProfile(null);
    setIsConnected(false);
    setIsSandboxMode(true);
    runScan({ isLive: false, query: '' });
  };

  const handleSaveClientId = (newId: string) => {
    setClientId(newId);
    localStorage.setItem('CYBERGUARD_GOOGLE_CLIENT_ID', newId);
  };

  const handleSaveManualToken = async (manualToken: string) => {
    const cleanToken = manualToken.replace(/^Bearer\s+/i, '').trim();
    if (!cleanToken) return;

    setAccessToken(cleanToken);
    localStorage.setItem('CYBERGUARD_GOOGLE_ACCESS_TOKEN', cleanToken);
    try {
      setIsScanning(true);
      setScanProgress({ current: 0, total: 1, message: 'Validating Google OAuth access token with Gmail API...' });
      const profile = await fetchLiveGmailProfile(cleanToken);
      setUserProfile(profile);
      setIsConnected(true);
      setIsSandboxMode(false);
      await runScan({ isLive: true, token: cleanToken, query: '' });
    } catch (e: any) {
      console.error('Manual token error:', e);
      alert(
        `Gmail API Authentication Failed: ${
          e.message || 'Token is invalid or expired.'
        }\n\nMake sure the token was generated with the scope "https://www.googleapis.com/auth/gmail.readonly" on developers.google.com/oauthplayground.`
      );
      setAccessToken('');
      localStorage.removeItem('CYBERGUARD_GOOGLE_ACCESS_TOKEN');
      setIsConnected(false);
      setIsSandboxMode(true);
    } finally {
      setIsScanning(false);
    }
  };

  const handleLaunchSandbox = () => {
    setIsConnected(false);
    setIsSandboxMode(true);
    runScan({ isLive: false, query: '' });
  };

  // Ingest Email Threat to SOC Dashboard
  const handleIngestToSoc = (email: ScannedGmailEmail) => {
    const newThreat: Threat = {
      id: `THR-GMAIL-${email.id}`,
      timestamp: 'Just now',
      source: 'Email',
      target: email.fromEmail,
      category: email.threatCategory,
      riskScore: email.riskScore,
      severity: email.severity,
      title: email.suggestedIncidentTitle,
      summary: email.explanation.slice(0, 110) + '...',
      status: 'DETECTED',
      indicators: email.indicators,
      explanation: email.explanation,
      recommendations: email.recommendations,
      metadata: {
        from: email.from,
        subject: email.subject,
        urls: email.extractedUrls,
        attachments: email.attachments.map((a) => a.filename),
        spfStatus: email.authTelemetry.spfStatus,
        dkimStatus: email.authTelemetry.dkimStatus,
        dmarcStatus: email.authTelemetry.dmarcStatus,
        mailboxAccount: userProfile?.emailAddress || 'secops-sandbox@threatlens.ai',
      },
    };

    ingestNewThreat(newThreat);

    setEmails((prev) =>
      prev.map((e) => (e.id === email.id ? { ...e, ingestedToSoc: true } : e))
    );
  };

  // Execute SOAR Automated Containment
  const handleQuarantine = (email: ScannedGmailEmail) => {
    const threatToContain: Threat = {
      id: `THR-GMAIL-${email.id}`,
      timestamp: 'Just now',
      source: 'Email',
      target: email.fromEmail,
      category: email.threatCategory,
      riskScore: email.riskScore,
      severity: email.severity,
      title: email.suggestedIncidentTitle,
      summary: email.explanation,
      status: 'DETECTED',
      indicators: email.indicators,
      explanation: email.explanation,
      recommendations: email.recommendations,
    };

    executeSOAR(threatToContain);

    setEmails((prev) =>
      prev.map((e) => (e.id === email.id ? { ...e, quarantined: true, ingestedToSoc: true } : e))
    );
  };

  // Ingest all Malicious in batch
  const handleIngestAllMalicious = () => {
    const malicious = emails.filter((e) => e.riskScore >= 60 && !e.ingestedToSoc);
    malicious.forEach((m) => handleIngestToSoc(m));
  };

  // Filtered List
  const filteredEmails = emails.filter((e) => {
    // Tab filter
    if (activeFilterTab === 'malicious' && e.riskScore < 70) return false;
    if (activeFilterTab === 'suspicious' && (e.riskScore < 40 || e.riskScore >= 70)) return false;
    if (activeFilterTab === 'safe' && e.riskScore >= 40) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        e.subject.toLowerCase().includes(q) ||
        e.from.toLowerCase().includes(q) ||
        e.senderDomain.toLowerCase().includes(q) ||
        e.snippet.toLowerCase().includes(q);
      if (!match) return false;
    }

    return true;
  });

  // Analytics Metrics
  const totalCount = emails.length;
  const maliciousCount = emails.filter((e) => e.riskScore >= 70).length;
  const suspiciousCount = emails.filter((e) => e.riskScore >= 40 && e.riskScore < 70).length;
  const safeCount = emails.filter((e) => e.riskScore < 40).length;
  const urlsCheckedCount = emails.reduce((acc, e) => acc + e.extractedUrls.length, 0);

  return (
    <div className="space-y-6 pb-12 animate-fade-in max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="p-5 rounded-2xl bg-[#0B1120] border border-slate-800 shadow-cyber-card relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 text-cyan-400 shrink-0">
              <Mail className="w-6 h-6" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-mono font-bold text-white tracking-wide">
                  LIVE GMAIL THREAT RADAR & OAUTH SOC INGESTION
                </h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  GMAIL API + VIRUSTOTAL
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  OAUTH 2.0 READONLY
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
                Inspects inbound Gmail mailboxes via Google OAuth 2.0, extracts email indicators (sender domain, lookalikes, SPF/DKIM/DMARC headers), correlates URLs against VirusTotal v3, and automates SOAR containment.
              </p>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center space-x-2 shrink-0">
            <button
              onClick={() => runScan({ isLive: isConnected, query: filterQueryPreset !== 'all' ? filterQueryPreset : '' })}
              disabled={isScanning}
              className="px-4 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold transition-all flex items-center space-x-1.5 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
              <span>Rescan Mailbox</span>
            </button>
          </div>
        </div>

        {/* Workflow Diagram Banner */}
        <div className="mt-4 pt-3 border-t border-slate-800/80">
          <div className="flex items-center space-x-1 text-[11px] font-mono text-slate-400 overflow-x-auto pb-1">
            <span className="text-slate-500 uppercase tracking-wider shrink-0 font-bold mr-1">Architecture Pipeline:</span>
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 shrink-0">1. Connect Gmail</span>
            <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-blue-300 shrink-0">2. Google OAuth 2.0</span>
            <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-purple-300 shrink-0">3. Gmail API messages.get</span>
            <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-amber-300 shrink-0">4. Indicator Extraction</span>
            <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-rose-300 shrink-0">5. VirusTotal & AI Heuristics</span>
            <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-emerald-300 shrink-0">6. SOC Ingestion & SOAR</span>
          </div>
        </div>
      </div>

      {/* Account Authorization Card */}
      <div className="p-5 sm:p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-cyber-card">
        {!isConnected ? (
          <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
            <div className="space-y-3 max-w-2xl w-full">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
                <h2 className="text-sm font-mono font-bold text-white uppercase tracking-wider">
                  MAILBOX INTEGRATION: CONNECT GMAIL VIA GOOGLE OAUTH 2.0
                </h2>
              </div>
              <p className="text-xs text-slate-300 font-sans leading-relaxed">
                Connect your Gmail mailbox to autonomously inspect inbound emails. Access is strictly read-only (<code className="text-cyan-300 font-mono text-[10px]">https://www.googleapis.com/auth/gmail.readonly</code>). Threat Lens AI will never modify or delete emails.
              </p>

              {/* Email Input Field + Connect Button */}
              <div className="flex flex-col sm:flex-row items-center gap-2 pt-1">
                <div className="relative flex-1 w-full">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
                  <input
                    type="email"
                    value={emailInputHint}
                    onChange={(e) => setEmailInputHint(e.target.value)}
                    placeholder="Enter Gmail address (e.g. secops-analyst@threatlens.ai)"
                    className="w-full pl-9 pr-3 py-2.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 font-mono text-xs text-slate-100 focus:outline-none"
                  />
                </div>
                <button
                  onClick={handleConnectGoogle}
                  disabled={isScanning}
                  className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-white hover:bg-slate-100 text-slate-900 font-sans font-bold text-xs shadow-lg transition-all transform active:scale-95 flex items-center justify-center space-x-2 shrink-0"
                >
                  {/* Google Multicolor 'G' Icon */}
                  <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                  </svg>
                  <span>Connect Gmail</span>
                </button>
              </div>
            </div>

          </div>
        ) : (
          <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
            <div className="flex items-center space-x-3.5">
              <div className="w-11 h-11 rounded-xl bg-gradient-to-tr from-emerald-500 to-teal-600 flex items-center justify-center text-slate-950 font-bold font-mono text-lg shadow-[0_0_20px_rgba(16,185,129,0.3)] shrink-0">
                {userProfile?.emailAddress?.charAt(0).toUpperCase() || 'G'}
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-sm font-mono font-bold text-white">
                    {userProfile?.emailAddress}
                  </h2>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center space-x-1">
                    <Check className="w-3 h-3" />
                    <span>OAuth Authorized</span>
                  </span>
                </div>
                <div className="flex items-center space-x-3 text-xs font-mono text-slate-400 mt-0.5">
                  <span>Total Messages: <strong className="text-slate-200">{userProfile?.messagesTotal?.toLocaleString() || 0}</strong></span>
                  <span>•</span>
                  <span>Scope: <strong className="text-cyan-300">gmail.readonly</strong></span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-3 w-full lg:w-auto justify-end">
              <button
                onClick={handleDisconnect}
                className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-rose-300 border border-slate-700 text-xs font-mono transition-colors flex items-center space-x-1.5"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Disconnect</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Real-Time Scan Progress Banner */}
      {isScanning && (
        <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 via-blue-950/30 to-purple-950/40 border border-cyan-500/40 animate-pulse space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center space-x-2">
              <RotateCcw className="w-4 h-4 text-cyan-400 animate-spin" />
              <span className="text-cyan-300 font-bold">Scanning Mailbox & Evaluating Security Rules...</span>
            </div>
            <span className="text-slate-400">
              {scanProgress.current} / {scanProgress.total} Items
            </span>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-300"
              style={{
                width: `${scanProgress.total > 0 ? (scanProgress.current / scanProgress.total) * 100 : 25}%`,
              }}
            />
          </div>
          <p className="text-[11px] font-mono text-slate-400 truncate">
            {scanProgress.message}
          </p>
        </div>
      )}

      {/* SOC Analytics KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 sm:gap-4">
        <div className="p-4 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Total Scanned</span>
          <span className="text-xl sm:text-2xl font-mono font-bold text-white mt-1 block">
            {totalCount}
          </span>
          <span className="text-[10px] font-mono text-cyan-400">Mailbox Telemetry</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#070C18] border border-rose-500/30 shadow-cyber-card">
          <span className="text-[10px] font-mono uppercase text-rose-400 block">Malicious Phish</span>
          <span className="text-xl sm:text-2xl font-mono font-bold text-rose-400 mt-1 block">
            {maliciousCount}
          </span>
          <span className="text-[10px] font-mono text-rose-500">Risk &ge; 70 (Critical)</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#070C18] border border-amber-500/30 shadow-cyber-card">
          <span className="text-[10px] font-mono uppercase text-amber-400 block">Suspicious Cues</span>
          <span className="text-xl sm:text-2xl font-mono font-bold text-amber-400 mt-1 block">
            {suspiciousCount}
          </span>
          <span className="text-[10px] font-mono text-amber-500">Risk 40 - 69</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#070C18] border border-emerald-500/30 shadow-cyber-card">
          <span className="text-[10px] font-mono uppercase text-emerald-400 block">Verified Safe</span>
          <span className="text-xl sm:text-2xl font-mono font-bold text-emerald-400 mt-1 block">
            {safeCount}
          </span>
          <span className="text-[10px] font-mono text-emerald-500">SPF/DKIM Intact</span>
        </div>

        <div className="p-4 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card col-span-2 sm:col-span-1">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">URLs Evaluated</span>
          <span className="text-xl sm:text-2xl font-mono font-bold text-cyan-400 mt-1 block">
            {urlsCheckedCount}
          </span>
          <span className="text-[10px] font-mono text-cyan-500">VirusTotal v3</span>
        </div>
      </div>

      {/* Query Filters & Preset Chips */}
      <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          {/* Preset Queries */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-500 mr-1 flex items-center space-x-1">
              <Filter className="w-3 h-3 text-cyan-400" />
              <span>Gmail Query Filters:</span>
            </span>
            {[
              { id: 'all', label: 'All Recent (8)' },
              { id: 'is:unread', label: 'Unread Only (is:unread)' },
              { id: 'has:attachment', label: 'Has Attachments' },
              { id: 'urgent OR invoice OR verify', label: 'High-Urgency & Invoices' },
            ].map((preset) => (
              <button
                key={preset.id}
                onClick={() => {
                  setFilterQueryPreset(preset.id);
                  runScan({
                    isLive: isConnected,
                    query: preset.id !== 'all' ? preset.id : '',
                  });
                }}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors border ${
                  filterQueryPreset === preset.id
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold'
                    : 'bg-slate-800 hover:bg-slate-750 text-slate-300 border-slate-700'
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>

          {/* Batch Ingest Button */}
          {maliciousCount > 0 && (
            <button
              onClick={handleIngestAllMalicious}
              className="px-3 py-1.5 rounded-xl bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-400 hover:to-red-500 text-white font-mono font-bold text-[11px] uppercase tracking-wider shadow-[0_0_15px_rgba(244,63,94,0.3)] transition-all shrink-0 flex items-center space-x-1.5"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Ingest All Malicious to SOC ({maliciousCount})</span>
            </button>
          )}
        </div>

        {/* Triage Tabs & Search Bar */}
        <div className="pt-2 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            {[
              { id: 'all', label: `All (${totalCount})` },
              { id: 'malicious', label: `Malicious (${maliciousCount})` },
              { id: 'suspicious', label: `Suspicious (${suspiciousCount})` },
              { id: 'safe', label: `Safe (${safeCount})` },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveFilterTab(tab.id as any)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  activeFilterTab === tab.id
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(0,240,255,0.15)]'
                    : 'text-slate-400 hover:text-white bg-slate-900 border border-transparent'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="relative max-w-xs w-full">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search sender, subject..."
              className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 font-mono text-xs text-slate-100 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* Scanned Email List Cards */}
      <div className="space-y-3">
        {filteredEmails.length === 0 ? (
          <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800 text-slate-400 space-y-2">
            <Mail className="w-10 h-10 mx-auto text-slate-600" />
            <p className="font-mono text-sm text-slate-300">No emails matching current filter</p>
            <p className="text-xs text-slate-500">Try changing query presets or search keyword.</p>
          </div>
        ) : (
          filteredEmails.map((email) => {
            const isHighRisk = email.riskScore >= 70;
            const isMediumRisk = email.riskScore >= 40 && email.riskScore < 70;

            return (
              <div
                key={email.id}
                className={`p-4 sm:p-5 rounded-2xl border transition-all ${
                  isHighRisk
                    ? 'bg-[#0E0C18] border-rose-500/35 hover:border-rose-500/60 shadow-[0_4px_20px_rgba(239,68,68,0.08)]'
                    : isMediumRisk
                    ? 'bg-[#0F121C] border-amber-500/35 hover:border-amber-500/60'
                    : 'bg-[#070C18] border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left Column: Risk Gauge + Email Metadata */}
                  <div className="flex items-start space-x-4 min-w-0">
                    <div className="shrink-0 flex flex-col items-center">
                      <RiskGauge score={email.riskScore} size="sm" />
                      <span className="text-[10px] font-mono font-bold mt-1 text-slate-400">
                        {email.riskScore}/100
                      </span>
                    </div>

                    <div className="space-y-1.5 min-w-0">
                      {/* Top Badges */}
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge level={email.severity} size="sm" />
                        <ThreatBadge category={email.threatCategory} size="sm" />

                        {email.isUnread && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase bg-blue-500/20 text-blue-300 border border-blue-500/30">
                            UNREAD
                          </span>
                        )}

                        {email.attachments.length > 0 && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30 flex items-center space-x-1">
                            <FileCode className="w-2.5 h-2.5" />
                            <span>{email.attachments.length} ATTACHMENT</span>
                          </span>
                        )}

                        {email.quarantined && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            ✓ QUARANTINED
                          </span>
                        )}

                        {email.ingestedToSoc && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                            INGESTED TO SOC
                          </span>
                        )}
                      </div>

                      {/* Subject */}
                      <h3 className="font-mono text-sm font-bold text-white tracking-wide truncate">
                        {email.subject}
                      </h3>

                      {/* Sender Details */}
                      <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                        <span className="text-slate-400">
                          From:{' '}
                          <strong className={isHighRisk ? 'text-rose-300' : 'text-cyan-300'}>
                            {email.from}
                          </strong>
                        </span>
                        <span className="text-slate-600">•</span>
                        <span className="text-slate-500">{email.date}</span>
                      </div>

                      {/* Snippet */}
                      <p className="text-xs text-slate-300 font-sans line-clamp-2">
                        {email.snippet}
                      </p>

                      {/* Indicator Pills */}
                      <div className="flex flex-wrap items-center gap-1.5 pt-1">
                        {email.indicators.slice(0, 3).map((ind, idx) => (
                          <span
                            key={idx}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                              ind.severity === 'critical'
                                ? 'bg-rose-950/40 text-rose-300 border-rose-500/30'
                                : ind.severity === 'high'
                                ? 'bg-orange-950/40 text-orange-300 border-orange-500/30'
                                : 'bg-slate-900 text-slate-300 border-slate-800'
                            }`}
                          >
                            {ind.name}: <strong className="font-bold">{ind.finding.slice(0, 35)}</strong>
                          </span>
                        ))}
                        {email.indicators.length > 3 && (
                          <span className="text-[10px] font-mono text-slate-500">
                            +{email.indicators.length - 3} more indicators
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Right Column: Actions */}
                  <div className="flex lg:flex-col items-center lg:items-end justify-end gap-2 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-800">
                    <button
                      onClick={() => setSelectedForensicEmail(email)}
                      className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-cyan-300 border border-slate-700 text-xs font-mono font-semibold transition-colors flex items-center space-x-1.5"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Inspect Forensics</span>
                    </button>

                    <button
                      onClick={() => handleIngestToSoc(email)}
                      disabled={email.ingestedToSoc}
                      className="px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-850 text-slate-300 border border-slate-800 text-[11px] font-mono transition-colors disabled:opacity-50 flex items-center space-x-1"
                    >
                      <Zap className="w-3 h-3 text-cyan-400" />
                      <span>{email.ingestedToSoc ? 'Ingested' : 'Ingest to SOC'}</span>
                    </button>

                    {email.riskScore >= 40 && (
                      <button
                        onClick={() => handleQuarantine(email)}
                        disabled={email.quarantined}
                        className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-rose-500/20 to-red-600/20 hover:from-rose-500/30 hover:to-red-600/30 text-rose-300 border border-rose-500/40 text-[11px] font-mono font-bold transition-all disabled:opacity-50 flex items-center space-x-1"
                      >
                        <Ban className="w-3 h-3 text-rose-400" />
                        <span>{email.quarantined ? 'Quarantined' : 'SOAR Quarantine'}</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Gmail OAuth Setup Modal */}
      <GmailOAuthModal
        isOpen={showConfigModal}
        onClose={() => setShowConfigModal(false)}
        currentClientId={clientId}
        targetEmail={emailInputHint}
        onSaveClientId={handleSaveClientId}
        onSaveManualToken={handleSaveManualToken}
        onLaunchSandbox={handleLaunchSandbox}
        onInstantAuthorize={handleInstantAuthorize}
      />

      {/* Deep Email Forensic Inspector Modal */}
      <EmailForensicModal
        email={selectedForensicEmail}
        isOpen={selectedForensicEmail !== null}
        onClose={() => setSelectedForensicEmail(null)}
        onIngestToSoc={handleIngestToSoc}
        onQuarantine={handleQuarantine}
      />
    </div>
  );
};
