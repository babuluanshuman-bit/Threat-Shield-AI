import React, { useState } from 'react';
import { analyzeAccountTakeover, AnalysisResult } from '../services/threatEngine';
import { useCyberGuard } from '../context/CyberGuardContext';
import { RiskGauge } from '../components/common/RiskGauge';
import { ExplainableEvidencePanel } from '../components/common/ExplainableEvidencePanel';
import { ResponsePanel } from '../components/common/ResponsePanel';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import { Threat } from '../types/cyberguard';
import {
  UserX,
  KeyRound,
  ShieldAlert,
  AlertTriangle,
  RotateCcw,
  Zap,
  Lock,
  Smartphone,
  Globe,
  GitBranch,
  ArrowDown,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  AlertOctagon,
  Bell,
  Cpu,
  Layers,
  Terminal,
  ExternalLink,
  Shield,
  Activity,
  UserCheck
} from 'lucide-react';

export const AccountTakeoverPage: React.FC = () => {
  const { ingestNewThreat } = useCyberGuard();

  const [user, setUser] = useState('priya.sharma@cyberguard.internal');
  const [phishingUrlDetected, setPhishingUrlDetected] = useState(true);
  const [credentialSubmitted, setCredentialSubmitted] = useState(true);
  const [failedLogins, setFailedLogins] = useState(5);
  const [newDevice, setNewDevice] = useState(true);
  const [newCountry, setNewCountry] = useState(true);
  const [passwordChanged, setPasswordChanged] = useState(true);
  const [mfaAltered, setMfaAltered] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [activeDiagramView, setActiveDiagramView] = useState<'visual' | 'ascii'>('visual');

  const [result, setResult] = useState<AnalysisResult | null>(() =>
    analyzeAccountTakeover({
      user: 'priya.sharma@cyberguard.internal',
      phishingUrlDetected: true,
      credentialSubmitted: true,
      phishingUrl: 'https://fake-bank-login.com',
      failedLogins: 5,
      newDevice: true,
      newCountry: true,
      passwordChanged: true,
      mfaAltered: true,
    })
  );

  const handleScan = (overrideParams?: Partial<{
    user: string;
    phishingUrlDetected: boolean;
    credentialSubmitted: boolean;
    failedLogins: number;
    newDevice: boolean;
    newCountry: boolean;
    passwordChanged: boolean;
    mfaAltered: boolean;
  }>) => {
    setIsScanning(true);

    const targetUser = overrideParams?.user ?? user;
    const targetPhishing = overrideParams?.phishingUrlDetected ?? phishingUrlDetected;
    const targetCreds = overrideParams?.credentialSubmitted ?? credentialSubmitted;
    const targetFailed = overrideParams?.failedLogins ?? failedLogins;
    const targetDevice = overrideParams?.newDevice ?? newDevice;
    const targetCountry = overrideParams?.newCountry ?? newCountry;
    const targetPass = overrideParams?.passwordChanged ?? passwordChanged;
    const targetMfa = overrideParams?.mfaAltered ?? mfaAltered;

    setTimeout(() => {
      const res = analyzeAccountTakeover({
        user: targetUser,
        phishingUrlDetected: targetPhishing,
        credentialSubmitted: targetCreds,
        phishingUrl: 'https://fake-bank-login.com',
        failedLogins: targetFailed,
        newDevice: targetDevice,
        newCountry: targetCountry,
        passwordChanged: targetPass,
        mfaAltered: targetMfa,
      });
      setResult(res);
      setIsScanning(false);

      if (res.riskScore >= 60) {
        const newThreat: Threat = {
          id: `THR-ATO-${Date.now()}`,
          timestamp: 'Just now',
          source: 'Authentication',
          target: targetUser,
          category: 'Account Takeover',
          riskScore: res.riskScore,
          severity: res.severity,
          title: res.suggestedIncidentTitle,
          summary: res.explanation.slice(0, 100) + '...',
          status: 'DETECTED',
          indicators: res.indicators,
          explanation: res.explanation,
          recommendations: res.recommendations,
          metadata: res.metadata,
        };
        ingestNewThreat(newThreat);
      }
    }, 400);
  };

  const simulateFullPhishingAtoChain = () => {
    setPhishingUrlDetected(true);
    setCredentialSubmitted(true);
    setFailedLogins(5);
    setNewDevice(true);
    setNewCountry(true);
    setPasswordChanged(true);
    setMfaAltered(true);

    handleScan({
      phishingUrlDetected: true,
      credentialSubmitted: true,
      failedLogins: 5,
      newDevice: true,
      newCountry: true,
      passwordChanged: true,
      mfaAltered: true,
    });
  };

  const resetAllSignals = () => {
    setPhishingUrlDetected(false);
    setCredentialSubmitted(false);
    setFailedLogins(0);
    setNewDevice(false);
    setNewCountry(false);
    setPasswordChanged(false);
    setMfaAltered(false);

    handleScan({
      phishingUrlDetected: false,
      credentialSubmitted: false,
      failedLogins: 0,
      newDevice: false,
      newCountry: false,
      passwordChanged: false,
      mfaAltered: false,
    });
  };

  const currentThreat: Threat | null = result
    ? {
        id: `THR-ATO-${Date.now()}`,
        timestamp: 'Just now',
        source: 'Authentication',
        target: user,
        category: 'Account Takeover',
        riskScore: result.riskScore,
        severity: result.severity,
        title: result.suggestedIncidentTitle,
        summary: result.explanation,
        status: 'DETECTED',
        indicators: result.indicators,
        explanation: result.explanation,
        recommendations: result.recommendations,
        metadata: result.metadata,
      }
    : null;

  return (
    <div className="space-y-8 pb-16 animate-fade-in max-w-6xl mx-auto">
      {/* 1. Header Banner */}
      <div className="p-6 rounded-2xl bg-[#0B1120] border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-rose-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div className="flex items-start space-x-4">
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 shrink-0">
              <UserX className="w-6 h-6" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-mono font-bold text-white tracking-wide">
                  ACCOUNT TAKEOVER (ATO) CORRELATED RISK ENGINE
                </h1>
                <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  MULTI-SIGNAL IDENTITY CORRELATION
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-300 font-sans mt-1.5 leading-relaxed max-w-3xl">
                Cross-layer threat correlation: fuzes initial phishing detonation telemetry with downstream identity signals, brute-force anomalies, and persistence tampering into a unified 0–100 composite risk score.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={simulateFullPhishingAtoChain}
              className="px-4 py-2.5 rounded-xl bg-rose-500 hover:bg-rose-400 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(244,63,94,0.4)] transition-all flex items-center space-x-2"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>Simulate Phishing → ATO (100%)</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Visual Architecture & Flow Topology */}
      <div className="p-6 rounded-2xl bg-[#080E1C] border border-cyan-500/30 shadow-[0_0_30px_rgba(0,240,255,0.07)] relative">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 mb-6 border-b border-slate-800">
          <div>
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-cyan-400 block">
              Autonomous Correlation Pipeline
            </span>
            <h2 className="text-lg font-mono font-bold text-white mt-0.5">
              CYBERGUARD Correlation Topology
            </h2>
          </div>

          <div className="inline-flex rounded-xl bg-slate-950 p-1 border border-slate-800 font-mono text-xs">
            <button
              onClick={() => setActiveDiagramView('visual')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeDiagramView === 'visual'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Visual Flow
            </button>
            <button
              onClick={() => setActiveDiagramView('ascii')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeDiagramView === 'ascii'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              ASCII Architecture
            </button>
          </div>
        </div>

        {activeDiagramView === 'visual' ? (
          <div className="space-y-6">
            {/* Top Node: CYBERGUARD Central Orchestrator */}
            <div className="flex flex-col items-center">
              <div className="px-6 py-3 rounded-2xl bg-gradient-to-r from-cyan-950/80 via-blue-900/60 to-purple-950/80 border-2 border-cyan-400/50 text-center shadow-[0_0_25px_rgba(0,240,255,0.25)]">
                <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 block font-bold">
                  Central SOC Orchestrator
                </span>
                <span className="text-base sm:text-lg font-mono font-extrabold text-white tracking-wider">
                  THREAT LENS AI / CYBERGUARD
                </span>
              </div>

              {/* Stem down & branch */}
              <div className="w-0.5 h-6 bg-cyan-400/60 my-1" />
              <div className="w-full max-w-2xl h-0.5 bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent" />
            </div>

            {/* Split Branches: Left (URL / Phishing) and Right (Account Activity) */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
              {/* Branch 1 */}
              <div className="p-5 rounded-2xl bg-slate-900/90 border border-cyan-500/30 flex flex-col justify-between group hover:border-cyan-400 transition-all shadow-md">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                      Branch 01 • Attack Surface
                    </span>
                    <Globe className="w-4 h-4 text-cyan-400" />
                  </div>
                  <h3 className="font-mono text-base font-bold text-white mb-2">
                    URL / Phishing Detection
                  </h3>
                  <p className="text-xs text-slate-300 font-sans leading-relaxed">
                    Detonates hostile links, sandbox heuristics, brand homoglyphs, and form-level credential harvesting signatures.
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono">
                  <span className="text-slate-400">Signal Origin:</span>
                  <span className="text-cyan-300 font-bold">Web Detonation Sandbox</span>
                </div>
              </div>

              {/* Branch 2 */}
              <div className="p-5 rounded-2xl bg-slate-900/90 border border-purple-500/30 flex flex-col justify-between group hover:border-purple-400 transition-all shadow-md">
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-[11px] font-mono font-bold text-purple-400 uppercase tracking-wider">
                      Branch 02 • Identity Telemetry
                    </span>
                    <UserCheck className="w-4 h-4 text-purple-400" />
                  </div>
                  <h3 className="font-mono text-base font-bold text-white mb-2">
                    Account Activity & Identity Signals
                  </h3>
                  <p className="text-xs text-slate-300 font-sans leading-relaxed">
                    Monitors IdP login streams, session tokens, new device UUIDs, foreign IPs, and high-privilege credential alterations.
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono">
                  <span className="text-slate-400">Sub-Engine:</span>
                  <span className="text-purple-300 font-bold">ATO Risk Engine</span>
                </div>
              </div>
            </div>

            {/* Convergence lines */}
            <div className="flex flex-col items-center">
              <div className="w-full max-w-2xl h-0.5 bg-gradient-to-r from-transparent via-rose-500/60 to-transparent" />
              <div className="w-0.5 h-6 bg-rose-500/60 my-1" />

              {/* Correlation Engine Node */}
              <div className="px-6 py-3.5 rounded-2xl bg-slate-950 border-2 border-rose-500/50 text-center max-w-md w-full shadow-[0_0_20px_rgba(244,63,94,0.2)]">
                <div className="flex items-center justify-center space-x-2 text-rose-400 mb-1">
                  <GitBranch className="w-4 h-4" />
                  <span className="text-xs font-mono font-bold uppercase tracking-wider">Cross-Domain Fusion</span>
                </div>
                <span className="text-base font-mono font-extrabold text-white">
                  Correlation Engine
                </span>
                <p className="text-[11px] text-slate-400 mt-1">
                  Correlates external phishing lure interaction with immediate downstream authentication anomalies.
                </p>
              </div>

              <div className="w-0.5 h-5 bg-rose-500/60 my-1" />

              {/* Overall Threat Score */}
              <div className="px-6 py-2.5 rounded-xl bg-rose-950/50 border border-rose-500/40 text-center max-w-xs w-full shadow">
                <span className="text-[10px] font-mono text-rose-300 uppercase tracking-widest block font-bold">
                  Unified Calculus Output
                </span>
                <span className="text-sm font-mono font-bold text-white">
                  Overall Threat Score (0–100)
                </span>
              </div>

              <div className="w-0.5 h-5 bg-rose-500/60 my-1" />

              {/* Automated Response */}
              <div className="px-6 py-3 rounded-2xl bg-gradient-to-r from-rose-600 to-red-600 text-slate-950 font-mono font-extrabold text-sm uppercase tracking-wider shadow-[0_0_25px_rgba(239,68,68,0.4)] flex items-center space-x-2">
                <Zap className="w-4 h-4 fill-current" />
                <span>Automated SOAR Playbook Response</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-5 rounded-2xl bg-slate-950 border border-slate-800 font-mono text-xs sm:text-sm text-cyan-300 overflow-x-auto leading-relaxed shadow-inner">
            <pre className="select-all">
{`                  CYBERGUARD / THREAT LENS AI
                               │
                    ┌──────────┴──────────┐
                    ↓                     ↓
              URL / Phishing          Account Activity
              Detection               / Identity Signals
                    │                     │
                    │               ATO Risk Engine
                    │                     │
                    └──────────┬──────────┘
                               ↓
                        Correlation Engine
                               ↓
                     Overall Threat Score
                               ↓
                    Automated SOAR Response`}
            </pre>
          </div>
        )}
      </div>

      {/* 3. Deep-Dive Section: How ATO works with a phishing URL */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6">
        <div>
          <span className="text-xs font-mono font-bold uppercase tracking-widest text-rose-400">
            Real-World Incident Scenario
          </span>
          <h2 className="text-xl font-mono font-bold text-white mt-1">
            How ATO Works with a Phishing URL
          </h2>
          <p className="text-xs sm:text-sm text-slate-300 font-sans mt-1">
            Imagine an attacker sends a high-fidelity credential harvesting lure to an employee inbox.
          </p>
        </div>

        {/* Attack Lure Card */}
        <div className="p-5 rounded-2xl bg-slate-950 border border-slate-800 grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
          <div className="md:col-span-8 space-y-2">
            <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
              <span>Attacker Inbound Vector:</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-750 font-mono text-xs sm:text-sm text-rose-300 flex items-center justify-between">
              <span className="truncate">https://fake-bank-login.com</span>
              <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 ml-2 shrink-0">
                Lure Payload
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans">
              Your phishing engine immediately evaluates the link and detects:
            </p>
          </div>

          <div className="md:col-span-4 p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-center flex flex-col items-center justify-center">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">
              Phishing Engine Detection
            </span>
            <span className="text-2xl font-mono font-extrabold text-rose-400 my-1">
              URL Risk = 95/100
            </span>
            <span className="text-xs font-mono font-bold text-rose-300 uppercase">
              ⚠ Malicious Credential Form
            </span>
          </div>
        </div>

        {/* Narrative Callout */}
        <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs sm:text-sm text-slate-200 font-sans leading-relaxed flex items-start space-x-3">
          <Cpu className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <strong className="text-cyan-300 font-mono block mb-1">
              But CYBERGUARD goes much further than static detection:
            </strong>
            If the user clicks the link and subsequently enters credentials, CYBERGUARD's correlation engine traces the identity lifecycle across all downstream access points:
          </div>
        </div>

        {/* Multi-Signal Correlation Matrix Table */}
        <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-950">
          <div className="p-4 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              Correlation Signal Matrix & Risk Impact
            </span>
            <span className="text-xs font-mono text-rose-400 font-bold">
              Composite Risk = 100/100 CRITICAL
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-900/50 text-slate-400 border-b border-slate-800 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="p-3.5">Signal Vector</th>
                  <th className="p-3.5">Telemetry Observed</th>
                  <th className="p-3.5 text-right">Risk Score Impact</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 text-slate-300">
                <tr className="hover:bg-slate-900/40">
                  <td className="p-3.5 font-bold text-white flex items-center space-x-2">
                    <Globe className="w-3.5 h-3.5 text-rose-400" />
                    <span>Phishing URL detected</span>
                  </td>
                  <td className="p-3.5 text-slate-400 font-sans">
                    User navigated to <code className="text-rose-300">https://fake-bank-login.com</code>
                  </td>
                  <td className="p-3.5 text-right font-bold text-rose-400">90</td>
                </tr>

                <tr className="hover:bg-slate-900/40">
                  <td className="p-3.5 font-bold text-white flex items-center space-x-2">
                    <KeyRound className="w-3.5 h-3.5 text-amber-400" />
                    <span>Credential submission</span>
                  </td>
                  <td className="p-3.5 text-slate-400 font-sans">
                    POST request dispatched with hashed username & password fields
                  </td>
                  <td className="p-3.5 text-right font-bold text-amber-400">+</td>
                </tr>

                <tr className="hover:bg-slate-900/40">
                  <td className="p-3.5 font-bold text-white flex items-center space-x-2">
                    <Smartphone className="w-3.5 h-3.5 text-orange-400" />
                    <span>New device</span>
                  </td>
                  <td className="p-3.5 text-slate-400 font-sans">
                    Unregistered hardware UUID and browser fingerprint
                  </td>
                  <td className="p-3.5 text-right font-bold text-orange-400">+</td>
                </tr>

                <tr className="hover:bg-slate-900/40">
                  <td className="p-3.5 font-bold text-white flex items-center space-x-2">
                    <Globe className="w-3.5 h-3.5 text-purple-400" />
                    <span>Foreign IP</span>
                  </td>
                  <td className="p-3.5 text-slate-400 font-sans">
                    Authentication routed from commercial VPN egress in Berlin
                  </td>
                  <td className="p-3.5 text-right font-bold text-purple-400">+</td>
                </tr>

                <tr className="hover:bg-slate-900/40">
                  <td className="p-3.5 font-bold text-white flex items-center space-x-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                    <span>Multiple failed logins</span>
                  </td>
                  <td className="p-3.5 text-slate-400 font-sans">
                    5 consecutive credential validation rejections in 3m window
                  </td>
                  <td className="p-3.5 text-right font-bold text-rose-400">+</td>
                </tr>

                <tr className="hover:bg-slate-900/40">
                  <td className="p-3.5 font-bold text-white flex items-center space-x-2">
                    <Lock className="w-3.5 h-3.5 text-rose-400" />
                    <span>Password changed</span>
                  </td>
                  <td className="p-3.5 text-slate-400 font-sans">
                    Root password updated immediately following unauthorized session initiation
                  </td>
                  <td className="p-3.5 text-right font-bold text-rose-400">+</td>
                </tr>

                <tr className="hover:bg-slate-900/40">
                  <td className="p-3.5 font-bold text-white flex items-center space-x-2">
                    <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                    <span>MFA changed</span>
                  </td>
                  <td className="p-3.5 text-slate-400 font-sans">
                    Secondary recovery SMS number and authenticator app replaced
                  </td>
                  <td className="p-3.5 text-right font-bold text-red-400">+</td>
                </tr>

                <tr className="bg-rose-950/30 font-bold border-t-2 border-rose-500/40">
                  <td colSpan={2} className="p-4 text-white text-sm">
                    ATO COMPOSITE RISK CALCULATION
                  </td>
                  <td className="p-4 text-right text-rose-400 text-sm font-extrabold">
                    → 100/100 CRITICAL
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* 🚨 Then CYBERGUARD Responds: Step-by-Step Chain */}
        <div className="p-6 rounded-2xl bg-gradient-to-b from-slate-950 to-[#070C18] border border-rose-500/40 shadow-2xl space-y-6">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/30">
              <AlertOctagon className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <span className="text-[10px] font-mono font-bold text-rose-400 uppercase tracking-widest block">
                Autonomous SOAR Execution
              </span>
              <h3 className="text-base sm:text-lg font-mono font-bold text-white">
                🚨 Then CYBERGUARD Responds
              </h3>
            </div>
          </div>

          {/* Sequential Step Timeline */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
            {[
              { step: '01', title: 'Phishing URL', desc: 'Weaponized domain sent in lure email' },
              { step: '02', title: 'User Clicks', desc: 'Victim navigates to spoofed login portal' },
              { step: '03', title: 'Credentials Compromised', desc: 'Username & password harvested' },
              { step: '04', title: 'ATO Monitoring Activated', desc: 'Real-time identity surveillance triggered' },
              { step: '05', title: 'Suspicious Login Detected', desc: 'Foreign IP & new device attempts access' },
              { step: '06', title: 'ATO Risk = 100/100', desc: 'Threshold triggers immediate SOAR lockdown' },
            ].map((node, i) => (
              <div
                key={i}
                className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between group hover:border-rose-500/50 transition-all shadow-sm"
              >
                <div>
                  <span className="text-[10px] font-mono font-bold text-rose-400 mb-1 block">
                    STEP {node.step}
                  </span>
                  <span className="text-xs font-mono font-bold text-white group-hover:text-rose-300 transition-colors">
                    {node.title}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans mt-2 leading-tight">
                  {node.desc}
                </p>
              </div>
            ))}
          </div>

          {/* Automated Remediation Action Box */}
          <div className="p-5 rounded-2xl bg-rose-950/20 border border-rose-500/30">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-300 block mb-3">
              Automated Containment Actions Dispatched:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-slate-950/90 border border-rose-500/20 flex items-center space-x-2.5 text-slate-200">
                <Lock className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Revoke active sessions</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/90 border border-rose-500/20 flex items-center space-x-2.5 text-slate-200">
                <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Block suspicious login</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/90 border border-rose-500/20 flex items-center space-x-2.5 text-slate-200">
                <Smartphone className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Force MFA verification</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/90 border border-rose-500/20 flex items-center space-x-2.5 text-slate-200">
                <Bell className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Alert user</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/90 border border-rose-500/20 flex items-center space-x-2.5 text-slate-200">
                <ShieldCheck className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Alert administrator</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Interactive Signal Correlation Sandbox */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-850">
          <div>
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-cyan-400 block">
              Simulation Sandbox
            </span>
            <h3 className="text-base font-mono font-bold text-white">
              Correlated Signals Checklist for Target Account
            </h3>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={resetAllSignals}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs transition-colors"
            >
              Reset
            </button>
            <span className="text-xs font-mono text-cyan-400 font-semibold px-2 py-1 rounded bg-slate-950 border border-slate-800">
              {user}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
          {/* Signal 1: Phishing URL */}
          <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-center justify-between cursor-pointer hover:border-slate-700 transition-colors">
            <div>
              <span className="text-slate-200 font-bold block">Phishing URL Detected</span>
              <span className="text-[10px] text-slate-500">Lure clicked (Risk 95/100)</span>
            </div>
            <input
              type="checkbox"
              checked={phishingUrlDetected}
              onChange={(e) => setPhishingUrlDetected(e.target.checked)}
              className="w-4 h-4 accent-rose-500 rounded"
            />
          </label>

          {/* Signal 2: Credential Submission */}
          <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-center justify-between cursor-pointer hover:border-slate-700 transition-colors">
            <div>
              <span className="text-slate-200 font-bold block">Credential Submission</span>
              <span className="text-[10px] text-slate-500">Form POST payload intercepted</span>
            </div>
            <input
              type="checkbox"
              checked={credentialSubmitted}
              onChange={(e) => setCredentialSubmitted(e.target.checked)}
              className="w-4 h-4 accent-rose-500 rounded"
            />
          </label>

          {/* Signal 3: Failed Logins */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-center justify-between">
            <div>
              <span className="text-slate-200 font-bold block">Failed Logins</span>
              <span className="text-[10px] text-slate-500">Consecutive failures in 3m</span>
            </div>
            <select
              value={failedLogins}
              onChange={(e) => setFailedLogins(Number(e.target.value))}
              className="bg-slate-900 border border-slate-750 text-white rounded px-2 py-1 text-xs"
            >
              <option value="0">0 attempts</option>
              <option value="2">2 attempts</option>
              <option value="5">5 attempts (Spike)</option>
              <option value="12">12 attempts (Brute)</option>
            </select>
          </div>

          {/* Signal 4: New Device Hardware */}
          <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-center justify-between cursor-pointer hover:border-slate-700 transition-colors">
            <div>
              <span className="text-slate-200 font-bold block">New Device Hardware</span>
              <span className="text-[10px] text-slate-500">Unrecognized hardware UUID</span>
            </div>
            <input
              type="checkbox"
              checked={newDevice}
              onChange={(e) => setNewDevice(e.target.checked)}
              className="w-4 h-4 accent-cyan-500 rounded"
            />
          </label>

          {/* Signal 5: New Country Geolocation */}
          <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-center justify-between cursor-pointer hover:border-slate-700 transition-colors">
            <div>
              <span className="text-slate-200 font-bold block">Foreign IP Geolocation</span>
              <span className="text-[10px] text-slate-500">Foreign IP jurisdiction (Berlin)</span>
            </div>
            <input
              type="checkbox"
              checked={newCountry}
              onChange={(e) => setNewCountry(e.target.checked)}
              className="w-4 h-4 accent-cyan-500 rounded"
            />
          </label>

          {/* Signal 6: Root Password Mutated */}
          <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-center justify-between cursor-pointer hover:border-slate-700 transition-colors">
            <div>
              <span className="text-slate-200 font-bold block">Root Password Mutated</span>
              <span className="text-[10px] text-slate-500">Updated post-auth</span>
            </div>
            <input
              type="checkbox"
              checked={passwordChanged}
              onChange={(e) => setPasswordChanged(e.target.checked)}
              className="w-4 h-4 accent-rose-500 rounded"
            />
          </label>

          {/* Signal 7: MFA Device Altered */}
          <label className="p-3.5 rounded-xl bg-slate-950 border border-slate-850 flex items-center justify-between cursor-pointer hover:border-slate-700 transition-colors">
            <div>
              <span className="text-slate-200 font-bold block">MFA Device Altered</span>
              <span className="text-[10px] text-slate-500">Recovery telephone replaced</span>
            </div>
            <input
              type="checkbox"
              checked={mfaAltered}
              onChange={(e) => setMfaAltered(e.target.checked)}
              className="w-4 h-4 accent-rose-500 rounded"
            />
          </label>

          {/* Compute Button */}
          <div className="sm:col-span-2 lg:col-span-2 flex items-center">
            <button
              onClick={() => handleScan()}
              disabled={isScanning}
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-400 hover:to-red-500 text-white font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(239,68,68,0.35)] transition-all flex items-center justify-center space-x-2"
            >
              {isScanning ? (
                <span>Correlating Cross-Domain Telemetry...</span>
              ) : (
                <span>Compute ATO Composite Risk Score</span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* 5. Results View */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            <div className="md:col-span-4 p-6 rounded-2xl bg-[#070C18] border border-slate-800 flex flex-col items-center justify-center text-center shadow-cyber-card">
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 mb-2">
                Account Takeover Risk
              </span>
              <RiskGauge score={result.riskScore} size="lg" />
              <div className="mt-4 flex items-center space-x-2">
                <ThreatBadge category="Account Takeover" />
                <SeverityBadge level={result.severity} />
              </div>
            </div>

            <div className="md:col-span-8 p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between">
              <div>
                <div className="pb-3 border-b border-slate-800 flex items-center justify-between mb-4">
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                    ATO Composite Correlation Formula
                  </h3>
                  <span className="text-xs font-mono text-rose-400 font-bold">
                    Risk Engine: {result.riskScore}/100 {result.riskScore >= 80 ? 'CRITICAL' : result.severity}
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 font-mono text-xs text-slate-300 space-y-2 leading-relaxed">
                  <p className="text-rose-400 font-bold">
                    {phishingUrlDetected && '[Phishing URL (90)] + '}
                    {credentialSubmitted && '[Credential Submission] + '}
                    {failedLogins >= 3 && `[${failedLogins} Failed Logins] + `}
                    {newDevice && '[New Device] + '}
                    {newCountry && '[Foreign IP] + '}
                    {passwordChanged && '[Password Mutated] + '}
                    {mfaAltered && '[MFA Replaced]'}
                  </p>
                  <p className="text-[11px] text-slate-400 font-sans">
                    Multi-signal correlation matches hostile credential harvesting followed by automated session hijacking, foreign proxy traversal, and adversary lockout persistence.
                  </p>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">
                  Target Identity: <strong className="text-cyan-300">{result.target}</strong>
                </span>
                <span className="text-slate-400">
                  Phishing Link: <strong className="text-rose-400">{phishingUrlDetected ? 'https://fake-bank-login.com' : 'None'}</strong>
                </span>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card">
            <ExplainableEvidencePanel
              indicators={result.indicators}
              explanation={result.explanation}
              recommendations={result.recommendations}
              riskScore={result.riskScore}
              severity={result.severity}
              target={result.target}
            />
          </div>

          {currentThreat && <ResponsePanel threat={currentThreat} />}
        </div>
      )}
    </div>
  );
};
