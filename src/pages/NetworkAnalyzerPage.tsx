import React, { useState, useMemo } from 'react';
import { analyzeNetwork, AnalysisResult } from '../services/threatEngine';
import {
  inspectIpAddressLocally,
  queryAbuseIpDb,
  IpIntelligence,
  DEFAULT_ABUSEIPDB_KEY
} from '../services/networkApiService';
import { useCyberGuard } from '../context/CyberGuardContext';
import { RiskGauge } from '../components/common/RiskGauge';
import { ExplainableEvidencePanel } from '../components/common/ExplainableEvidencePanel';
import { ResponsePanel } from '../components/common/ResponsePanel';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import { Threat } from '../types/cyberguard';
import {
  Network,
  Activity,
  Zap,
  Server,
  AlertTriangle,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ArrowRight,
  Filter,
  Key,
  ExternalLink,
  Check,
  X,
  Globe,
  Radio
} from 'lucide-react';

export const NetworkAnalyzerPage: React.FC = () => {
  const { ingestNewThreat } = useCyberGuard();

  // Network Flow State
  const [srcIp, setSrcIp] = useState('192.168.1.42');
  const [destIp, setDestIp] = useState('185.220.101.5');
  const [connectionsPerMin, setConnectionsPerMin] = useState(1284);
  const [normalBaseline, setNormalBaseline] = useState(40);
  const [port, setPort] = useState(8443);
  const [protocol, setProtocol] = useState('HTTPS');
  const [isScanning, setIsScanning] = useState(false);

  // Free API Integration State (AbuseIPDB - Preconfigured with user key)
  const [showApiModal, setShowApiModal] = useState(false);
  const [abuseIpDbKey, setAbuseIpDbKey] = useState(() => localStorage.getItem('CYBERGUARD_ABUSEIPDB_KEY') || DEFAULT_ABUSEIPDB_KEY);
  const [isApiActive, setIsApiActive] = useState(() => localStorage.getItem('CYBERGUARD_ABUSEIPDB_ACTIVE') !== 'false');

  // Live Destination IP Intelligence Inspection
  const liveDestIntel = useMemo(() => inspectIpAddressLocally(destIp), [destIp]);

  // Initial Analysis Result
  const [result, setResult] = useState<AnalysisResult | null>(() =>
    analyzeNetwork({
      srcIp: '192.168.1.42',
      destIp: '185.220.101.5',
      connectionsPerMin: 1284,
      normalBaseline: 40,
      port: 8443,
      protocol: 'HTTPS',
    })
  );

  const presets = [
    { label: 'C2 Beaconing Spike (APT-37 - Critical)', src: '192.168.1.42', dest: '185.220.101.5', conns: 1284, base: 40, port: 8443, proto: 'HTTPS' },
    { label: 'Outbound SSH Port Scan (Mirai - High)', src: '192.168.1.88', dest: '194.26.29.112', conns: 410, base: 5, port: 22, proto: 'TCP' },
    { label: 'Google Cloud Sync (Legitimate - Safe)', src: '192.168.1.105', dest: '142.250.190.46', conns: 34, base: 40, port: 443, proto: 'HTTPS' },
    { label: 'Cloudflare Secure DNS (Legitimate - Safe)', src: '192.168.1.50', dest: '1.1.1.1', conns: 42, base: 40, port: 53, proto: 'DNS' },
  ];

  const handleScan = async () => {
    setIsScanning(true);

    let externalScore: { abuseScore: number; source: string; details?: string } | undefined = undefined;

    // Optional: Live AbuseIPDB API Query if user provided an API key
    if (isApiActive && abuseIpDbKey.trim()) {
      try {
        const liveIntel = await queryAbuseIpDb(destIp, abuseIpDbKey);
        externalScore = {
          abuseScore: liveIntel.abuseConfidenceScore,
          source: liveIntel.source,
          details: liveIntel.threatDetails,
        };
      } catch (err) {
        console.warn('AbuseIPDB query failed, using built-in IP intelligence:', err);
      }
    }

    setTimeout(() => {
      const res = analyzeNetwork({
        srcIp,
        destIp,
        connectionsPerMin,
        normalBaseline,
        port,
        protocol,
        ipIntel: externalScore
          ? {
              isMalicious: externalScore.abuseScore > 40,
              isSafe: externalScore.abuseScore <= 10,
              entityName: liveDestIntel.entityName,
              actorOrOrg: liveDestIntel.actorOrOrg,
              threatDetails: externalScore.details || liveDestIntel.threatDetails,
              abuseConfidenceScore: externalScore.abuseScore,
              source: externalScore.source,
            }
          : undefined,
      });

      setResult(res);
      setIsScanning(false);

      if (res.riskScore >= 60) {
        const newThreat: Threat = {
          id: `THR-NET-${Date.now()}`,
          timestamp: 'Just now',
          source: 'Network',
          target: `${srcIp} → ${destIp}`,
          category: 'Network Anomaly',
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
    }, 500);
  };

  const anomalyMultiplier = Math.round((connectionsPerMin / Math.max(1, normalBaseline)) * 10) / 10;
  const isVelocitySpike = anomalyMultiplier > 2.5;

  const currentThreat: Threat | null = result
    ? {
        id: `THR-NET-${Date.now()}`,
        timestamp: 'Just now',
        source: 'Network',
        target: `${srcIp} → ${destIp}`,
        category: 'Network Anomaly',
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
    <div className="space-y-6 pb-12 animate-fade-in max-w-6xl mx-auto">
      {/* Header */}
      <div className="p-4 rounded-2xl bg-[#0B1120] border border-slate-800">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-mono font-bold text-white tracking-wide">
                  NETWORK TRAFFIC & COMMAND-AND-CONTROL (C2) ANALYZER
                </h1>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Evaluates destination IP reputation against enterprise cloud subnets and adversary C2 threat feeds, analyzing NetFlow velocity bursts and port tunneling.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Preset Configurator Card */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center gap-2 pb-2 border-b border-slate-850">
          <span className="text-[11px] font-mono text-slate-500">Preset Scenarios:</span>
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setSrcIp(p.src);
                setDestIp(p.dest);
                setConnectionsPerMin(p.conns);
                setNormalBaseline(p.base);
                setPort(p.port);
                setProtocol(p.proto);
              }}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors border ${
                destIp === p.dest
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                  : 'bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-cyan-300 border-slate-700'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Input Parameters Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
          <div>
            <label className="text-[10px] uppercase text-slate-400 block mb-1">Source Host IP</label>
            <input
              type="text"
              value={srcIp}
              onChange={(e) => setSrcIp(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[10px] uppercase text-slate-400 block">Destination IP (C2 Target)</label>
              {liveDestIntel.isSafe ? (
                <span className="text-[9px] font-bold text-emerald-400 flex items-center space-x-0.5">
                  <ShieldCheck className="w-2.5 h-2.5" />
                  <span>Verified Safe</span>
                </span>
              ) : liveDestIntel.isMalicious ? (
                <span className="text-[9px] font-bold text-rose-400 flex items-center space-x-0.5">
                  <AlertTriangle className="w-2.5 h-2.5" />
                  <span>Known C2</span>
                </span>
              ) : (
                <span className="text-[9px] font-bold text-slate-400">Public IP</span>
              )}
            </div>
            <input
              type="text"
              value={destIp}
              onChange={(e) => setDestIp(e.target.value)}
              className={`w-full px-3 py-2 rounded-lg bg-slate-950 border font-bold focus:outline-none ${
                liveDestIntel.isSafe
                  ? 'border-emerald-500/40 text-emerald-300 focus:border-emerald-400'
                  : liveDestIntel.isMalicious
                  ? 'border-rose-500/50 text-rose-300 focus:border-rose-400'
                  : 'border-slate-800 text-white focus:border-cyan-400'
              }`}
            />
            {/* Real-time IP Entity Tag */}
            <span className="text-[10px] text-slate-400 block mt-1 truncate" title={liveDestIntel.entityName}>
              Entity: <strong className={liveDestIntel.isSafe ? 'text-emerald-400' : liveDestIntel.isMalicious ? 'text-rose-400' : 'text-cyan-300'}>
                {liveDestIntel.entityName}
              </strong>
            </span>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[10px] uppercase text-slate-400 block">Connections / Min</label>
              <span className={`text-[10px] font-bold ${isVelocitySpike ? 'text-rose-400' : 'text-emerald-400'}`}>
                {anomalyMultiplier}x baseline
              </span>
            </div>
            <input
              type="number"
              value={connectionsPerMin}
              onChange={(e) => setConnectionsPerMin(Number(e.target.value))}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-cyan-300 font-bold focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div>
            <label className="text-[10px] uppercase text-slate-400 block mb-1">Baseline Normal (Conns/Min)</label>
            <input
              type="number"
              value={normalBaseline}
              onChange={(e) => setNormalBaseline(Number(e.target.value))}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-400"
            />
          </div>
        </div>

        {/* Secondary Row: Port & Protocol */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs pt-1">
          <div>
            <label className="text-[10px] uppercase text-slate-400 block mb-1">Service Port</label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div>
            <label className="text-[10px] uppercase text-slate-400 block mb-1">Transport Protocol</label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-400"
            >
              <option value="HTTPS">HTTPS (Port 443 / TLS)</option>
              <option value="HTTP">HTTP (Port 80)</option>
              <option value="DNS">DNS (Port 53 / UDP)</option>
              <option value="SSH">SSH (Port 22)</option>
              <option value="TCP">Custom TCP Tunnel</option>
            </select>
          </div>

          <div className="sm:col-span-2 flex items-end justify-end">
            <button
              onClick={handleScan}
              disabled={isScanning}
              className="w-full sm:w-auto py-2.5 px-6 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(0,240,255,0.35)] transition-all flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              {isScanning ? (
                <>
                  <Radio className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Correlating NetFlow Packets...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  <span>Run Network Threat Audit</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Dynamic NetFlow Status Banner */}
      <div
        className={`p-5 rounded-2xl border flex flex-col sm:flex-row items-center justify-between gap-4 font-mono transition-all ${
          result && result.riskScore <= 30
            ? 'bg-emerald-950/20 border-emerald-500/40 shadow-[0_0_20px_rgba(16,185,129,0.1)]'
            : result && result.riskScore <= 60
            ? 'bg-amber-950/20 border-amber-500/40'
            : 'bg-rose-950/20 border-rose-500/40 shadow-[0_0_20px_rgba(244,63,94,0.15)]'
        }`}
      >
        <div className="flex items-center space-x-3">
          <div
            className={`p-2.5 rounded-xl border ${
              result && result.riskScore <= 30
                ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                : result && result.riskScore <= 60
                ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                : 'bg-rose-500/20 text-rose-400 border-rose-500/30 animate-pulse'
            }`}
          >
            {result && result.riskScore <= 30 ? (
              <ShieldCheck className="w-5 h-5" />
            ) : (
              <Activity className="w-5 h-5" />
            )}
          </div>
          <div>
            <span
              className={`text-xs font-bold uppercase tracking-wider block ${
                result && result.riskScore <= 30
                  ? 'text-emerald-400'
                  : result && result.riskScore <= 60
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {result && result.riskScore <= 30
                ? 'Verified Legitimate Enterprise Flow (Normal Traffic)'
                : result && result.riskScore <= 60
                ? 'Moderate Traffic Velocity Fluctuation'
                : 'Severe Network Connection Velocity Spike & C2 Alert'}
            </span>
            <span className="text-sm font-bold text-white">
              {srcIp} → {destIp} ({liveDestIntel.entityName} • Port {port}/{protocol})
            </span>
          </div>
        </div>

        <div className="text-right shrink-0">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Traffic Multiplier</span>
          <span
            className={`text-xl font-extrabold ${
              anomalyMultiplier <= 1.2
                ? 'text-emerald-400'
                : anomalyMultiplier <= 2.5
                ? 'text-amber-400'
                : 'text-rose-400'
            }`}
          >
            {anomalyMultiplier}x Baseline
          </span>
          <span className="text-[10px] text-slate-400 block">
            ({connectionsPerMin.toLocaleString()} conns/min vs {normalBaseline} baseline)
          </span>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            <div className="md:col-span-4 p-6 rounded-2xl bg-[#070C18] border border-slate-800 flex flex-col items-center justify-center text-center shadow-cyber-card">
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 mb-2">
                Network Risk Index
              </span>
              <RiskGauge score={result.riskScore} size="lg" />
              <div className="mt-4 flex items-center space-x-2">
                <ThreatBadge category="Network Anomaly" />
                <SeverityBadge level={result.severity} />
              </div>
              <span className="text-[11px] font-mono mt-3 block">
                {result.riskScore <= 30 ? (
                  <span className="text-emerald-400 font-bold">✓ Safe Enterprise Communication</span>
                ) : (
                  <span className="text-rose-400 font-bold">⚠ Command & Control Anomaly Flagged</span>
                )}
              </span>
            </div>

            <div className="md:col-span-8 p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between">
              <div>
                <div className="pb-3 border-b border-slate-800 flex items-center justify-between mb-4 flex-wrap gap-2">
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                    NetFlow Protocol & Reputation Forensics
                  </h3>
                  <span
                    className={`text-xs font-mono font-bold ${
                      result.riskScore <= 30
                        ? 'text-emerald-400'
                        : result.riskScore <= 60
                        ? 'text-amber-400'
                        : 'text-rose-400'
                    }`}
                  >
                    Risk Engine: {result.riskScore}/100 {result.severity}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Flow Rate</span>
                    <span
                      className={`font-bold mt-1 block ${
                        anomalyMultiplier > 2.5 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {connectionsPerMin.toLocaleString()} conns/min
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Historical Baseline</span>
                    <span className="text-slate-300 font-bold mt-1 block">{normalBaseline} conns/min</span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">IoC Classification</span>
                    <span
                      className={`font-bold mt-1 block truncate ${
                        liveDestIntel.isSafe
                          ? 'text-emerald-400'
                          : liveDestIntel.isMalicious
                          ? 'text-rose-400'
                          : 'text-cyan-300'
                      }`}
                    >
                      {liveDestIntel.entityName}
                    </span>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between text-xs font-mono flex-wrap gap-2">
                <span className="text-slate-400">
                  Target Flow: <strong className="text-cyan-300">{result.target}</strong>
                </span>
                <span className="text-slate-500">
                  Intel Source: <strong className="text-slate-300">{result.metadata?.reputationSource || 'NetFlow Engine'}</strong>
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
        </div>
      )}

      {/* Free AbuseIPDB API Setup Modal */}
      {showApiModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-sm animate-fade-in overflow-y-auto">
          <div className="w-full max-w-lg p-4 sm:p-6 rounded-2xl bg-[#0B1120] border border-slate-800 space-y-4 sm:space-y-5 shadow-2xl my-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Key className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-mono font-bold text-white">Free IP Threat Intelligence API</h3>
                  <p className="text-xs text-slate-400">Query real-time global IP abuse and C2 blacklists</p>
                </div>
              </div>
              <button onClick={() => setShowApiModal(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 font-mono">
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold text-cyan-300">AbuseIPDB API</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      1,000 FREE / DAY
                    </span>
                  </div>
                  <a
                    href="https://www.abuseipdb.com/pricing"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[11px] text-cyan-400 hover:underline flex items-center space-x-1"
                  >
                    <span>Get Free Key</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  AbuseIPDB checks destination IPs against 100+ million security analyst reports for brute force, botnets, and C2 activity. Free for personal/research use with zero credit card required.
                </p>
                <input
                  type="password"
                  placeholder="Paste your AbuseIPDB API Key..."
                  value={abuseIpDbKey}
                  onChange={(e) => setAbuseIpDbKey(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-100 focus:outline-none focus:border-cyan-400"
                />
                <button
                  onClick={() => {
                    localStorage.setItem('CYBERGUARD_ABUSEIPDB_KEY', abuseIpDbKey);
                    localStorage.setItem('CYBERGUARD_ABUSEIPDB_ACTIVE', 'true');
                    setIsApiActive(true);
                    setShowApiModal(false);
                  }}
                  disabled={!abuseIpDbKey.trim()}
                  className="w-full py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs transition-colors flex items-center justify-center space-x-1"
                >
                  <Check className="w-3.5 h-3.5" />
                  <span>Activate AbuseIPDB Integration</span>
                </button>
              </div>

              {/* Built-in Option */}
              <button
                onClick={() => {
                  localStorage.setItem('CYBERGUARD_ABUSEIPDB_ACTIVE', 'false');
                  setIsApiActive(false);
                  setShowApiModal(false);
                }}
                className="w-full py-2.5 rounded-xl bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 text-xs transition-colors"
              >
                Use Built-in Offline Subnet & C2 Threat Database (0 API Keys Needed)
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
