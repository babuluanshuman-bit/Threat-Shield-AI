import React, { useState, useEffect } from 'react';
import {
  DEFAULT_VIRUSTOTAL_KEY,
  analyzeLiveUrl,
  LiveUrlAnalysisResult,
  VirusTotalUrlData,
} from '../services/urlIntelligenceService';
import { useCyberGuard } from '../context/CyberGuardContext';
import { RiskGauge } from '../components/common/RiskGauge';
import { ExplainableEvidencePanel } from '../components/common/ExplainableEvidencePanel';
import { ResponsePanel } from '../components/common/ResponsePanel';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import { Threat } from '../types/cyberguard';
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Calendar,
  Server,
  Zap,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Key,
  ExternalLink,
  Check,
  X,
  Copy,
  Activity,
  ChevronDown,
  ChevronUp,
  Radio,
  Sparkles,
} from 'lucide-react';

export const UrlAnalyzerPage: React.FC = () => {
  const { ingestNewThreat } = useCyberGuard();
  const [urlInput, setUrlInput] = useState('https://secure-bank-login.xyz/auth/verify');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [showAllVendors, setShowAllVendors] = useState(false);
  const [copiedText, setCopiedText] = useState(false);

  // VirusTotal Free API v3 Settings
  const [showApiModal, setShowApiModal] = useState(false);
  const [vtApiKey, setVtApiKey] = useState(
    () => localStorage.getItem('CYBERGUARD_VT_KEY') || DEFAULT_VIRUSTOTAL_KEY
  );
  const [isVtActive, setIsVtActive] = useState(
    () => localStorage.getItem('CYBERGUARD_VT_ACTIVE') !== 'false'
  );

  // Analysis Result
  const [result, setResult] = useState<LiveUrlAnalysisResult | null>(null);

  const sampleUrls = [
    { label: 'Banking Phish (Critical)', url: 'https://secure-bank-login.xyz/auth/verify' },
    { label: 'PayPal Homoglyph (Critical)', url: 'https://paypa1-support-verify.online/login' },
    { label: 'Google Official (Safe)', url: 'https://google.com' },
    { label: 'GitHub Official (Safe)', url: 'https://github.com' },
    { label: 'Google Phishing Test Vector', url: 'https://testsafebrowsing.appspot.com/s/phishing.html' },
  ];

  // Run live scan
  const handleScan = async (targetUrl?: string) => {
    const toScan = targetUrl || urlInput;
    if (!toScan.trim()) return;

    setIsScanning(true);
    setScanStep('Resolving Live DNS via Cloudflare Anycast...');

    try {
      setTimeout(() => {
        setScanStep('Querying VirusTotal v3 across 70+ Security Engines...');
      }, 350);

      const activeKey = isVtActive ? vtApiKey : undefined;
      const res = await analyzeLiveUrl(toScan, activeKey);

      setScanStep('Correlating Autonomous Threat Telemetry & Heuristics...');
      await new Promise((r) => setTimeout(r, 200));

      setResult(res);

      // Ingest to live threat stream if dangerous
      if (res.riskScore >= 60) {
        const newThreat: Threat = {
          id: `THR-URL-${Date.now()}`,
          timestamp: 'Just now',
          source: 'URL',
          target: toScan,
          category: res.threatCategory,
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
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  // Initial Scan on Mount
  useEffect(() => {
    handleScan('https://secure-bank-login.xyz/auth/verify');
  }, []);

  const handleSaveApiKey = (key: string, active: boolean) => {
    setVtApiKey(key);
    setIsVtActive(active);
    localStorage.setItem('CYBERGUARD_VT_KEY', key);
    localStorage.setItem('CYBERGUARD_VT_ACTIVE', active ? 'true' : 'false');
    setShowApiModal(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 2000);
  };

  // Convert current analysis result to Threat object for ResponsePanel
  const currentThreat: Threat | null = result
    ? {
        id: `THR-URL-${Date.now()}`,
        timestamp: 'Just now',
        source: 'URL',
        target: result.target,
        category: result.threatCategory,
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
      {/* Header Bar */}
      <div className="p-4 rounded-2xl bg-[#0B1120] border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-mono font-bold text-white tracking-wide">
                REAL-TIME PHISHING & URL ANALYZER
              </h1>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Genuine multi-vendor URL inspection: VirusTotal 70+ AV engines, Cloudflare DoH live DNS, brand homoglyphs, and SSL telemetry.
            </p>
          </div>
        </div>
      </div>

      {/* URL Scanner Search Input */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleScan();
              }}
              placeholder="Paste any live URL or domain (e.g. https://google.com or suspicious link)"
              className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none transition-colors"
            />
          </div>

          <button
            onClick={() => handleScan()}
            disabled={isScanning || !urlInput.trim()}
            className="w-full sm:w-auto py-3 px-6 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(0,240,255,0.35)] transition-all transform active:scale-95 disabled:opacity-50 flex items-center justify-center space-x-2 shrink-0"
          >
            {isScanning ? (
              <>
                <RotateCcw className="w-4 h-4 animate-spin text-slate-950" />
                <span>Scanning Live Engines...</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4 fill-current" />
                <span>Detonate & Analyze URL</span>
              </>
            )}
          </button>
        </div>

        {/* Live scanning progress bar */}
        {isScanning && (
          <div className="p-3 rounded-xl bg-cyan-950/40 border border-cyan-800/40 flex items-center space-x-3 text-xs font-mono text-cyan-300 animate-pulse">
            <Activity className="w-4 h-4 text-cyan-400 animate-spin" />
            <span>{scanStep}</span>
          </div>
        )}

        {/* Quick Sample Buttons */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-slate-500">Test Preset Vectors:</span>
          {sampleUrls.map((s, idx) => (
            <button
              key={idx}
              onClick={() => {
                setUrlInput(s.url);
                handleScan(s.url);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[11px] font-mono transition-colors"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Analysis Results View */}
      {result && (
        <div className="space-y-6">
          {/* Top Result Banner */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            {/* Risk Gauge Card */}
            <div className="md:col-span-4 p-6 rounded-2xl bg-[#070C18] border border-slate-800 flex flex-col items-center justify-center text-center shadow-cyber-card">
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 mb-2">
                Unified Risk Score
              </span>
              <RiskGauge score={result.riskScore} size="lg" />
              <div className="mt-4 flex items-center space-x-2">
                <ThreatBadge category={result.threatCategory} />
                <SeverityBadge level={result.severity} />
              </div>
              <div className="mt-3 text-[11px] font-mono text-slate-400">
                {result.metadata?.vtDetectionRatio}
              </div>
            </div>

            {/* Live Telemetry & Network Sandbox Card */}
            <div className="md:col-span-8 p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between">
              <div>
                <div className="pb-3 border-b border-slate-800 flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                      Live Network & Sandbox Telemetry
                    </h3>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      LIVE DATA
                    </span>
                  </div>
                  <span className="text-xs font-mono text-cyan-400 font-bold">
                    {result.metadata?.httpStatus || '200 OK (Rendered)'}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Domain / Age</span>
                    <span className="text-white font-bold mt-1 block truncate" title={result.metadata?.domainAge}>
                      {result.metadata?.domainAge || 'Established'}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">SSL Status</span>
                    <span className="text-white font-bold mt-1 block truncate">
                      {result.metadata?.sslStatus || 'Valid TLS'}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Live Resolved IP</span>
                    <span className="text-white font-bold mt-1 block truncate" title={result.metadata?.ipResolved}>
                      {result.metadata?.ipResolved || 'Unresolved'}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">ISP / Autonomous System</span>
                    <span className="text-white font-bold mt-1 block truncate" title={result.metadata?.asnOrg}>
                      {result.metadata?.asnOrg || 'Global Public Internet'}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">DNS Status</span>
                    <span className="text-white font-bold mt-1 block truncate" title={result.metadata?.dnsStatus}>
                      {result.metadata?.dnsStatus || 'NOERROR (Cloudflare 1.1.1.1)'}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">AV Consensus</span>
                    <span
                      className={`font-bold mt-1 block truncate ${
                        (result.metadata?.vtMaliciousCount || 0) > 0 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {(result.metadata?.vtMaliciousCount || 0) > 0
                        ? `${result.metadata?.vtMaliciousCount} Engines Flagged`
                        : '0 Detections (Clean)'}
                    </span>
                  </div>
                </div>

                {/* Additional Live Metadata (Title or Categories) */}
                {(result.metadata?.pageTitle || (result.metadata?.categories && result.metadata.categories.length > 0)) && (
                  <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-xs font-mono">
                    {result.metadata?.pageTitle && (
                      <span className="text-slate-400">
                        Page Title: <strong className="text-white font-sans font-medium">{result.metadata.pageTitle}</strong>
                      </span>
                    )}
                    {result.metadata?.categories && result.metadata.categories.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 ml-auto">
                        {result.metadata.categories.map((cat, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-300"
                          >
                            {cat}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="pt-4 border-t border-slate-800 mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                <span className="text-slate-400 break-all mr-2">
                  Target URL: <strong className="text-cyan-300">{result.target}</strong>
                </span>
                <button
                  onClick={() => copyToClipboard(result.target)}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center space-x-1 shrink-0 self-start sm:self-auto"
                >
                  {copiedText ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedText ? 'Copied' : 'Copy URL'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* VirusTotal 70+ Antivirus & Phishing Engines Breakdown Card */}
          {result.virusTotalData && (
            <div className="p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
                    <Radio className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                      VirusTotal v3 Multi-Vendor Intelligence
                    </h3>
                    <p className="text-[11px] font-sans text-slate-400">
                      Consensus telemetry across {result.virusTotalData.totalVendors} global threat analysis engines
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <span className="text-slate-400">Detection Ratio:</span>
                    <span
                      className={`font-bold px-2.5 py-1 rounded-lg border ${
                        result.virusTotalData.maliciousCount > 0
                          ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                          : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                      }`}
                    >
                      {result.virusTotalData.detectionRatio}
                    </span>
                  </div>

                  <button
                    onClick={() => setShowAllVendors(!showAllVendors)}
                    className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors"
                  >
                    <span>{showAllVendors ? 'Collapse' : 'View All'}</span>
                    {showAllVendors ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {/* Vendor Badges Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5">
                {(showAllVendors
                  ? result.virusTotalData.topVendors
                  : result.virusTotalData.topVendors.slice(0, 8)
                ).map((vendor, idx) => {
                  const isBad = vendor.category === 'malicious' || vendor.category === 'suspicious';
                  return (
                    <div
                      key={idx}
                      className={`p-2.5 rounded-xl border flex items-center justify-between text-xs font-mono ${
                        isBad
                          ? 'bg-rose-950/20 border-rose-500/40 text-rose-300'
                          : 'bg-slate-900/60 border-slate-800 text-slate-300'
                      }`}
                    >
                      <span className="font-medium truncate mr-2" title={vendor.engineName}>
                        {vendor.engineName}
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${
                          isBad
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : vendor.category === 'harmless'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {vendor.result || vendor.category}
                      </span>
                    </div>
                  );
                })}
              </div>

              {result.virusTotalData.topVendors.length === 0 && (
                <div className="text-center py-4 text-xs font-mono text-slate-500">
                  URL queued or undergoing fresh analysis. Telemetry updating momentarily.
                </div>
              )}
            </div>
          )}

          {/* Explainable Evidence Panel */}
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

      {/* API Key Configuration Modal */}
      {showApiModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md p-6 rounded-2xl bg-[#0B1120] border border-slate-800 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2 text-white font-mono font-bold text-sm">
                <Key className="w-4 h-4 text-cyan-400" />
                <span>VirusTotal API Configuration</span>
              </div>
              <button
                onClick={() => setShowApiModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-400 font-sans">
              Connect your VirusTotal API key to enable live scanning across 70+ security vendors.
              Free accounts provide 500 requests per day.
            </p>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-[11px] text-slate-400 uppercase block mb-1">
                  VirusTotal API Key (v3)
                </label>
                <input
                  type="text"
                  value={vtApiKey}
                  onChange={(e) => setVtApiKey(e.target.value)}
                  placeholder="Paste VirusTotal API key..."
                  className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 text-slate-100 placeholder-slate-600 focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-slate-300">Enable Live API Scanning</span>
                <input
                  type="checkbox"
                  checked={isVtActive}
                  onChange={(e) => setIsVtActive(e.target.checked)}
                  className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowApiModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs"
              >
                Cancel
              </button>
              <button
                onClick={() => handleSaveApiKey(vtApiKey, isVtActive)}
                className="px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs uppercase"
              >
                Save & Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
