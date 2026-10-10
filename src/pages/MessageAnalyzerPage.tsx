import React, { useState, useMemo } from 'react';
import { analyzeMessage, AnalysisResult } from '../services/threatEngine';
import {
  queryVirusTotalUrl,
  VirusTotalUrlData,
  DEFAULT_VIRUSTOTAL_KEY
} from '../services/urlIntelligenceService';
import { useCyberGuard } from '../context/CyberGuardContext';
import { RiskGauge } from '../components/common/RiskGauge';
import { ExplainableEvidencePanel } from '../components/common/ExplainableEvidencePanel';
import { ResponsePanel } from '../components/common/ResponsePanel';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import { Threat } from '../types/cyberguard';
import {
  Smartphone,
  MessageSquare,
  Zap,
  RotateCcw,
  Sparkles,
  AlertTriangle,
  Send,
  CheckCircle2,
  Globe,
  ShieldAlert,
  ShieldCheck,
  Key,
  ExternalLink,
  X,
  Link2,
  Check,
  Info,
  Layers,
  HelpCircle,
  Cpu,
  Radio
} from 'lucide-react';

export const MessageAnalyzerPage: React.FC = () => {
  const { ingestNewThreat } = useCyberGuard();

  const [channel, setChannel] = useState<'WhatsApp' | 'SMS' | 'Telegram' | 'Instagram DM'>('WhatsApp');
  const [sender, setSender] = useState('+91 98210 99412');
  const [text, setText] = useState(
    'Congratulations! You won ₹50,000 in the Diwali Mega Reward. Click this link and enter your bank details to claim your reward: https://reward-claim-fest.xyz/bank-verify'
  );
  const [isScanning, setIsScanning] = useState(false);
  const [showApiGuideModal, setShowApiGuideModal] = useState(false);

  // Live VirusTotal Threat Intel for embedded links
  const [vtData, setVtData] = useState<VirusTotalUrlData | null>(null);
  const [isVtScanning, setIsVtScanning] = useState(false);
  const [vtError, setVtError] = useState<string | null>(null);

  const [result, setResult] = useState<AnalysisResult | null>(() =>
    analyzeMessage({
      channel: 'WhatsApp',
      sender: '+91 98210 99412',
      text: 'Congratulations! You won ₹50,000 in the Diwali Mega Reward. Click this link and enter your bank details to claim your reward: https://reward-claim-fest.xyz/bank-verify',
    })
  );

  const sampleMessages = [
    {
      channel: 'WhatsApp' as const,
      sender: '+91 98210 99412',
      text: 'Congratulations! You won ₹50,000 in the Diwali Mega Reward. Click this link and enter your bank details to claim your reward: https://reward-claim-fest.xyz/bank-verify',
      label: 'WhatsApp Lottery Scam (Critical Link)',
    },
    {
      channel: 'SMS' as const,
      sender: 'VK-SBI-BNK',
      text: 'Dear customer, your SBI NetBanking will be blocked today due to pending PAN/KYC. Update immediately at http://sbi-kyc-update.top or account will be frozen.',
      label: 'Banking SMS Urgency (Phishing Link)',
    },
    {
      channel: 'Telegram' as const,
      sender: '@CryptoSupportAdmin',
      text: 'Urgent security breach detected on your wallet. Send 0.1 ETH to verify ownership and restore balance.',
      label: 'Crypto Wallet Impersonation (No Link)',
    },
    {
      channel: 'SMS' as const,
      sender: 'VM-SWIGGY',
      text: 'Your order #4921 has been picked up by Rahul and is arriving in 18 minutes. Track order in Swiggy app.',
      label: 'Legitimate Delivery SMS (Safe)',
    },
  ];

  // Extract embedded URL if present
  const extractedUrl = useMemo(() => {
    return text.match(/https?:\/\/[^\s"'<>]+/i)?.[0] || null;
  }, [text]);

  // Dynamic suspicious phrase tagging
  const dynamicHighlightedTokens = useMemo(() => {
    const tokens: Array<{ phrase: string; tag: string; impact: string }> = [];

    if (/congratulations|mega reward|won ₹|claim your reward|lottery|cashback/i.test(text)) {
      tokens.push({
        phrase: 'Congratulations! / Won Reward',
        tag: 'Social Engineering Hook',
        impact: 'Bypasses vigilance with artificial excitement and dopamine incentive',
      });
    }
    if (/₹50,000|\$|50,000|0\.1 eth/i.test(text)) {
      tokens.push({
        phrase: 'Monetary Sum / Crypto Bait',
        tag: 'Financial Reward Bait',
        impact: 'Fabricates financial windfall or asset loss to incentivize rapid compliance',
      });
    }
    if (/click this link|update immediately|http:\/\/|https:\/\//i.test(text)) {
      tokens.push({
        phrase: 'Deceptive Hyperlink CTA',
        tag: 'Malicious Redirection',
        impact: 'Redirects victim to unverified external credential harvesting infrastructure',
      });
    }
    if (/bank details|pan\/kyc|kyc|otp|pin|cvv|blocked today|wallet/i.test(text)) {
      tokens.push({
        phrase: 'High-Privilege Credential Request',
        tag: 'PII / Account Harvesting',
        impact: 'Direct solicitation of confidential identity tokens or banking secrets',
      });
    }
    if (/urgent|blocked today|account will be frozen|security breach|immediately|expire/i.test(text)) {
      tokens.push({
        phrase: 'Artificial Time Pressure',
        tag: 'Fear / Urgency Coercion',
        impact: 'Fabricates emergency consequences to force immediate unscrutinized action',
      });
    }

    return tokens.length > 0
      ? tokens
      : [
          {
            phrase: 'Standard Message Telemetry',
            tag: 'Neutral Content',
            impact: 'No aggressive cognitive manipulation patterns flagged in text body',
          },
        ];
  }, [text]);

  const handleScan = async () => {
    setIsScanning(true);
    setVtError(null);

    const urlInMessage = text.match(/https?:\/\/[^\s"'<>]+/i)?.[0];
    let liveVt: VirusTotalUrlData | null = null;

    if (urlInMessage) {
      setIsVtScanning(true);
      try {
        liveVt = await queryVirusTotalUrl(urlInMessage);
        setVtData(liveVt);
      } catch (err: any) {
        console.warn('VirusTotal query notice:', err);
        setVtError(err?.message || 'VirusTotal query completed via heuristic profile');
      } finally {
        setIsVtScanning(false);
      }
    } else {
      setVtData(null);
    }

    const res = analyzeMessage({ text, channel, sender });

    // If VirusTotal returned real malicious flags on embedded URL, fuse indicators
    if (liveVt && liveVt.maliciousCount > 0) {
      res.riskScore = Math.min(100, Math.max(res.riskScore, 75 + Math.min(25, liveVt.maliciousCount * 4)));
      res.severity = res.riskScore >= 80 ? 'CRITICAL' : 'HIGH';
      res.indicators.unshift({
        name: 'VirusTotal Threat Intelligence (Live Scan)',
        finding: `${liveVt.maliciousCount}/${liveVt.totalVendors} global security engines flagged embedded link as MALICIOUS`,
        impact: 35,
        severity: 'critical',
        details: `Destination link "${urlInMessage}" identified as active phishing/malware by vendors including ${
          liveVt.topVendors
            .filter((v) => v.category === 'malicious')
            .slice(0, 3)
            .map((v) => v.engineName)
            .join(', ') || 'reputable threat vendors'
        }.`,
      });
      res.explanation += ` Furthermore, live VirusTotal Threat Intelligence confirmed the embedded destination URL is malicious (${liveVt.maliciousCount}/${liveVt.totalVendors} engines flagged).`;
    }

    setResult(res);
    setIsScanning(false);

    if (res.riskScore >= 60) {
      const newThreat: Threat = {
        id: `THR-MSG-${Date.now()}`,
        timestamp: 'Just now',
        source: channel === 'WhatsApp' ? 'WhatsApp' : 'SMS',
        target: sender,
        category: res.threatCategory,
        riskScore: res.riskScore,
        severity: res.severity,
        title: res.suggestedIncidentTitle,
        summary: res.explanation.slice(0, 100) + '...',
        status: 'DETECTED',
        indicators: res.indicators,
        explanation: res.explanation,
        recommendations: res.recommendations,
        metadata: {
          ...res.metadata,
          embeddedUrl: urlInMessage,
          virusTotalRatio: liveVt ? liveVt.detectionRatio : undefined,
        },
      };
      ingestNewThreat(newThreat);
    }
  };

  const currentThreat: Threat | null = result
    ? {
        id: `THR-MSG-${Date.now()}`,
        timestamp: 'Just now',
        source: channel === 'WhatsApp' ? 'WhatsApp' : 'SMS',
        target: sender,
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
      {/* Header */}
      <div className="p-4 rounded-2xl bg-[#0B1120] border border-slate-800">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Smartphone className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-mono font-bold text-white tracking-wide">
                  SMS, WHATSAPP & SOCIAL ENGINEERING ANALYZER
                </h1>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Evaluates psychological coercion, lottery lures, KYC smishing, and correlates embedded links with live VirusTotal Threat Intelligence.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <div className="px-2.5 py-1.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono font-semibold flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>VirusTotal Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Input Box */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        {/* Presets */}
        <div className="flex flex-wrap items-center gap-2 pb-2 border-b border-slate-850">
          <span className="text-[11px] font-mono text-slate-500">Preset Scenarios:</span>
          {sampleMessages.map((sample, i) => (
            <button
              key={i}
              onClick={() => {
                setChannel(sample.channel);
                setSender(sample.sender);
                setText(sample.text);
                setVtData(null);
              }}
              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[11px] font-mono transition-colors"
            >
              {sample.label}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-[11px] font-mono uppercase text-slate-400 font-semibold mb-1 block">
              Channel Platform
            </label>
            <select
              value={channel}
              onChange={(e) => setChannel(e.target.value as any)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 font-mono text-xs text-slate-100 focus:outline-none"
            >
              <option value="WhatsApp">WhatsApp</option>
              <option value="SMS">SMS / Text Message</option>
              <option value="Telegram">Telegram</option>
              <option value="Instagram DM">Instagram DM</option>
            </select>
          </div>

          <div>
            <label className="text-[11px] font-mono uppercase text-slate-400 font-semibold mb-1 block">
              Sender Handle / Phone
            </label>
            <input
              type="text"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 font-mono text-xs text-slate-100 focus:outline-none"
            />
          </div>
        </div>

        <div>
          <label className="text-[11px] font-mono uppercase text-slate-400 font-semibold mb-1 block">
            Message Content
          </label>
          <textarea
            rows={3}
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-full p-3.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 font-mono text-xs text-slate-100 focus:outline-none"
          />
        </div>

        {/* Embedded Link Detection & VirusTotal Status Strip */}
        <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between flex-wrap gap-2 text-xs font-mono">
          <div className="flex items-center space-x-2">
            <Globe className="w-4 h-4 text-cyan-400 flex-shrink-0" />
            <span className="text-slate-400">Embedded Link Telemetry:</span>
            {extractedUrl ? (
              <span className="text-cyan-300 font-bold break-all bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
                {extractedUrl}
              </span>
            ) : (
              <span className="text-slate-500 italic">No link detected (Heuristic NLP text mode)</span>
            )}
          </div>
          <div className="flex items-center space-x-2">
            {extractedUrl ? (
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3" />
                <span>VirusTotal Auto-Scan Ready</span>
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 border border-slate-700 text-slate-400">
                Pure NLP Intent Engine
              </span>
            )}
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleScan}
            disabled={isScanning || isVtScanning}
            className="py-3 px-6 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(0,240,255,0.35)] transition-all transform active:scale-95 disabled:opacity-50 flex items-center space-x-2"
          >
            {isScanning || isVtScanning ? (
              <>
                <RotateCcw className="w-4 h-4 animate-spin text-slate-950" />
                <span>{isVtScanning ? 'Querying VirusTotal Engines...' : 'Parsing Cognitive Tokens...'}</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4 fill-current" />
                <span>Analyze Message & Audit Threat</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Interactive Highlighted Suspicious Phrases */}
      {result && result.riskScore >= 40 && (
        <div className="p-6 rounded-2xl bg-gradient-to-b from-[#0F172A] to-[#070C18] border border-amber-500/40 shadow-cyber-card space-y-4">
          <div className="flex items-center space-x-2 text-amber-400">
            <Sparkles className="w-4 h-4" />
            <h3 className="font-mono text-xs font-bold uppercase tracking-wider">
              Highlighted Cognitive Manipulation Phrases
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {dynamicHighlightedTokens.map((tok, i) => (
              <div
                key={i}
                className="p-3 rounded-xl bg-slate-950/80 border border-amber-500/25 space-y-1 font-mono text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40">
                    "{tok.phrase}"
                  </span>
                  <span className="text-[10px] text-rose-400 uppercase font-bold">
                    {tok.tag}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans mt-1">
                  {tok.impact}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live VirusTotal Threat Intel Card (Shown when URL is scanned) */}
      {vtData && (
        <div className="p-5 rounded-2xl bg-[#0B1120] border border-cyan-500/40 shadow-cyber-card space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2 pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div>
                <span className="font-mono text-xs font-bold text-white uppercase tracking-wider block">
                  VirusTotal Threat Intelligence (Live URL Scan)
                </span>
                <span className="text-[11px] text-slate-400 font-sans">
                  Consensus across 70+ global antivirus engines and URL blocklists
                </span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <span
                className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border ${
                  vtData.maliciousCount > 0
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                }`}
              >
                {vtData.detectionRatio}
              </span>
              <a
                href={`https://www.virustotal.com/gui/url/${vtData.id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors"
                title="Open in VirusTotal GUI"
              >
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Scanned Target</span>
              <span className="text-cyan-300 font-bold truncate block mt-1" title={vtData.url}>
                {vtData.url}
              </span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Reputation Score</span>
              <span className={`font-bold block mt-1 ${vtData.reputation < 0 ? 'text-rose-400' : 'text-slate-300'}`}>
                {vtData.reputation} / 100
              </span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Top Flagging Vendors</span>
              <span className="text-rose-400 font-bold block mt-1 truncate">
                {vtData.topVendors.filter((v) => v.category === 'malicious').slice(0, 3).map((v) => v.engineName).join(', ') || '0 Vendors (Clean)'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            <div className="md:col-span-4 p-6 rounded-2xl bg-[#070C18] border border-slate-800 flex flex-col items-center justify-center text-center shadow-cyber-card">
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 mb-2">
                Social Engineering Score
              </span>
              <RiskGauge score={result.riskScore} size="lg" />
              <div className="mt-4 flex items-center space-x-2">
                <ThreatBadge category={result.threatCategory} />
                <SeverityBadge level={result.severity} />
              </div>
            </div>

            <div className="md:col-span-8 p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between">
              <div>
                <div className="pb-3 border-b border-slate-800 flex items-center justify-between mb-4">
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                    NLP Entity & Intent Extraction
                  </h3>
                  <span className="text-xs font-mono text-cyan-400 font-bold">
                    Channel: {channel}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Lure Intent</span>
                    <span className="text-rose-400 font-bold mt-1 block">
                      {result.riskScore >= 70 ? 'Financial Scam Lure' : result.riskScore >= 40 ? 'Urgency Coercion' : 'Benign Telemetry'}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Credential Target</span>
                    <span className="text-rose-400 font-bold mt-1 block">
                      {/bank|pan|kyc|otp|pin|wallet/i.test(text) ? 'Bank Account / KYC Secrets' : 'None Detected'}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Threat Modality</span>
                    <span className="text-amber-400 font-bold mt-1 block">
                      {extractedUrl ? 'Smishing Hyperlink' : 'Pure Social Engineering'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Target Sender: <strong className="text-cyan-300">{result.target}</strong></span>
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

      {/* Free Threat APIs Guide Modal */}
      {showApiGuideModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-sm animate-fade-in overflow-y-auto">
          <div className="w-full max-w-2xl p-5 sm:p-6 rounded-2xl bg-[#0B1120] border border-slate-800 space-y-4 shadow-2xl my-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Key className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-mono font-bold text-white">
                    SMS & Social Engineering Threat Intel APIs
                  </h3>
                  <p className="text-xs text-slate-400">
                    Architecture guide on VirusTotal & recommended free APIs for checking smishing
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowApiGuideModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3.5 text-xs font-mono max-h-[60vh] overflow-y-auto pr-1">
              {/* 1. VirusTotal API */}
              <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/40 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                      ★ CURRENTLY ACTIVE IN THIS PLATFORM
                    </span>
                    <strong className="text-white">1. VirusTotal API v3 (URL & Hash Intel)</strong>
                  </div>
                  <span className="text-[10px] text-emerald-400">Integrated</span>
                </div>
                <p className="text-slate-300 font-sans leading-relaxed text-[12px]">
                  <strong>Is it okay to use VirusTotal?</strong> <strong>Yes, absolutely!</strong> Over 90% of real-world SMS/WhatsApp smishing campaigns deliver their attack payload through an embedded URL (fake KYC portals, bank credential harvest forms, or malicious <code>.apk</code> malware downloads). VirusTotal queries 70+ antivirus engines and blacklists (Kaspersky, BitDefender, Google Safe Browsing, CRDF, Sophos) simultaneously.
                </p>
                <div className="text-[11px] text-slate-400 border-t border-cyan-500/20 pt-1.5">
                  <strong>Limitation:</strong> VirusTotal inspects URLs, IPs, and file hashes — it does not analyze plain text without URLs (e.g. pure social engineering or emergency impersonation).
                </div>
              </div>

              {/* 2. Unshorten.me API */}
              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                      FREE • NO KEY NEEDED
                    </span>
                    <strong className="text-white">2. Unshorten.me API (URL Unshortening)</strong>
                  </div>
                  <a
                    href="https://unshorten.me"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline flex items-center space-x-1 text-[11px]"
                  >
                    <span>unshorten.me</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <p className="text-slate-300 font-sans leading-relaxed text-[12px]">
                  Smishers routinely hide malicious destinations behind link shorteners like <code>bit.ly</code>, <code>tinyurl.com</code>, <code>is.gd</code>, and <code>t.co</code>. The free <code>https://unshorten.me/api/v2/unshorten?url=...</code> expands short links to reveal the true destination domain before passing it to VirusTotal!
                </p>
              </div>

              {/* 3. Hugging Face Inference API */}
              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                      FREE TIER
                    </span>
                    <strong className="text-white">3. Hugging Face Inference API (NLP Text Classifier)</strong>
                  </div>
                  <a
                    href="https://huggingface.co"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline flex items-center space-x-1 text-[11px]"
                  >
                    <span>huggingface.co</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <p className="text-slate-300 font-sans leading-relaxed text-[12px]">
                  For messages <em>without</em> URLs (e.g. CEO fraud, OTP interception, emergency family baiting), Hugging Face offers free serverless models like <code>mrm8488/bert-tiny-finetuned-sms-spam-detection</code> that output spam vs. ham probabilities with zero server cost.
                </p>
              </div>

              {/* 4. Google Gemini 2.0 Flash */}
              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300 border border-blue-500/40">
                      FREE TIER (15 RPM)
                    </span>
                    <strong className="text-white">4. Google Gemini 2.0 Flash API (Reasoning)</strong>
                  </div>
                  <a
                    href="https://aistudio.google.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline flex items-center space-x-1 text-[11px]"
                  >
                    <span>Google AI Studio</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <p className="text-slate-300 font-sans leading-relaxed text-[12px]">
                  Exceptional at analyzing multilingual Indian & global scams (Hinglish, regional dialect lures, fake electricity bill disconnect notices, and UPI PIN theft) with explainable step-by-step risk attribution.
                </p>
              </div>

              {/* 5. Numverify Phone API */}
              <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                      FREE 100/mo
                    </span>
                    <strong className="text-white">5. Numverify API (Phone & Telecom Carrier Lookup)</strong>
                  </div>
                  <a
                    href="https://numverify.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline flex items-center space-x-1 text-[11px]"
                  >
                    <span>numverify.com</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <p className="text-slate-300 font-sans leading-relaxed text-[12px]">
                  Verifies whether the sender phone number belongs to a real cellular telecom line or a virtual VoIP / burner proxy service frequently exploited by cybercrime rings.
                </p>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setShowApiGuideModal(false)}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono font-bold text-xs transition-colors"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
