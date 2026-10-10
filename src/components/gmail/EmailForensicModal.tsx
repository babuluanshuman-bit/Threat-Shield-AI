import React, { useState } from 'react';
import { ScannedGmailEmail } from '../../services/gmailScannerService';
import { SeverityBadge, ThreatBadge } from '../common/ThreatBadge';
import { RiskGauge } from '../common/RiskGauge';
import {
  X,
  Mail,
  ShieldAlert,
  Globe,
  FileCode,
  Lock,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  Zap,
  CheckCircle2,
  Ban,
  Radio,
  FileText,
  User,
  Calendar,
  Layers,
  Sparkles
} from 'lucide-react';

interface EmailForensicModalProps {
  email: ScannedGmailEmail | null;
  isOpen: boolean;
  onClose: () => void;
  onIngestToSoc: (email: ScannedGmailEmail) => void;
  onQuarantine: (email: ScannedGmailEmail) => void;
}

export const EmailForensicModal: React.FC<EmailForensicModalProps> = ({
  email,
  isOpen,
  onClose,
  onIngestToSoc,
  onQuarantine,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'headers' | 'urls' | 'attachments' | 'body'>('overview');

  if (!isOpen || !email) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/85 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-4xl bg-[#070C18] border border-cyan-500/30 rounded-2xl shadow-[0_0_50px_rgba(0,240,255,0.18)] overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Top Bar */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/80">
          <div className="flex items-center space-x-3 truncate">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
              <Mail className="w-5 h-5" />
            </div>
            <div className="truncate">
              <div className="flex items-center space-x-2">
                <span className="font-mono text-xs font-bold text-white tracking-wide truncate">
                  EMAIL FORENSIC INSPECTOR
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-slate-800 text-slate-300 border border-slate-700">
                  ID: {email.id}
                </span>
                {email.isSandboxDemo && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    SANDBOX
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300 truncate font-sans mt-0.5 font-medium">
                {email.subject}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0 ml-3">
            <SeverityBadge level={email.severity} />
            <button
              onClick={onClose}
              className="p-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center px-4 bg-slate-950/60 border-b border-slate-850 overflow-x-auto">
          {[
            { id: 'overview', label: 'Threat Overview & AI Analysis', icon: Sparkles },
            { id: 'body', label: 'Message Body & Payload', icon: FileText },
            { id: 'urls', label: `URLs & VirusTotal (${email.extractedUrls.length})`, icon: Globe },
            { id: 'attachments', label: `Attachments (${email.attachments.length})`, icon: FileCode },
            { id: 'headers', label: 'Raw Headers & Protocol Forensics', icon: Layers },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 px-3.5 py-2.5 text-xs font-mono border-b-2 whitespace-nowrap transition-colors ${
                  isActive
                    ? 'border-cyan-400 text-cyan-300 font-bold bg-cyan-500/5'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Body */}
        <div className="p-4 sm:p-6 overflow-y-auto font-sans text-xs text-slate-300 space-y-6">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Top Summary Grid */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
                <div className="md:col-span-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col items-center justify-center text-center">
                  <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 mb-1">
                    Risk Assessment
                  </span>
                  <RiskGauge score={email.riskScore} size="lg" />
                  <div className="mt-3 flex items-center space-x-2">
                    <ThreatBadge category={email.threatCategory} />
                    <span className="text-xs font-mono font-bold text-slate-300">
                      Score: {email.riskScore}/100
                    </span>
                  </div>
                </div>

                <div className="md:col-span-8 p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3 flex flex-col justify-between">
                  <div>
                    <h3 className="font-mono text-xs font-bold uppercase text-white tracking-wider mb-2">
                      Sender Metadata & Authentication
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                      <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
                        <span className="text-[10px] text-slate-500 uppercase block">From Display Name</span>
                        <span className="text-white font-semibold block truncate mt-0.5">
                          {email.fromDisplayName || 'None'}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
                        <span className="text-[10px] text-slate-500 uppercase block">Sender Address</span>
                        <span className="text-cyan-300 font-semibold block truncate mt-0.5">
                          {email.fromEmail}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
                        <span className="text-[10px] text-slate-500 uppercase block">Sender Domain</span>
                        <span className="text-slate-200 block truncate mt-0.5">
                          {email.senderDomain}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800">
                        <span className="text-[10px] text-slate-500 uppercase block">DMARC / SPF Status</span>
                        <span
                          className={`font-bold block mt-0.5 ${
                            email.authTelemetry.dmarcStatus === 'PASS'
                              ? 'text-emerald-400'
                              : 'text-rose-400'
                          }`}
                        >
                          DMARC: {email.authTelemetry.dmarcStatus} | SPF: {email.authTelemetry.spfStatus}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 font-mono flex items-center justify-between">
                    <span>Date: {email.date}</span>
                    <span>Recipient: {email.to}</span>
                  </div>
                </div>
              </div>

              {/* Explainable AI Analysis */}
              <div className="p-5 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-3">
                <div className="flex items-center space-x-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <h4 className="font-mono text-xs font-bold uppercase text-white tracking-wider">
                    Threat Lens AI Explainable Evidence
                  </h4>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-sans">
                  {email.explanation}
                </p>

                {/* MITRE ATT&CK Mapping */}
                {email.mitreTechniques.length > 0 && (
                  <div className="pt-2">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1.5">
                      MITRE ATT&CK Mapped Techniques:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {email.mitreTechniques.map((tech, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950/60 text-purple-300 border border-purple-500/30 font-semibold"
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Detected Indicators Breakdown */}
              <div className="space-y-3">
                <h4 className="font-mono text-xs font-bold uppercase text-slate-400 tracking-wider">
                  Extracted Threat Indicators ({email.indicators.length})
                </h4>
                <div className="space-y-2">
                  {email.indicators.map((ind, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-xl border flex items-start justify-between ${
                        ind.severity === 'critical'
                          ? 'bg-rose-950/20 border-rose-500/40'
                          : ind.severity === 'high'
                          ? 'bg-orange-950/20 border-orange-500/40'
                          : ind.severity === 'medium'
                          ? 'bg-amber-950/20 border-amber-500/40'
                          : 'bg-emerald-950/20 border-emerald-500/40'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono font-bold text-xs text-white">
                            {ind.name}
                          </span>
                          <span
                            className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase border ${
                              ind.severity === 'critical'
                                ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                                : ind.severity === 'high'
                                ? 'bg-orange-500/20 text-orange-300 border-orange-500/30'
                                : ind.severity === 'medium'
                                ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                            }`}
                          >
                            {ind.severity}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 font-sans">
                          {ind.finding}
                        </p>
                        {ind.details && (
                          <p className="text-[11px] text-slate-400 font-sans">
                            {ind.details}
                          </p>
                        )}
                      </div>

                      <span
                        className={`text-xs font-mono font-bold shrink-0 ml-3 ${
                          ind.impact > 0 ? 'text-rose-400' : 'text-emerald-400'
                        }`}
                      >
                        {ind.impact > 0 ? `+${ind.impact}` : ind.impact}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: BODY */}
          {activeTab === 'body' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <span className="font-mono text-xs font-bold text-white uppercase block mb-1">
                  Decoded Message Body
                </span>
                <p className="text-[11px] text-slate-400 mb-3">
                  Parsed directly from base64url MIME payload parts.
                </p>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">
                  {email.bodyText || email.snippet}
                </div>
              </div>

              {email.extractedUrls.length > 0 && (
                <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-2">
                  <div className="flex items-center space-x-2 text-rose-300 font-mono font-bold text-xs">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span>Embedded Hyperlinks Detected in Message:</span>
                  </div>
                  <div className="space-y-1 font-mono text-[11px]">
                    {email.extractedUrls.map((url, i) => (
                      <div
                        key={i}
                        className="p-2 rounded bg-slate-900/80 border border-slate-800 text-rose-300 break-all flex items-center justify-between"
                      >
                        <span>{url}</span>
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-rose-500/20 text-rose-400 font-bold uppercase shrink-0 ml-2">
                          DO NOT CLICK
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: URLS & VIRUSTOTAL */}
          {activeTab === 'urls' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-mono text-xs font-bold uppercase text-white">
                    Extracted Hyperlink Intelligence
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Reputational telemetry correlated with VirusTotal v3 and DNS resolvers.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-xs">
                  {email.extractedUrls.length} Links
                </span>
              </div>

              {email.extractedUrls.length === 0 ? (
                <div className="p-8 text-center rounded-2xl bg-slate-900/40 border border-slate-800 text-slate-400">
                  <Globe className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                  <span>No external hyperlinks found in this email payload.</span>
                </div>
              ) : (
                <div className="space-y-3">
                  {email.extractedUrls.map((url, i) => {
                    const vtDetails = email.virusTotalSummary?.details?.[url];
                    const isMalicious = vtDetails?.isMalicious;

                    return (
                      <div
                        key={i}
                        className={`p-4 rounded-xl border space-y-2 ${
                          isMalicious
                            ? 'bg-rose-950/20 border-rose-500/40'
                            : 'bg-slate-900/60 border-slate-800'
                        }`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="space-y-1 truncate pr-3">
                            <span className="font-mono text-xs font-bold text-white break-all">
                              {url}
                            </span>
                            <span className="text-[11px] text-slate-400 block font-mono">
                              Domain: {url.split('/')[2] || url}
                            </span>
                          </div>

                          {vtDetails && (
                            <span
                              className={`px-2 py-1 rounded text-xs font-mono font-bold shrink-0 ${
                                isMalicious
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              }`}
                            >
                              VT: {vtDetails.malicious}/{vtDetails.total} Vendors
                            </span>
                          )}
                        </div>

                        {isMalicious && (
                          <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-200 text-xs font-sans">
                            <strong className="font-mono text-rose-300">VIRUSTOTAL ALERT:</strong> Multiple threat detection engines flagged this URL as an active phishing / credential harvester vector.
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: ATTACHMENTS */}
          {activeTab === 'attachments' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-mono text-xs font-bold uppercase text-white">
                    Attachment Forensics & Payload Entropy
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    File extension verification and malware container analysis.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-xs">
                  {email.attachments.length} Attachments
                </span>
              </div>

              {email.attachments.length === 0 ? (
                <div className="p-8 text-center rounded-2xl bg-slate-900/40 border border-slate-800 text-slate-400">
                  <FileCode className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                  <span>No file attachments present in this message.</span>
                </div>
              ) : (
                <div className="space-y-3">
                  {email.attachments.map((att, i) => (
                    <div
                      key={i}
                      className={`p-4 rounded-xl border space-y-2 ${
                        att.isSuspicious
                          ? 'bg-rose-950/20 border-rose-500/40'
                          : 'bg-slate-900/60 border-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <div
                            className={`p-2 rounded-lg ${
                              att.isSuspicious
                                ? 'bg-rose-500/20 text-rose-400'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            <FileCode className="w-5 h-5" />
                          </div>
                          <div>
                            <span className="font-mono text-xs font-bold text-white block">
                              {att.filename}
                            </span>
                            <span className="text-[11px] text-slate-400 font-mono">
                              MIME: {att.mimeType} | Size: {(att.size / 1024).toFixed(1)} KB
                            </span>
                          </div>
                        </div>

                        <span
                          className={`px-2 py-1 rounded text-xs font-mono font-bold ${
                            att.isSuspicious
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          }`}
                        >
                          {att.isSuspicious ? 'HIGH-RISK PAYLOAD' : 'VERIFIED SAFE'}
                        </span>
                      </div>

                      {att.reason && (
                        <p className="text-xs text-rose-300 font-sans pl-1">
                          ⚠️ {att.reason}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 5: HEADERS */}
          {activeTab === 'headers' && (
            <div className="space-y-4">
              <div>
                <h4 className="font-mono text-xs font-bold uppercase text-white">
                  Raw Mail Protocol Forensics & Authentication Headers
                </h4>
                <p className="text-[11px] text-slate-400">
                  Examine SPF, DKIM, and DMARC alignment records as returned by Google MX servers.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">SPF Policy</span>
                  <span
                    className={`font-bold mt-1 block ${
                      email.authTelemetry.spfStatus === 'PASS'
                        ? 'text-emerald-400'
                        : 'text-rose-400'
                    }`}
                  >
                    {email.authTelemetry.spfStatus}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">DKIM Signature</span>
                  <span
                    className={`font-bold mt-1 block ${
                      email.authTelemetry.dkimStatus === 'PASS'
                        ? 'text-emerald-400'
                        : 'text-amber-400'
                    }`}
                  >
                    {email.authTelemetry.dkimStatus}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">DMARC Alignment</span>
                  <span
                    className={`font-bold mt-1 block ${
                      email.authTelemetry.dmarcStatus === 'PASS'
                        ? 'text-emerald-400'
                        : 'text-rose-400'
                    }`}
                  >
                    {email.authTelemetry.dmarcStatus}
                  </span>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-2 max-h-72 overflow-y-auto">
                {Object.entries(email.headers).map(([key, val]) => (
                  <div key={key} className="border-b border-slate-850 pb-1.5 break-all">
                    <strong className="text-cyan-400 uppercase">{key}: </strong>
                    <span className="text-slate-300">{val}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer / SOC Response Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-400">Response Playbook:</span>
            {email.quarantined ? (
              <span className="px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono text-xs font-bold">
                ✓ EMAIL QUARANTINED
              </span>
            ) : email.riskScore >= 60 ? (
              <span className="px-2.5 py-1 rounded-lg bg-rose-500/20 text-rose-300 border border-rose-500/30 font-mono text-xs font-bold">
                ⚠️ CONTAINMENT REQUIRED
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-400 font-mono text-xs">
                STANDARD LOGGING
              </span>
            )}
          </div>

          <div className="flex items-center space-x-2.5">
            <button
              onClick={() => onIngestToSoc(email)}
              disabled={email.ingestedToSoc}
              className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 font-mono text-xs font-semibold disabled:opacity-50 flex items-center space-x-1.5"
            >
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>{email.ingestedToSoc ? 'Ingested to SOC' : 'Ingest to SOC Dashboard'}</span>
            </button>

            {email.riskScore >= 40 && (
              <button
                onClick={() => onQuarantine(email)}
                disabled={email.quarantined}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-400 hover:to-red-500 text-white font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(244,63,94,0.4)] disabled:opacity-50 flex items-center space-x-1.5"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>{email.quarantined ? 'Quarantined via SOAR' : 'Execute SOAR Quarantine'}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
