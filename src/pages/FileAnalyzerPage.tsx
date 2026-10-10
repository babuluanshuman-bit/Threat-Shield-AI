import React, { useState, useRef } from 'react';
import { analyzeFile, AnalysisResult } from '../services/threatEngine';
import {
  DEFAULT_VIRUSTOTAL_KEY,
  analyzeFileLocally,
  queryVirusTotalHash,
  getPresetForensicReport,
  FileForensicReport,
} from '../services/fileForensicService';
import { useCyberGuard } from '../context/CyberGuardContext';
import { RiskGauge } from '../components/common/RiskGauge';
import { ExplainableEvidencePanel } from '../components/common/ExplainableEvidencePanel';
import { ResponsePanel } from '../components/common/ResponsePanel';
import { SeverityBadge, ThreatBadge } from '../components/common/ThreatBadge';
import { Threat } from '../types/cyberguard';
import {
  FileCode,
  Upload,
  Zap,
  RotateCcw,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  FileText,
  Binary,
  Scan,
  RefreshCw,
  Key,
  ExternalLink,
  Check,
  X,
  ShieldAlert,
  Copy,
  Lock,
  FileCheck,
  Sparkles,
} from 'lucide-react';

export const FileAnalyzerPage: React.FC = () => {
  const { ingestNewThreat } = useCyberGuard();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // File and Analysis State
  const [fileName, setFileName] = useState('invoice.pdf');
  const [fileSize, setFileSize] = useState('412 KB');
  const [hash, setHash] = useState('a82fc109de83b4029481fe10d8a4392bc194091bc');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // VirusTotal Free API v3 State (Preconfigured with user API key)
  const [showApiModal, setShowApiModal] = useState(false);
  const [vtApiKey, setVtApiKey] = useState(() => localStorage.getItem('CYBERGUARD_VT_KEY') || DEFAULT_VIRUSTOTAL_KEY);
  const [isVtActive, setIsVtActive] = useState(() => localStorage.getItem('CYBERGUARD_VT_ACTIVE') !== 'false');

  // Initial Forensic Report
  const [forensicReport, setForensicReport] = useState<FileForensicReport>(() =>
    getPresetForensicReport('invoice.pdf')
  );

  // Initial Analysis Result
  const [result, setResult] = useState<AnalysisResult | null>(() => {
    const rep = getPresetForensicReport('invoice.pdf');
    return analyzeFile({
      name: 'invoice.pdf',
      size: '412 KB',
      hash: 'a82fc109de83b4029481fe10d8a4392bc194091bc',
      forensicReport: rep,
    });
  });

  const presets = [
    {
      name: 'invoice.pdf',
      size: '412 KB',
      hash: 'a82fc109de83b4029481fe10d8a4392bc194091bc',
      label: 'Trojanized PDF Dropper (High)',
    },
    {
      name: 'salary_statement.docx.exe',
      size: '1.2 MB',
      hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4',
      label: 'Double Extension Executable (Critical)',
    },
    {
      name: 'Annual_Report_2026.pdf',
      size: '3.4 MB',
      hash: '9b71d224bd62f3785d96d46ad3ea3d73319bf521',
      label: 'Clean Corporate Report (Safe)',
    },
  ];

  const handleSelectPreset = (p: typeof presets[0]) => {
    setUploadedFile(null);
    setFileName(p.name);
    setFileSize(p.size);
    setHash(p.hash);
    const rep = getPresetForensicReport(p.name);
    setForensicReport(rep);

    const res = analyzeFile({
      name: p.name,
      size: p.size,
      hash: p.hash,
      forensicReport: rep,
    });
    setResult(res);

    if (res.riskScore >= 60) {
      ingestNewThreat({
        id: `THR-FILE-${Date.now()}`,
        timestamp: 'Just now',
        source: 'File',
        target: p.name,
        category: 'Malicious File',
        riskScore: res.riskScore,
        severity: res.severity,
        title: res.suggestedIncidentTitle,
        summary: res.explanation.slice(0, 100) + '...',
        status: 'DETECTED',
        indicators: res.indicators,
        explanation: res.explanation,
        recommendations: res.recommendations,
        metadata: res.metadata,
      });
    }
  };

  const handleFileUpload = async (file: File) => {
    setUploadedFile(file);
    setFileName(file.name);
    setIsScanning(true);

    try {
      // 1. Run full local static forensics (entropy, magic headers, macro disassembler, SHA-256)
      let rep = await analyzeFileLocally(file);

      // 2. Query VirusTotal Free API v3 if active & key provided
      if (isVtActive && vtApiKey.trim()) {
        try {
          const vtData = await queryVirusTotalHash(rep.sha256, vtApiKey);
          rep = {
            ...rep,
            vtDetectionRatio: vtData.detectionRatio,
            vtMaliciousCount: vtData.maliciousCount,
            vtTotalVendors: vtData.totalVendors,
            isMalicious: rep.isMalicious || vtData.isMalicious,
            isSafe: !vtData.isMalicious && rep.isSafe,
          };
        } catch (vtErr) {
          console.warn('VirusTotal query note:', vtErr);
        }
      }

      setFileSize(rep.fileSizeFormatted);
      setHash(rep.sha256);
      setForensicReport(rep);

      // 3. Evaluate threat engine with real forensic telemetry
      const res = analyzeFile({
        name: file.name,
        size: rep.fileSizeFormatted,
        hash: rep.sha256,
        forensicReport: rep,
      });

      setResult(res);

      if (res.riskScore >= 60) {
        ingestNewThreat({
          id: `THR-FILE-${Date.now()}`,
          timestamp: 'Just now',
          source: 'File',
          target: file.name,
          category: 'Malicious File',
          riskScore: res.riskScore,
          severity: res.severity,
          title: res.suggestedIncidentTitle,
          summary: res.explanation.slice(0, 100) + '...',
          status: 'DETECTED',
          indicators: res.indicators,
          explanation: res.explanation,
          recommendations: res.recommendations,
          metadata: res.metadata,
        });
      }
    } catch (err) {
      console.error('File forensic analysis failed:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleManualScan = async () => {
    if (uploadedFile) {
      await handleFileUpload(uploadedFile);
      return;
    }

    setIsScanning(true);
    setTimeout(() => {
      const rep = getPresetForensicReport(fileName);
      setForensicReport(rep);
      const res = analyzeFile({
        name: fileName,
        size: fileSize,
        hash,
        forensicReport: rep,
      });
      setResult(res);
      setIsScanning(false);

      if (res.riskScore >= 60) {
        ingestNewThreat({
          id: `THR-FILE-${Date.now()}`,
          timestamp: 'Just now',
          source: 'File',
          target: fileName,
          category: 'Malicious File',
          riskScore: res.riskScore,
          severity: res.severity,
          title: res.suggestedIncidentTitle,
          summary: res.explanation.slice(0, 100) + '...',
          status: 'DETECTED',
          indicators: res.indicators,
          explanation: res.explanation,
          recommendations: res.recommendations,
          metadata: res.metadata,
        });
      }
    }, 450);
  };

  const handleCopyHash = () => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const currentThreat: Threat | null = result
    ? {
        id: `THR-FILE-${Date.now()}`,
        timestamp: 'Just now',
        source: 'File',
        target: fileName,
        category: 'Malicious File',
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
            <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400">
              <FileCode className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-mono font-bold text-white tracking-wide">
                  MALICIOUS FILE & CONTENT STATIC FORENSIC SCANNER
                </h1>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Inspects Shannon entropy, binary magic number MIME spoofing, and embedded macro/shell streams, cross-referencing global multi-engine antivirus threat telemetry.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Preset & Upload Card */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-wrap items-center gap-2 pb-2 border-b border-slate-850">
          <span className="text-[11px] font-mono text-slate-500">Preset File Samples:</span>
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleSelectPreset(p)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors border ${
                fileName === p.name && !uploadedFile
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  : 'bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-cyan-300 border-slate-700'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Hidden File Input */}
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />

        {/* Upload Container */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
              handleFileUpload(e.dataTransfer.files[0]);
            }
          }}
          onClick={() => fileInputRef.current?.click()}
          className={`p-8 border-2 border-dashed rounded-2xl text-center space-y-3 cursor-pointer transition-all ${
            isDragging
              ? 'border-rose-400 bg-rose-950/40 shadow-[0_0_30px_rgba(244,63,94,0.25)] scale-[1.005]'
              : 'border-slate-700 hover:border-rose-500/60 bg-slate-950/60 hover:bg-slate-950/80'
          }`}
        >
          <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center mx-auto">
            <Binary className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center justify-center space-x-2">
              <span className="font-mono text-xs font-bold text-slate-200 block">
                Target: <strong className="text-rose-400">{fileName}</strong> ({fileSize})
              </span>
              {uploadedFile && (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  Custom User File
                </span>
              )}
            </div>
            <div className="flex items-center justify-center space-x-2 mt-1">
              <p className="text-[11px] text-slate-400 font-mono truncate max-w-md">
                SHA-256: {hash}
              </p>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleCopyHash();
                }}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                title="Copy SHA-256 hash"
              >
                {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <p className="text-[10px] text-slate-500 font-sans mt-1">
              Click anywhere or drag & drop any PDF, Word document, image, text, or binary file for full forensic extraction
            </p>
          </div>

          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleManualScan();
              }}
              disabled={isScanning}
              className="py-2.5 px-6 rounded-xl bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-400 hover:to-red-500 text-white font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(239,68,68,0.35)] transition-all flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>De-obfuscating Object Streams...</span>
                </>
              ) : (
                <>
                  <Scan className="w-3.5 h-3.5" />
                  <span>Run Static File Forensics</span>
                </>
              )}
            </button>

            <button
              onClick={(e) => {
                e.stopPropagation();
                fileInputRef.current?.click();
              }}
              className="py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-200 hover:text-rose-300 font-mono text-xs font-semibold border border-slate-700 transition-all flex items-center space-x-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Browse File</span>
            </button>
          </div>
        </div>
      </div>

      {/* Forensic Diagnostics Telemetry Badges */}
      {forensicReport && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Shannon Entropy */}
          <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-cyber-card space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-slate-400">Shannon Entropy</span>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                  forensicReport.entropy > 7.3
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : forensicReport.entropy > 6.5
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {forensicReport.entropyLabel}
              </span>
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-xl font-mono font-bold text-white">
                {forensicReport.entropy.toFixed(2)}
              </span>
              <span className="text-xs font-mono text-slate-500">/ 8.00 bits</span>
            </div>
            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  forensicReport.entropy > 7.3
                    ? 'bg-rose-500'
                    : forensicReport.entropy > 6.5
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'
                }`}
                style={{ width: `${(forensicReport.entropy / 8.0) * 100}%` }}
              />
            </div>
          </div>

          {/* Magic Byte Verification */}
          <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-cyber-card space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-slate-400">Magic Number Header</span>
              {forensicReport.isExtensionSpoofed ? (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                  SPOOFED
                </span>
              ) : (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                  MATCH
                </span>
              )}
            </div>
            <p className="text-xs font-mono font-bold text-white truncate pt-1">
              {forensicReport.actualType}
            </p>
            <p className="text-[10px] font-mono text-slate-400 truncate">
              MIME: {forensicReport.detectedMime}
            </p>
          </div>

          {/* Embedded Macro Streams */}
          <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-cyber-card space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-slate-400">Stream Disassembly</span>
              {forensicReport.hasSuspiciousStreams ? (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                  ACTIVE HOOKS
                </span>
              ) : (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                  CLEAN
                </span>
              )}
            </div>
            <p
              className={`text-xs font-mono font-bold pt-1 ${
                forensicReport.hasSuspiciousStreams ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {forensicReport.hasSuspiciousStreams
                ? `Tokens: ${forensicReport.suspiciousKeywordsFound.slice(0, 2).join(', ')}`
                : 'Zero Suspicious Macros'}
            </p>
            <p className="text-[10px] font-mono text-slate-400">
              {forensicReport.hasSuspiciousStreams
                ? 'Execution payload vectors found'
                : 'No executable script streams'}
            </p>
          </div>

          {/* Antivirus Vendor Intelligence */}
          <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-cyber-card space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-slate-400">Antivirus Vendors</span>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                  (forensicReport.vtMaliciousCount || 0) > 0
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {(forensicReport.vtMaliciousCount || 0) > 0 ? 'FLAGGED' : 'CLEAN'}
              </span>
            </div>
            <p
              className={`text-xs font-mono font-bold pt-1 ${
                (forensicReport.vtMaliciousCount || 0) > 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {forensicReport.vtDetectionRatio || '0 / 72 Antivirus Vendors'}
            </p>
            <p className="text-[10px] font-mono text-slate-400">
              {isVtActive && vtApiKey.trim() ? 'Live VirusTotal v3 verification' : 'Offline hash intel database'}
            </p>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            <div className="md:col-span-4 p-6 rounded-2xl bg-[#070C18] border border-slate-800 flex flex-col items-center justify-center text-center shadow-cyber-card">
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 mb-2">
                File Threat Score
              </span>
              <RiskGauge score={result.riskScore} size="lg" />
              <div className="mt-4 flex items-center space-x-2">
                <ThreatBadge category="Malicious File" />
                <SeverityBadge level={result.severity} />
              </div>
            </div>

            <div className="md:col-span-8 p-6 rounded-2xl bg-[#070C18] border border-slate-800 shadow-cyber-card flex flex-col justify-between">
              <div>
                <div className="pb-3 border-b border-slate-800 flex items-center justify-between mb-4">
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                    Static Binary Metadata Forensics
                  </h3>
                  <span
                    className={`text-xs font-mono font-bold ${
                      result.riskScore > 50 ? 'text-rose-400' : 'text-emerald-400'
                    }`}
                  >
                    Risk: {result.riskScore}/100 {result.severity}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Shannon Entropy</span>
                    <span
                      className={`font-bold mt-1 block ${
                        result.riskScore > 50 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {result.metadata?.entropy || `${forensicReport?.entropy || 4.12} / 8.0`}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Embedded Macros</span>
                    <span
                      className={`font-bold mt-1 block ${
                        forensicReport?.hasSuspiciousStreams ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {forensicReport?.hasSuspiciousStreams ? 'DETECTED' : 'Zero Found (Clean)'}
                    </span>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">AV Detections</span>
                    <span
                      className={`font-bold mt-1 block ${
                        (forensicReport?.vtMaliciousCount || 0) > 0 ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {result.metadata?.vtDetections || forensicReport?.vtDetectionRatio || '0 / 72 Clean'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400 truncate max-w-md">
                  Target: <strong className="text-cyan-300">{result.target}</strong>
                </span>
                <span className="text-slate-500 text-[11px]">
                  Format: {forensicReport?.actualType || 'Standard Document'}
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

      {/* Free VirusTotal API Modal */}
      {showApiModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4 overflow-y-auto">
          <div className="bg-[#0B1120] border border-slate-800 rounded-2xl max-w-lg w-full p-4 sm:p-6 space-y-4 sm:space-y-5 shadow-2xl my-auto animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/30">
                  <Key className="w-4 h-4" />
                </div>
                <h3 className="font-mono font-bold text-sm text-white">
                  VirusTotal Free API v3 Integration
                </h3>
              </div>
              <button
                onClick={() => setShowApiModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300">
              <p>
                <strong>VirusTotal v3</strong> is the industry-standard multi-engine antivirus platform. Integrating your free personal key allows CyberGuard to query real-time verdict telemetry from over <strong>70+ leading Antivirus vendors</strong> (CrowdStrike, Kaspersky, Microsoft Defender, Bitdefender, Sophos, etc.).
              </p>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <span className="font-mono font-bold text-[11px] text-cyan-300 flex items-center space-x-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                  <span>100% Free Tier Specifications</span>
                </span>
                <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px]">
                  <li>500 SHA-256 hash lookups per day (4 requests/minute)</li>
                  <li>Completely free forever — zero credit card required</li>
                  <li>Instant key generation on signup at VirusTotal</li>
                </ul>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  VirusTotal Personal API Key (64 hex characters):
                </label>
                <input
                  type="text"
                  placeholder="Paste your 64-character VirusTotal API key..."
                  value={vtApiKey}
                  onChange={(e) => setVtApiKey(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs focus:outline-none focus:border-rose-500 transition-colors"
                />
              </div>

              <div className="flex items-center justify-between text-[11px] font-mono pt-1">
                <a
                  href="https://www.virustotal.com/gui/my-apikey"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-rose-400 hover:text-rose-300 flex items-center space-x-1 underline"
                >
                  <span>Get your free VirusTotal key</span>
                  <ExternalLink className="w-3 h-3" />
                </a>

                <label className="flex items-center space-x-2 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={isVtActive}
                    onChange={(e) => setIsVtActive(e.target.checked)}
                    className="rounded bg-slate-950 border-slate-800 text-rose-500 focus:ring-0"
                  />
                  <span>Enable live API queries</span>
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setVtApiKey('');
                  localStorage.removeItem('CYBERGUARD_VT_KEY');
                  setShowApiModal(false);
                }}
                className="px-3 py-2 rounded-xl text-xs font-mono text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                Clear Key
              </button>
              <button
                type="button"
                onClick={() => {
                  localStorage.setItem('CYBERGUARD_VT_KEY', vtApiKey.trim());
                  localStorage.setItem('CYBERGUARD_VT_ACTIVE', isVtActive ? 'true' : 'false');
                  setShowApiModal(false);
                }}
                className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-rose-500 hover:bg-rose-400 text-white shadow-[0_0_15px_rgba(244,63,94,0.3)] transition-all flex items-center space-x-1.5"
              >
                <Check className="w-3.5 h-3.5" />
                <span>Save API Configuration</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
