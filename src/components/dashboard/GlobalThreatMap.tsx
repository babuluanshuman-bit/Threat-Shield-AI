import React, { useState, useEffect } from 'react';
import {
  Shield,
  Radio,
  Zap,
  Globe,
  Activity,
  Terminal,
  Cpu,
  Crosshair,
  Lock,
  Server,
  Wifi,
  WifiOff,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Layers,
  Sparkles,
  ArrowRight
} from 'lucide-react';

interface DefenseNode {
  id: string;
  name: string;
  region: string;
  coordinates: { x: number; y: number }; // percentage on radar canvas
  ip: string;
  status: 'OPTIMAL' | 'ATTACK_SURGE' | 'SHIELDED' | 'ISOLATED';
  latency: number; // ms
  activeThreats: number;
  protocol: string;
  entropy: number;
  attackVector?: {
    id: string;
    sourceIp: string;
    origin: string;
    technique: string;
    payloadSnippet: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    targetService: string;
    confidence: number;
    soarAction: string;
  };
}

const GLOBAL_NODES: DefenseNode[] = [
  {
    id: 'frankfurt',
    name: 'Frankfurt Core Gateway',
    region: 'EU-CENTRAL-1',
    coordinates: { x: 52, y: 36 },
    ip: '194.26.29.112',
    status: 'ATTACK_SURGE',
    latency: 14,
    activeThreats: 3,
    protocol: 'HTTPS / TLS 1.3',
    entropy: 7.94,
    attackVector: {
      id: 'VEC-9902',
      sourceIp: '185.220.101.5',
      origin: 'Tor Exit / Bulletproof Proxy (DE)',
      technique: 'T1071.001 (Cobalt Strike C2 Beaconing)',
      payloadSnippet: '0x4D5A9000 0x03000000 /beacon.dll?id=8841 [PACKED]',
      severity: 'CRITICAL',
      targetService: 'Corporate Active Directory SSO',
      confidence: 99.2,
      soarAction: 'Perimeter BGP Null-Route + Token Revocation',
    },
  },
  {
    id: 'ashburn',
    name: 'Ashburn Cloud Fabric',
    region: 'US-EAST-1',
    coordinates: { x: 26, y: 40 },
    ip: '54.210.82.19',
    status: 'SHIELDED',
    latency: 19,
    activeThreats: 0,
    protocol: 'gRPC / QUIC',
    entropy: 3.12,
  },
  {
    id: 'tokyo',
    name: 'Tokyo FinTech Edge',
    region: 'AP-NORTHEAST-1',
    coordinates: { x: 82, y: 42 },
    ip: '13.112.44.8',
    status: 'OPTIMAL',
    latency: 22,
    activeThreats: 1,
    protocol: 'HTTP/2 TLS',
    entropy: 6.45,
    attackVector: {
      id: 'VEC-7714',
      sourceIp: '45.154.255.89',
      origin: 'Unallocated Autonomous System (AS-209)',
      technique: 'T1566.002 (Homoglyph Typosquat)',
      payloadSnippet: 'POST /v1/auth/login host:paypa1-update.asia',
      severity: 'HIGH',
      targetService: 'Payment Gateway API Cluster',
      confidence: 94.6,
      soarAction: 'DNS Sinkhole + WAF Regex Quarantine',
    },
  },
  {
    id: 'mumbai',
    name: 'Mumbai HyperEdge DC',
    region: 'AP-SOUTH-1',
    coordinates: { x: 68, y: 52 },
    ip: '13.233.109.21',
    status: 'OPTIMAL',
    latency: 16,
    activeThreats: 0,
    protocol: 'TCP / WireGuard',
    entropy: 2.89,
  },
  {
    id: 'saopaulo',
    name: 'São Paulo Transit Node',
    region: 'SA-EAST-1',
    coordinates: { x: 38, y: 72 },
    ip: '177.71.201.55',
    status: 'OPTIMAL',
    latency: 41,
    activeThreats: 0,
    protocol: 'BGP Anycast',
    entropy: 3.41,
  },
];

export const GlobalThreatMap: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<DefenseNode>(GLOBAL_NODES[0]);
  const [isSimulatingWave, setIsSimulatingWave] = useState(false);
  const [isCloaked, setIsCloaked] = useState(false);
  const [honeytokensCount, setHoneytokensCount] = useState(4);
  const [neutralizedMap, setNeutralizedMap] = useState<Record<string, boolean>>({});
  const [packetRate, setPacketRate] = useState(24810);
  const [radarDegrees, setRadarDegrees] = useState(0);

  // Radar sweep animation
  useEffect(() => {
    const radarInterval = setInterval(() => {
      setRadarDegrees((prev) => (prev + 3) % 360);
    }, 40);
    return () => clearInterval(radarInterval);
  }, []);

  // Fluctuating packet rate jitter
  useEffect(() => {
    const jitterInterval = setInterval(() => {
      const delta = Math.floor((Math.random() - 0.5) * 240);
      setPacketRate((prev) => Math.max(22000, Math.min(32000, prev + delta)));
    }, 1200);
    return () => clearInterval(jitterInterval);
  }, []);

  // Simulate APT Intrusion Wave
  const handleTriggerAptWave = () => {
    setIsSimulatingWave(true);
    // Switch to Frankfurt node
    setSelectedNode(GLOBAL_NODES[0]);
    // Reset neutralization for this vector
    setNeutralizedMap((prev) => ({ ...prev, [GLOBAL_NODES[0].attackVector?.id || '']: false }));

    setTimeout(() => {
      setIsSimulatingWave(false);
    }, 6000);
  };

  // Deploy Honeytoken Decoy
  const handleDeployHoneytoken = () => {
    setHoneytokensCount((prev) => prev + 1);
  };

  // Autonomous / Manual Neutralization
  const handleNeutralizeVector = (vectorId: string) => {
    setNeutralizedMap((prev) => ({ ...prev, [vectorId]: true }));
  };

  const isCurrentNeutralized = selectedNode.attackVector?.id
    ? !!neutralizedMap[selectedNode.attackVector.id]
    : false;

  return (
    <div className="relative rounded-2xl border border-slate-800 bg-[#070C18] p-5 shadow-cyber-card space-y-5 overflow-hidden">
      
      {/* Background Ambient Grid & Cyber Scanlines */}
      <div className="absolute inset-0 cyber-grid-bg opacity-30 pointer-events-none" />
      <div className="absolute -top-32 -right-32 w-80 h-80 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none" />
      <div className="absolute -bottom-32 -left-32 w-80 h-80 bg-purple-500/10 rounded-full blur-[100px] pointer-events-none" />

      {/* Header Bar */}
      <div className="relative flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="relative p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-blue-600/20 to-purple-500/20 border border-cyan-500/40 text-cyan-400 shadow-[0_0_20px_rgba(0,240,255,0.2)]">
            <Crosshair className="w-5 h-5 text-cyan-300 animate-spin-slow" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-sm sm:text-base font-mono font-extrabold tracking-wider text-white">
                Autonomous Global Threat Interceptor
              </h3>
              <span className="hidden sm:inline-block px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                SENTINEL-9 HUD
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Continuous multi-vector perimeter interception, real-time packet entropy analysis, and autonomous edge neutralization.
            </p>
          </div>
        </div>

        {/* Live Interception Ticker */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <div className="px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center space-x-2">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 text-[11px]">Ingest Velocity:</span>
            <span className="text-cyan-300 font-bold">{packetRate.toLocaleString()} p/s</span>
          </div>

          <div className="px-3 py-1.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center space-x-1.5">
            <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
            <span className="text-[11px] font-bold">SOAR ARMED (11ms)</span>
          </div>
        </div>
      </div>

      {/* Main Interactive Stage: Radar Mesh + Live Decompiler Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 relative">
        
        {/* Left 7 Cols: Interactive Orbital Radar Mesh Canvas */}
        <div className="lg:col-span-7 flex flex-col justify-between rounded-2xl bg-gradient-to-b from-[#050914] to-[#080E20] border border-slate-800/90 p-4 relative overflow-hidden min-h-[360px] sm:min-h-[400px]">
          
          {/* Radar HUD Top Telemetry Overlay */}
          <div className="relative z-10 flex items-center justify-between text-[11px] font-mono text-slate-400 pb-2 border-b border-slate-800/60">
            <div className="flex items-center space-x-2">
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-300 font-bold">ORBITAL DEFENSE MESH</span>
              <span className="text-slate-500 text-[10px]">| 5 EDGE NODES</span>
            </div>
            <div className="flex items-center space-x-3 text-[10px]">
              <span className="text-slate-500">AZIMUTH: <strong className="text-cyan-400">{radarDegrees.toString().padStart(3, '0')}°</strong></span>
              <span className="text-slate-500">PERIMETER: <strong className="text-emerald-400">{isCloaked ? 'CLOAKED' : 'ENGAGED'}</strong></span>
            </div>
          </div>

          {/* SVG Animated Radar Canvas */}
          <div className="relative w-full h-[260px] sm:h-[280px] my-3 flex items-center justify-center select-none">
            
            {/* SVG Coordinate Rings & Crosshairs */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <radialGradient id="radarSweepGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.15" />
                  <stop offset="70%" stopColor="#00f0ff" stopOpacity="0.04" />
                  <stop offset="100%" stopColor="#00f0ff" stopOpacity="0" />
                </radialGradient>
              </defs>

              {/* Concentric Circles */}
              <circle cx="50%" cy="50%" r="35%" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="3 3" />
              <circle cx="50%" cy="50%" r="65%" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
              <circle cx="50%" cy="50%" r="90%" fill="none" stroke="#334155" strokeWidth="1" opacity="0.6" />

              {/* Crosshair Lines */}
              <line x1="50%" y1="5%" x2="50%" y2="95%" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" />
              <line x1="5%" y1="50%" x2="95%" y2="50%" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" />

              {/* Animated Rotating Radar Sweep Ray */}
              <g style={{ transformOrigin: '50% 50%', transform: `rotate(${radarDegrees}deg)` }}>
                <line x1="50%" y1="50%" x2="50%" y2="5%" stroke="#00f0ff" strokeWidth="2" opacity="0.8" />
                <path d="M 50% 50% L 50% 5% A 45% 45% 0 0 1 75% 25% Z" fill="url(#radarSweepGrad)" />
              </g>

              {/* Dynamic Attack Vector Trajectory Lines */}
              {isSimulatingWave && !isCurrentNeutralized && (
                <line
                  x1="15%"
                  y1="15%"
                  x2={`${selectedNode.coordinates.x}%`}
                  y2={`${selectedNode.coordinates.y}%`}
                  stroke="#ef4444"
                  strokeWidth="2"
                  strokeDasharray="6 3"
                  className="animate-pulse"
                />
              )}

              {/* Inter-Node Mesh Interconnect Lines */}
              <line x1="26%" y1="40%" x2="52%" y2="36%" stroke="#00f0ff" strokeWidth="1" opacity="0.25" />
              <line x1="52%" y1="36%" x2="68%" y2="52%" stroke="#00f0ff" strokeWidth="1" opacity="0.25" />
              <line x1="68%" y1="52%" x2="82%" y2="42%" stroke="#00f0ff" strokeWidth="1" opacity="0.25" />
              <line x1="26%" y1="40%" x2="38%" y2="72%" stroke="#00f0ff" strokeWidth="1" opacity="0.25" />
            </svg>

            {/* Simulated Attacker Origin (Tor/Adversary Node) */}
            {isSimulatingWave && !isCurrentNeutralized && (
              <div
                className="absolute z-20 transition-all font-mono"
                style={{ left: '15%', top: '15%', transform: 'translate(-50%, -50%)' }}
              >
                <div className="relative group cursor-pointer">
                  <div className="w-8 h-8 rounded-full bg-rose-600/30 border border-rose-500/80 flex items-center justify-center animate-ping" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="w-3.5 h-3.5 rounded-full bg-rose-500" />
                  </div>
                  <div className="absolute left-9 top-0 px-2 py-1 rounded bg-rose-950/90 border border-rose-500/60 text-[9px] text-rose-300 font-bold whitespace-nowrap shadow-lg">
                    ⚡ APT-37 ADVERSARY BURST
                  </div>
                </div>
              </div>
            )}

            {/* Interactive Nodes On Radar Canvas */}
            {GLOBAL_NODES.map((node) => {
              const isSelected = selectedNode.id === node.id;
              const hasThreat = node.attackVector && !neutralizedMap[node.attackVector.id];

              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className="absolute z-20 cursor-pointer font-mono group"
                  style={{
                    left: `${node.coordinates.x}%`,
                    top: `${node.coordinates.y}%`,
                    transform: 'translate(-50%, -50%)',
                  }}
                >
                  <div className="relative flex items-center justify-center">
                    {/* Pulsing ring for active selection or threat */}
                    {hasThreat ? (
                      <div className="absolute w-10 h-10 rounded-full bg-rose-500/20 border border-rose-500/60 animate-ping pointer-events-none" />
                    ) : isSelected ? (
                      <div className="absolute w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-400/50 animate-pulse pointer-events-none" />
                    ) : null}

                    {/* Node Core Orb */}
                    <div
                      className={`w-6 h-6 rounded-full flex items-center justify-center border transition-transform transform group-hover:scale-125 ${
                        hasThreat
                          ? 'bg-rose-950 border-rose-500 text-rose-300 shadow-[0_0_15px_rgba(244,63,94,0.6)]'
                          : isSelected
                          ? 'bg-cyan-950 border-cyan-400 text-cyan-300 shadow-[0_0_15px_rgba(0,240,255,0.5)]'
                          : isCloaked
                          ? 'bg-purple-950 border-purple-400 text-purple-300'
                          : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-cyan-500/60 hover:text-cyan-300'
                      }`}
                    >
                      <Server className="w-3 h-3" />
                    </div>

                    {/* Node Callout Badge */}
                    <div
                      className={`absolute top-7 px-2 py-0.5 rounded text-[9px] font-bold whitespace-nowrap transition-all shadow-md pointer-events-none ${
                        isSelected
                          ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-300'
                          : 'bg-slate-900/90 border border-slate-800 text-slate-400 group-hover:text-slate-200'
                      }`}
                    >
                      {node.name.split(' ')[0]}
                      {hasThreat && <span className="ml-1 text-rose-400 font-extrabold">• ATTACK</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Interactive Defense Playbook Controls Toolbar */}
          <div className="relative z-10 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
            <div className="flex items-center gap-2">
              {/* Trigger Live APT Wave */}
              <button
                onClick={handleTriggerAptWave}
                disabled={isSimulatingWave}
                className={`px-3 py-1.5 rounded-xl border font-bold text-[11px] transition-all flex items-center space-x-1.5 ${
                  isSimulatingWave
                    ? 'bg-rose-500/20 border-rose-500 text-rose-300 animate-pulse'
                    : 'bg-slate-900 hover:bg-slate-850 border-slate-800 hover:border-rose-500/40 text-rose-300'
                }`}
              >
                <Zap className="w-3.5 h-3.5 fill-current" />
                <span>{isSimulatingWave ? 'INTRUSION PROBE FIRING...' : 'Simulate APT Wave'}</span>
              </button>

              {/* Deploy Honeytoken Decoy */}
              <button
                onClick={handleDeployHoneytoken}
                className="px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/40 text-cyan-300 text-[11px] font-bold transition-all flex items-center space-x-1.5"
              >
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span>Deploy Canary Decoy ({honeytokensCount})</span>
              </button>

              {/* Engage Subnet Cloaking */}
              <button
                onClick={() => setIsCloaked(!isCloaked)}
                className={`px-3 py-1.5 rounded-xl border text-[11px] font-bold transition-all flex items-center space-x-1.5 ${
                  isCloaked
                    ? 'bg-purple-500/20 border-purple-500 text-purple-300 shadow-[0_0_15px_rgba(168,85,247,0.3)]'
                    : 'bg-slate-900 hover:bg-slate-850 border-slate-800 text-slate-300'
                }`}
              >
                <Lock className="w-3.5 h-3.5 text-purple-400" />
                <span>{isCloaked ? 'Cloak Active' : 'Engage Cloak'}</span>
              </button>
            </div>

            <div className="text-[10px] text-slate-500">
              CLICK ANY NODE TO INSPECT TELEMETRY
            </div>
          </div>
        </div>

        {/* Right 5 Cols: Live Interception & Hex Decompiler Inspector */}
        <div className="lg:col-span-5 rounded-2xl bg-[#050914] border border-slate-800 p-4 flex flex-col justify-between space-y-4 font-mono">
          
          {/* Header of Inspector */}
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold uppercase tracking-wider text-white">
                Live Interceptor Inspector
              </span>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                selectedNode.attackVector && !isCurrentNeutralized
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}
            >
              {selectedNode.attackVector && !isCurrentNeutralized ? 'THREAT INTERCEPTED' : 'NODE PRISTINE'}
            </span>
          </div>

          {/* Node Metadata Grid */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Selected Node</span>
              <span className="font-bold text-white block mt-0.5 truncate">{selectedNode.name}</span>
              <span className="text-[10px] text-cyan-400 block mt-0.5">{selectedNode.ip}</span>
            </div>

            <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Round-Trip Latency</span>
              <span className="font-bold text-emerald-400 block mt-0.5">{selectedNode.latency} ms</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">{selectedNode.protocol}</span>
            </div>
          </div>

          {/* If Threat Exists on This Node */}
          {selectedNode.attackVector ? (
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-rose-400 flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                  <span>{selectedNode.attackVector.technique}</span>
                </span>
                <span className="text-[10px] text-slate-400">
                  Confidence: <strong className="text-white">{selectedNode.attackVector.confidence}%</strong>
                </span>
              </div>

              {/* Monospace Payload Hex Decompiler Stream */}
              <div className="p-2.5 rounded-lg bg-black/80 border border-slate-800/80 font-mono text-[10px] space-y-1 text-slate-300 break-all select-all">
                <div className="flex items-center justify-between text-slate-500 pb-1 border-b border-slate-900">
                  <span>RAW PAYLOAD DECOMPILER</span>
                  <span className="text-cyan-400">ENTROPY: {selectedNode.entropy}/8.0</span>
                </div>
                <div className="text-slate-400 leading-tight">
                  {selectedNode.attackVector.payloadSnippet}
                </div>
                <div className="text-[9px] text-slate-500 pt-0.5">
                  Origin: <span className="text-amber-300">{selectedNode.attackVector.origin}</span> ({selectedNode.attackVector.sourceIp})
                </div>
              </div>

              {/* Shannon Entropy Bar */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-slate-400">Cryptographic Entropy Packing:</span>
                  <span className="text-amber-400 font-bold">
                    {selectedNode.entropy > 6.0 ? 'Metamorphic Packing Detected' : 'Normal Text Flow'}
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${
                      selectedNode.entropy > 6.0 ? 'bg-gradient-to-r from-amber-400 to-rose-500' : 'bg-cyan-400'
                    }`}
                    style={{ width: `${(selectedNode.entropy / 8.0) * 100}%` }}
                  />
                </div>
              </div>

              {/* Action Button: Neutralize / Sinkhole */}
              <div className="pt-2 border-t border-slate-850 flex items-center justify-between gap-2">
                {isCurrentNeutralized ? (
                  <div className="w-full p-2 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-center text-xs font-bold flex items-center justify-center space-x-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>SOAR NEUTRALIZED • PERIMETER SINKHOLED</span>
                  </div>
                ) : (
                  <button
                    onClick={() => handleNeutralizeVector(selectedNode.attackVector!.id)}
                    className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-rose-600 via-rose-500 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(244,63,94,0.3)] transition-all transform hover:scale-[1.02] active:scale-[0.98] flex items-center justify-center space-x-2"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    <span>Execute SOAR Containment (Sinkhole IP)</span>
                  </button>
                )}
              </div>
            </div>
          ) : (
            /* Clean Node State */
            <div className="p-6 rounded-xl bg-slate-950/60 border border-slate-850 text-center space-y-2">
              <div className="w-10 h-10 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-400">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <h4 className="text-xs font-bold text-white uppercase">Perimeter Clear</h4>
              <p className="text-[11px] text-slate-400 font-sans">
                No adversary C2 or zero-day anomaly signatures detected on {selectedNode.region}. Honeytokens patrolling.
              </p>
              <div className="pt-2 text-[10px] text-cyan-400 font-mono">
                Shannon Entropy: {selectedNode.entropy}/8.0 [Clean Baseline]
              </div>
            </div>
          )}

          {/* Autonomous Response Micro-Audit Stamp */}
          <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-850 flex items-center justify-between text-[10px] text-slate-400">
            <span className="flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Decentralized Consensus Engine:</span>
            </span>
            <span className="text-cyan-300 font-bold">100% In-Memory Audit</span>
          </div>
        </div>

      </div>

    </div>
  );
};
