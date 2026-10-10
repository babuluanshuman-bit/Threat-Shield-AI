import React from 'react';
import { useCyberGuard } from '../../context/CyberGuardContext';
import {
  LayoutDashboard,
  Globe,
  Mail,
  Smartphone,
  Image as ImageIcon,
  Network,
  FileCode,
  X,
  Shield
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    metrics,
    mobileSidebarOpen,
    setMobileSidebarOpen,
  } = useCyberGuard();

  const commandCenterItems = [
    { id: 'dashboard', label: 'SOC Command Center', icon: LayoutDashboard },
  ];

  const analyzerItems = [
    { id: 'url-scanner', label: 'URL & Website Analyzer', icon: Globe },
    { id: 'email-scanner', label: 'AI Email Phishing Scanner', icon: Mail },
    { id: 'message-scanner', label: 'SMS & WhatsApp Analyzer', icon: Smartphone },
    { id: 'media-scanner', label: 'Deepfake & AI Media Scanner', icon: ImageIcon },
    { id: 'network-threat', label: 'Network Threat Radar', icon: Network },
    { id: 'file-scanner', label: 'Malicious File Forensic', icon: FileCode },
  ];

  const handleItemClick = (id: string) => {
    setActiveTab(id);
    setMobileSidebarOpen(false);
  };

  const renderNavContent = () => (
    <>
      <div className="p-3 space-y-6">
        {/* Section 1: Command Center */}
        <div>
          <div className="px-3 mb-2 flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
              Operations Center
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          </div>

          <nav className="space-y-1">
            {commandCenterItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => handleItemClick(item.id)}
                  className={`w-full flex items-center px-3 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-[0_0_15px_rgba(0,240,255,0.15)] translate-x-1'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span>{item.label}</span>
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Section 2: AI Threat Detectors */}
        <div>
          <div className="px-3 mb-2 flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
              Multi-Modal AI Analyzers
            </span>
          </div>

          <nav className="space-y-1">
            {analyzerItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => handleItemClick(item.id)}
                  className={`w-full flex items-center px-3 py-2 rounded-xl text-xs font-mono transition-all ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-[0_0_15px_rgba(0,240,255,0.15)] translate-x-1 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent font-medium'
                  }`}
                >
                  <div className="flex items-center space-x-2.5 truncate">
                    <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span className="truncate">{item.label}</span>
                  </div>
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Footer System Telemetry */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/60 m-2 rounded-xl border">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">SOC System Status</span>
          <span className="flex items-center text-[10px] font-mono text-emerald-400 font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse mr-1.5" />
            ONLINE
          </span>
        </div>
        <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
          <span>Protected Nodes:</span>
          <span className="text-slate-300 font-semibold">{metrics.protectedUsers.toLocaleString()}</span>
        </div>
      </div>
    </>
  );

  return (
    <>
      {/* Desktop Persistent Sidebar (Only visible on lg+ screens) */}
      <aside className="hidden lg:flex w-64 shrink-0 bg-[#070C18] border-r border-slate-800 flex-col justify-between h-[calc(100vh-4rem)] sticky top-16 select-none overflow-y-auto">
        {renderNavContent()}
      </aside>

      {/* Mobile & Tablet Slide-Over Drawer */}
      {mobileSidebarOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          {/* Backdrop overlay */}
          <div
            onClick={() => setMobileSidebarOpen(false)}
            className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm animate-fade-in"
          />

          {/* Slide-over panel */}
          <div className="fixed inset-y-0 left-0 w-72 max-w-[85vw] bg-[#070C18] border-r border-slate-800 shadow-2xl flex flex-col justify-between select-none overflow-y-auto animate-slide-up z-50">
            {/* Mobile Header with Brand & Close Button */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/90">
              <div className="flex items-center space-x-2">
                <Shield className="w-5 h-5 text-cyan-400 fill-cyan-400/20" />
                <span className="font-mono text-sm font-bold text-white tracking-wide">
                  CYBERGUARD<span className="text-cyan-400">.SOC</span>
                </span>
              </div>
              <button
                onClick={() => setMobileSidebarOpen(false)}
                className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
                title="Close Navigation"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Navigation Content */}
            <div className="flex-1 flex flex-col justify-between overflow-y-auto">
              {renderNavContent()}
            </div>
          </div>
        </div>
      )}
    </>
  );
};
