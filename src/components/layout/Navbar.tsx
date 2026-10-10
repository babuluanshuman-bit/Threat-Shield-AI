import React from 'react';
import { useCyberGuard } from '../../context/CyberGuardContext';
import {
  Shield,
  Zap,
  Bell,
  Bot,
  Search,
  Command,
  LayoutDashboard,
  Home,
  Menu,
  X
} from 'lucide-react';

export const Navbar: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    unreadNotificationCount,
    setNotificationsOpen,
    copilotOpen,
    setCopilotOpen,
    setSearchOpen,
    triggerLiveAttackDemo,
    isDemoMode,
    toggleDemoMode,
    mobileSidebarOpen,
    setMobileSidebarOpen,
  } = useCyberGuard();

  return (
    <header className="sticky top-0 z-40 w-full h-16 bg-[#070C18]/95 backdrop-blur-md border-b border-slate-800 px-3 sm:px-6 flex items-center justify-between">
      {/* Left: Mobile Menu Toggle + Brand Identity */}
      <div className="flex items-center space-x-2.5 sm:space-x-4">
        {/* Mobile Sidebar Hamburger (only visible when in console view on < lg screens) */}
        {activeTab !== 'landing' && (
          <button
            onClick={() => setMobileSidebarOpen(!mobileSidebarOpen)}
            className="lg:hidden p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
            title="Toggle Navigation Menu"
            aria-label="Toggle Navigation Menu"
          >
            {mobileSidebarOpen ? <X className="w-5 h-5 text-cyan-400" /> : <Menu className="w-5 h-5" />}
          </button>
        )}

        <div
          onClick={() => setActiveTab('landing')}
          className="flex items-center space-x-2.5 sm:space-x-3 cursor-pointer group select-none"
        >
          <div className="relative shrink-0">
            <div className="w-8 h-8 sm:w-9 sm:h-9 rounded-xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-purple-600 p-[1px] shadow-[0_0_20px_rgba(0,240,255,0.4)] group-hover:shadow-[0_0_30px_rgba(0,240,255,0.7)] transition-all">
              <div className="w-full h-full bg-[#070C18] rounded-[11px] flex items-center justify-center text-cyan-400">
                <Shield className="w-4 h-4 sm:w-5 sm:h-5 fill-cyan-400/20" />
              </div>
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 w-2 sm:w-2.5 h-2 sm:h-2.5 rounded-full bg-emerald-400 ring-2 ring-[#070C18] animate-pulse" />
          </div>

          <div>
            <div className="flex items-center space-x-1.5 sm:space-x-2">
              <span className="font-mono text-sm sm:text-base font-extrabold tracking-wider text-white group-hover:text-cyan-300 transition-colors">
                THREAT LENS<span className="text-cyan-400"> AI</span>
              </span>
              <span className="hidden sm:inline-block px-1.5 py-0.2 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                SOC
              </span>
            </div>
            <p className="hidden md:block text-[10px] text-slate-400 font-mono tracking-tight">
              Detect. Explain. Respond. Protect.
            </p>
          </div>
        </div>

        {/* Telemetry Status indicator */}
        <div className="hidden xl:flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-slate-300">Autonomous SOC: <strong className="text-emerald-400 font-semibold">Active</strong></span>
        </div>
      </div>

      {/* Center: Search Trigger (Ctrl + K) */}
      <div className="hidden md:flex items-center max-w-xs w-full mx-3 lg:mx-4">
        <button
          onClick={() => setSearchOpen(true)}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded-xl bg-slate-900/90 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-400 transition-all shadow-inner"
        >
          <div className="flex items-center space-x-2">
            <Search className="w-3.5 h-3.5 text-cyan-400" />
            <span>Search telemetry, incidents...</span>
          </div>
          <kbd className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-400 flex items-center">
            <Command className="w-2.5 h-2.5 mr-0.5" /> K
          </kbd>
        </button>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center space-x-1.5 sm:space-x-2.5">
        {/* Mobile Search Button */}
        <button
          onClick={() => setSearchOpen(true)}
          className="md:hidden p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
          title="Search"
        >
          <Search className="w-4 h-4 text-cyan-400" />
        </button>

        {/* Toggle View: Console vs Landing */}
        {activeTab !== 'landing' ? (
          <button
            onClick={() => setActiveTab('landing')}
            className="hidden sm:flex items-center space-x-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-mono transition-colors"
          >
            <Home className="w-3.5 h-3.5 text-cyan-400" />
            <span>Landing</span>
          </button>
        ) : (
          <button
            onClick={() => setActiveTab('dashboard')}
            className="hidden sm:flex items-center space-x-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-medium transition-colors"
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>SOC Console</span>
          </button>
        )}

        {/* Demo Mode Toggle Badge */}
        <button
          onClick={toggleDemoMode}
          className={`hidden md:flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-mono font-semibold transition-all border ${
            isDemoMode
              ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
              : 'bg-slate-900 text-slate-400 border-slate-800'
          }`}
          title="Toggle Hackathon Demo Telemetry Mode"
        >
          <span>🎬 DEMO</span>
          <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-ping" />
        </button>

        {/* Run Live Attack Simulation */}
        <button
          onClick={() => triggerLiveAttackDemo('scenario-phishing')}
          className="flex items-center space-x-1.5 sm:space-x-2 px-2.5 sm:px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-mono font-extrabold text-[11px] sm:text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(0,240,255,0.4)] transition-all transform active:scale-95 whitespace-nowrap"
        >
          <Zap className="w-3.5 h-3.5 sm:w-4 sm:h-4 fill-slate-950 text-slate-950" />
          <span className="hidden sm:inline">RUN LIVE ATTACK DEMO</span>
          <span className="sm:hidden">ATTACK DEMO</span>
        </button>

        {/* Notifications Button */}
        <button
          onClick={() => setNotificationsOpen(true)}
          className="relative p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
          title="Security Notifications"
        >
          <Bell className="w-4 h-4 text-slate-300" />
          {unreadNotificationCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-white font-mono text-[9px] font-bold flex items-center justify-center animate-pulse">
              {unreadNotificationCount}
            </span>
          )}
        </button>

        {/* Cyber Copilot Button */}
        <button
          onClick={() => setCopilotOpen(!copilotOpen)}
          className={`flex items-center space-x-1.5 p-2 px-2.5 sm:px-3 rounded-xl border transition-all ${
            copilotOpen
              ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-[0_0_15px_rgba(0,240,255,0.3)]'
              : 'bg-slate-900 hover:bg-slate-850 text-slate-300 border-slate-800'
          }`}
          title="AI SOC Copilot"
        >
          <Bot className="w-4 h-4 text-cyan-400" />
          <span className="hidden xl:inline text-xs font-mono font-semibold">COPILOT</span>
        </button>
      </div>
    </header>
  );
};
