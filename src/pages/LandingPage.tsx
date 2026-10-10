import React from 'react';
import { useCyberGuard } from '../context/CyberGuardContext';
import {
  Shield,
  Zap,
  Radio,
  ArrowRight
} from 'lucide-react';

export const LandingPage: React.FC = () => {
  const { setActiveTab, triggerLiveAttackDemo } = useCyberGuard();

  return (
    <div className="min-h-[calc(100vh-4rem)] bg-[#030611] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200 relative overflow-hidden font-sans flex flex-col justify-center items-center">
      
      {/* Visual Ambient Canvas & Noise Shimmers */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(0,240,255,0.16),rgba(5,8,17,0))] pointer-events-none" />
      <div className="absolute top-[15%] left-[-10%] w-[600px] h-[600px] bg-cyan-600/12 rounded-full blur-[150px] pointer-events-none animate-pulse-slow" />
      <div className="absolute top-[35%] right-[-10%] w-[700px] h-[700px] bg-purple-600/12 rounded-full blur-[180px] pointer-events-none" />
      <div className="absolute bottom-[5%] left-[25%] w-[600px] h-[600px] bg-blue-600/10 rounded-full blur-[160px] pointer-events-none" />
      
      {/* Architectural Subtle Grid */}
      <div className="absolute inset-0 cyber-grid-bg opacity-40 pointer-events-none" />

      {/* =========================================================================
          HERO SECTION: Monumental Headline & Kinetic CTAs
          ========================================================================= */}
      <section className="relative z-10 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 sm:py-24 flex flex-col justify-center items-center text-center">
        
        {/* Main Monumental Headline */}
        <h1 className="text-6xl sm:text-8xl md:text-9xl lg:text-[9.5rem] font-mono font-black tracking-tight text-white leading-none select-none">
          THREAT LENS{' '}
          <span className="relative inline-block">
            <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 bg-clip-text text-transparent drop-shadow-[0_0_50px_rgba(0,240,255,0.4)]">
              AI
            </span>
            <span className="absolute -bottom-2 left-0 w-full h-[4px] sm:h-[6px] bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 rounded-full opacity-80" />
          </span>
        </h1>

        {/* Subheading / Tagline with Monospace Accents - Scaled Up */}
        <div className="mt-8 sm:mt-10 flex flex-wrap items-center justify-center gap-2 sm:gap-4 font-mono font-extrabold text-2xl sm:text-4xl lg:text-5xl tracking-widest select-none">
          <span className="text-cyan-400 drop-shadow-[0_0_20px_rgba(0,240,255,0.3)]">
            Detect.
          </span>
          <span className="text-slate-600 font-light">•</span>
          <span className="text-blue-400 drop-shadow-[0_0_20px_rgba(96,165,250,0.3)]">
            Explain.
          </span>
          <span className="text-slate-600 font-light">•</span>
          <span className="text-purple-400 drop-shadow-[0_0_20px_rgba(192,132,252,0.3)]">
            Respond.
          </span>
          <span className="text-slate-600 font-light">•</span>
          <span className="text-emerald-400 drop-shadow-[0_0_20px_rgba(52,211,153,0.3)]">
            Protect.
          </span>
        </div>

        {/* Scaled-up Paragraph Description */}
        <p className="mt-8 sm:mt-10 max-w-4xl lg:max-w-5xl mx-auto text-xl sm:text-2xl lg:text-3xl text-slate-300 font-sans font-normal leading-relaxed tracking-normal">
          An integrated AI-Powered Cybersecurity Operations Center (SOC) defending enterprise infrastructure against phishing, malicious websites, deepfakes, and network intrusions.
        </p>

        {/* Magnetic Action CTA Buttons - Prominent & Enlarged */}
        <div className="mt-12 sm:mt-16 flex flex-col sm:flex-row items-center justify-center gap-5 sm:gap-8 w-full max-w-2xl">
          <button
            onClick={() => setActiveTab('dashboard')}
            className="w-full sm:w-auto px-10 sm:px-12 py-5 sm:py-6 rounded-2xl bg-gradient-to-r from-cyan-400 via-cyan-500 to-blue-600 hover:from-cyan-300 hover:to-blue-500 text-slate-950 font-mono font-black text-sm sm:text-base lg:text-lg uppercase tracking-wider shadow-[0_0_40px_rgba(0,240,255,0.45)] transition-all transform hover:scale-[1.04] active:scale-[0.98] flex items-center justify-center space-x-3.5 group border border-cyan-300/50"
          >
            <Shield className="w-5 h-5 sm:w-6 sm:h-6 text-slate-950 group-hover:rotate-12 transition-transform" />
            <span>LAUNCH SECURITY CONSOLE</span>
            <ArrowRight className="w-5 h-5 sm:w-6 sm:h-6 text-slate-950 group-hover:translate-x-1.5 transition-transform" />
          </button>

          <button
            onClick={() => triggerLiveAttackDemo('scenario-phishing')}
            className="w-full sm:w-auto px-10 sm:px-12 py-5 sm:py-6 rounded-2xl bg-slate-900/90 hover:bg-slate-850 text-cyan-300 border-2 border-cyan-500/50 hover:border-cyan-400 font-mono font-black text-sm sm:text-base lg:text-lg uppercase tracking-wider shadow-[0_0_30px_rgba(0,0,0,0.7)] backdrop-blur-xl transition-all transform hover:scale-[1.04] active:scale-[0.98] flex items-center justify-center space-x-3.5 group"
          >
            <Zap className="w-5 h-5 sm:w-6 sm:h-6 text-cyan-400 fill-current group-hover:scale-110 transition-transform" />
            <span>RUN LIVE THREAT DEMO</span>
            <Radio className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400 animate-pulse" />
          </button>
        </div>

      </section>

    </div>
  );
};
