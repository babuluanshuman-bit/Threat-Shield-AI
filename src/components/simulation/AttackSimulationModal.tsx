import React, { useState, useEffect } from 'react';
import { useCyberGuard } from '../../context/CyberGuardContext';
import { ATTACK_SCENARIOS } from '../../data/attackScenarios';
import { AttackScenario, AttackSimulationStep } from '../../types/cyberguard';
import { RiskGauge } from '../common/RiskGauge';
import {
  Play,
  Pause,
  SkipForward,
  RotateCcw,
  X,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Terminal,
  Zap,
  ExternalLink,
  MessageSquare
} from 'lucide-react';
import confetti from 'canvas-confetti';

export const AttackSimulationModal: React.FC = () => {
  const {
    simulationModalOpen,
    setSimulationModalOpen,
    activeScenarioId,
    setActiveScenarioId,
    ingestNewThreat,
    executeSOAR,
    setSelectedIncident,
    setActiveTab,
    setCopilotOpen,
  } = useCyberGuard();

  const currentScenario =
    ATTACK_SCENARIOS.find((s) => s.id === activeScenarioId) || ATTACK_SCENARIOS[0];

  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [completed, setCompleted] = useState<boolean>(false);

  // Reset steps when scenario changes or modal opens
  useEffect(() => {
    if (simulationModalOpen) {
      setCurrentStepIndex(0);
      setCompleted(false);
      setIsPlaying(false);
    }
  }, [simulationModalOpen, activeScenarioId]);

  // Auto-play timer
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    if (isPlaying && !completed) {
      timer = setTimeout(() => {
        if (currentStepIndex < currentScenario.steps.length - 1) {
          setCurrentStepIndex((prev) => prev + 1);
        } else {
          setIsPlaying(false);
          setCompleted(true);
          handleSimulationEnd();
        }
      }, 1500);
    }
    return () => clearTimeout(timer);
  }, [isPlaying, currentStepIndex, completed, currentScenario]);

  const handleNextStep = () => {
    if (currentStepIndex < currentScenario.steps.length - 1) {
      setCurrentStepIndex((prev) => prev + 1);
    } else {
      setCompleted(true);
      handleSimulationEnd();
    }
  };

  const handleReset = () => {
    setCurrentStepIndex(0);
    setCompleted(false);
    setIsPlaying(false);
  };

  const handleSimulationEnd = () => {
    // Ingest threat and auto-trigger SOAR containment
    ingestNewThreat(currentScenario.resultingThreat);
    const inc = executeSOAR(currentScenario.resultingThreat);

    try {
      confetti({
        particleCount: 60,
        spread: 70,
        origin: { y: 0.6 },
        colors: ['#00F0FF', '#3B82F6', '#10B981'],
      });
    } catch (e) {
      // ignore
    }
  };

  const handleOpenIncident = () => {
    setSelectedIncident(currentScenario.resultingIncident);
    setSimulationModalOpen(false);
    setActiveTab('dashboard');
  };

  const handleAskCopilot = () => {
    setSimulationModalOpen(false);
    setCopilotOpen(true);
  };

  if (!simulationModalOpen) return null;

  const currentStep = currentScenario.steps[currentStepIndex];
  const progressPercent = Math.round(
    ((currentStepIndex + 1) / currentScenario.steps.length) * 100
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-slate-950/85 backdrop-blur-md animate-fade-in overflow-y-auto">
      <div className="relative w-full max-w-5xl my-auto max-h-[95vh] sm:max-h-[90vh] flex flex-col rounded-2xl border border-cyan-500/30 bg-[#0B1120] shadow-[0_0_50px_rgba(0,240,255,0.2)] overflow-hidden">
        {/* Top Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 text-cyan-400">
              <Zap className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="font-mono text-base font-bold text-white tracking-wide">
                  CYBERGUARD ATTACK SIMULATOR
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  LIVE JUDGE DEMONSTRATION
                </span>
              </div>
              <p className="text-xs text-slate-400">
                End-to-end autonomous threat lifecycle: Ingest → AI Detection → Explainable Risk → SOAR Containment
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setSimulationModalOpen(false)}
              className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Scenario Selector Tabs */}
        <div className="flex items-center space-x-2 px-6 py-2.5 overflow-x-auto border-b border-slate-800/80 bg-slate-900/50 scrollbar-none">
          <span className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider shrink-0 mr-2">
            Scenario:
          </span>
          {ATTACK_SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => {
                setActiveScenarioId(s.id);
                setCurrentStepIndex(0);
                setCompleted(false);
                setIsPlaying(false);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium whitespace-nowrap transition-all ${
                activeScenarioId === s.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(0,240,255,0.25)]'
                  : 'bg-slate-800/50 hover:bg-slate-800 text-slate-400 border border-transparent'
              }`}
            >
              {s.name}
            </button>
          ))}
        </div>

        {/* Main Content Body */}
        <div className="flex-1 overflow-y-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Pipeline Stepper & Payload */}
          <div className="lg:col-span-7 space-y-5">
            {/* Scenario Description Card */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-bold text-cyan-400 uppercase">
                  Simulated Threat Vector
                </span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {currentScenario.category}
                </span>
              </div>
              <p className="text-xs text-slate-300 font-sans leading-relaxed">
                {currentScenario.description}
              </p>

              {/* Initial Payload Box */}
              <div className="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs space-y-1">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider flex items-center">
                  <Terminal className="w-3 h-3 mr-1 text-cyan-400" />
                  Inbound Data Payload
                </div>
                {Object.entries(currentScenario.initialPayload).map(([key, val]) => (
                  <div key={key} className="text-slate-300 truncate">
                    <span className="text-slate-500">{key}: </span>
                    <span className="text-cyan-300">{String(val)}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Stepper Progress Pipeline */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                  Real-Time Detection & Response Pipeline
                </h4>
                <span className="text-xs font-mono text-cyan-400">
                  Step {currentStepIndex + 1} of {currentScenario.steps.length} ({progressPercent}%)
                </span>
              </div>

              {/* Progress Bar */}
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-300"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>

              {/* Steps Vertical Stream */}
              <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2">
                {currentScenario.steps.map((step, idx) => {
                  const isCurrent = idx === currentStepIndex;
                  const isPast = idx < currentStepIndex;

                  return (
                    <div
                      key={step.id}
                      className={`p-3 rounded-lg border transition-all ${
                        isCurrent
                          ? 'bg-cyan-500/10 border-cyan-500/40 shadow-[0_0_15px_rgba(0,240,255,0.15)] translate-x-1'
                          : isPast
                          ? 'bg-slate-900/40 border-slate-800 text-slate-400'
                          : 'bg-slate-950/40 border-slate-900 text-slate-600 opacity-60'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2.5">
                          {isPast ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                          ) : isCurrent ? (
                            <div className="w-4 h-4 rounded-full bg-cyan-400 animate-ping shrink-0" />
                          ) : (
                            <div className="w-4 h-4 rounded-full border border-slate-700 flex items-center justify-center text-[10px] text-slate-500 shrink-0">
                              {idx + 1}
                            </div>
                          )}
                          <span
                            className={`font-mono text-xs font-bold ${
                              isCurrent
                                ? 'text-white'
                                : isPast
                                ? 'text-slate-300'
                                : 'text-slate-500'
                            }`}
                          >
                            {step.title}
                          </span>
                        </div>
                        <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400">
                          {step.phase}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-slate-400 font-sans pl-6">
                        {step.description}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Column: Live Risk Gauge & Containment Outcome */}
          <div className="lg:col-span-5 flex flex-col justify-between space-y-4">
            {/* Live Risk Evaluation Card */}
            <div className="p-5 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 flex flex-col items-center justify-center text-center">
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 mb-2">
                CyberGuard Unified Risk Engine
              </span>
              <RiskGauge
                score={
                  currentStepIndex >= 4
                    ? currentScenario.resultingThreat.riskScore
                    : Math.min(65, (currentStepIndex + 1) * 15)
                }
                size="md"
                subtext="Multi-Signal Composite Threat Index"
              />

              {/* Indicators Preview */}
              {currentStepIndex >= 4 && (
                <div className="w-full mt-4 p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-left space-y-1.5 animate-fade-in font-mono text-[11px]">
                  <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-1">
                    Explainable Indicators:
                  </div>
                  {currentScenario.resultingThreat.indicators.slice(0, 3).map((ind, i) => (
                    <div key={i} className="flex items-center justify-between text-slate-300">
                      <span className="truncate pr-2">• {ind.name}</span>
                      <span className="text-rose-400 font-bold shrink-0">+{ind.impact}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Post-Containment Success Banner */}
            {completed && (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-3 animate-fade-in">
                <div className="flex items-center space-x-2 text-emerald-400">
                  <ShieldCheck className="w-5 h-5 shrink-0" />
                  <span className="font-mono text-xs font-bold uppercase tracking-wider">
                    Threat Neutralized & Contained
                  </span>
                </div>
                <p className="text-xs text-emerald-200/90 font-sans leading-relaxed">
                  Autonomous SOAR playbook contained the attack. Incident{' '}
                  <span className="font-mono font-bold text-white underline">
                    {currentScenario.resultingIncident.id}
                  </span>{' '}
                  has been created in the Incident Center.
                </p>

                <div className="flex items-center space-x-2 pt-1">
                  <button
                    onClick={handleOpenIncident}
                    className="flex-1 py-2 px-3 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-xs flex items-center justify-center space-x-1.5 transition-colors shadow-lg"
                  >
                    <span>View Incident Ticket</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={handleAskCopilot}
                    className="py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 font-mono text-xs flex items-center space-x-1.5 transition-colors"
                  >
                    <MessageSquare className="w-3.5 h-3.5" />
                    <span>Explain in Copilot</span>
                  </button>
                </div>
              </div>
            )}

            {/* Simulation Controls */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
              <button
                onClick={handleReset}
                className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center space-x-1.5 transition-colors"
                title="Reset Simulation"
              >
                <RotateCcw className="w-4 h-4" />
                <span className="hidden sm:inline">Reset</span>
              </button>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setIsPlaying((prev) => !prev)}
                  disabled={completed}
                  className={`py-2 px-4 rounded-lg font-mono text-xs font-bold uppercase tracking-wider flex items-center space-x-2 transition-all ${
                    isPlaying
                      ? 'bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-[0_0_15px_rgba(245,158,11,0.35)]'
                      : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_20px_rgba(0,240,255,0.35)]'
                  } disabled:opacity-40`}
                >
                  {isPlaying ? (
                    <>
                      <Pause className="w-4 h-4 fill-current" />
                      <span>Pause</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-current" />
                      <span>Auto-Play</span>
                    </>
                  )}
                </button>

                <button
                  onClick={handleNextStep}
                  disabled={completed}
                  className="py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-mono text-xs flex items-center space-x-1.5 transition-colors disabled:opacity-40"
                  title="Step Forward"
                >
                  <span>Step</span>
                  <SkipForward className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
