import React, { useState, useRef, useEffect } from 'react';
import { useCyberGuard } from '../../context/CyberGuardContext';
import {
  Bot,
  Send,
  X,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  ExternalLink,
  Key,
  RefreshCw,
  Trash2,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Zap
} from 'lucide-react';
import {
  queryGeminiCopilot,
  detectSuggestedAction,
  getStoredGeminiKey,
  setStoredGeminiKey,
  DEFAULT_GEMINI_KEY
} from '../../services/copilotService';

interface Message {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  source?: 'gemini' | 'offline_soc_knowledge';
  modelUsed?: string;
  actionButton?: {
    label: string;
    action: () => void;
  };
}

export const CyberCopilotDrawer: React.FC = () => {
  const {
    copilotOpen,
    setCopilotOpen,
    threats,
    incidents,
    selectedIncident,
    metrics,
    posture,
    setActiveTab,
    triggerLiveAttackDemo,
  } = useCyberGuard();

  const [input, setInput] = useState('');
  const [isThinking, setIsThinking] = useState(false);
  const [apiKey, setApiKey] = useState<string>(() => getStoredGeminiKey());
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [tempKey, setTempKey] = useState(apiKey);
  const [keySavedStatus, setKeySavedStatus] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'init-1',
      sender: 'assistant',
      text: `Hello Analyst. I am **CYBERGUARD COPILOT**, your AI Security Operations Center assistant powered by Google Gemini.\n\nCurrently monitoring **${metrics.protectedUsers.toLocaleString()} users** with **${metrics.threatsDetected} threats detected** today. How can I assist your investigation?`,
      timestamp: 'Just now',
      source: 'gemini',
      modelUsed: 'gemini-flash-lite',
    },
  ]);

  const quickPrompts = [
    'Explain Critical Threats',
    'Analyze Current Incident',
    'Show High-Risk Users',
    'Recommend SOAR Response',
    'Summarize Security Posture',
    'How does Phishing Detection work?',
  ];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (copilotOpen) {
      scrollToBottom();
    }
  }, [messages, copilotOpen, isThinking]);

  const handleSaveKey = () => {
    const clean = tempKey.trim() || DEFAULT_GEMINI_KEY;
    setApiKey(clean);
    setStoredGeminiKey(clean);
    setKeySavedStatus('Key saved successfully!');
    setTimeout(() => {
      setKeySavedStatus(null);
      setShowKeyModal(false);
    }, 1200);
  };

  const handleResetDefaultKey = () => {
    setTempKey(DEFAULT_GEMINI_KEY);
    setApiKey(DEFAULT_GEMINI_KEY);
    setStoredGeminiKey(DEFAULT_GEMINI_KEY);
    setKeySavedStatus('Reset to default Gemini key');
    setTimeout(() => {
      setKeySavedStatus(null);
    }, 1500);
  };

  const handleClearMessages = () => {
    setMessages([
      {
        id: `init-${Date.now()}`,
        sender: 'assistant',
        text: `Chat cleared. **CYBERGUARD COPILOT** ready for new queries. Active security score: **${metrics.securityScore}/100**.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        source: 'gemini',
      },
    ]);
  };

  const handleSend = async (textToSend?: string) => {
    const query = textToSend || input;
    if (!query.trim() || isThinking) return;

    const userMsg: Message = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: query.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsThinking(true);

    try {
      const result = await queryGeminiCopilot(
        query,
        {
          metrics,
          threats,
          incidents,
          selectedIncident,
          posture,
        },
        apiKey
      );

      const suggested = detectSuggestedAction(query, result.text);

      let actionButton: { label: string; action: () => void } | undefined = undefined;
      if (suggested) {
        actionButton = {
          label: suggested.label,
          action: () => {
            if (suggested.actionType === 'simulation') {
              triggerLiveAttackDemo(suggested.target);
            } else {
              setActiveTab(suggested.target);
              setCopilotOpen(false);
            }
          },
        };
      }

      const aiMsg: Message = {
        id: `ai-${Date.now()}`,
        sender: 'assistant',
        text: result.text,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        source: result.source,
        modelUsed: result.modelUsed,
        actionButton,
      };

      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      console.error('[CYBERGUARD] Copilot query error:', err);
      setMessages((prev) => [
        ...prev,
        {
          id: `ai-err-${Date.now()}`,
          sender: 'assistant',
          text: `### ⚠️ Copilot Warning\nEncountered an issue communicating with the AI model. Please verify your Gemini API key in settings.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          source: 'offline_soc_knowledge',
        },
      ]);
    } finally {
      setIsThinking(false);
    }
  };

  /**
   * Enhanced Markdown text renderer for beautiful, readable SOC analyst output
   */
  const renderFormattedContent = (content: string) => {
    const lines = content.split('\n');

    return (
      <div className="space-y-1.5 text-xs font-sans leading-relaxed">
        {lines.map((line, idx) => {
          const trimmed = line.trim();

          // Empty line
          if (!trimmed) {
            return <div key={idx} className="h-1.5" />;
          }

          // Headers: ### or ## or #
          if (trimmed.startsWith('### ')) {
            return (
              <h4 key={idx} className="text-sm font-bold text-cyan-300 font-mono flex items-center space-x-1.5 mt-2.5 mb-1">
                <span>{renderInlineFormatting(trimmed.replace(/^###\s+/, ''))}</span>
              </h4>
            );
          }
          if (trimmed.startsWith('## ')) {
            return (
              <h3 key={idx} className="text-sm font-bold text-white font-mono flex items-center space-x-1.5 mt-3 mb-1">
                <span>{renderInlineFormatting(trimmed.replace(/^##\s+/, ''))}</span>
              </h3>
            );
          }
          if (trimmed.startsWith('# ')) {
            return (
              <h2 key={idx} className="text-base font-bold text-white font-mono mt-3.5 mb-1">
                {renderInlineFormatting(trimmed.replace(/^#\s+/, ''))}
              </h2>
            );
          }

          // Blockquote: >
          if (trimmed.startsWith('>')) {
            return (
              <div
                key={idx}
                className="pl-3 py-1 my-1.5 border-l-2 border-cyan-400 bg-cyan-950/20 text-cyan-200/90 rounded-r text-[11px] font-mono italic"
              >
                {renderInlineFormatting(trimmed.replace(/^>\s*/, ''))}
              </div>
            );
          }

          // Bullet points: • or - or *
          if (trimmed.startsWith('• ') || trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
            const bulletText = trimmed.replace(/^([•\-\*]\s+)/, '');
            return (
              <div key={idx} className="flex items-start space-x-2 pl-1.5 my-1">
                <span className="text-cyan-400 font-bold select-none">•</span>
                <span className="flex-1 text-slate-200">{renderInlineFormatting(bulletText)}</span>
              </div>
            );
          }

          // Numbered lists: 1. or 2.
          const numberedMatch = trimmed.match(/^(\d+)\.\s+(.*)$/);
          if (numberedMatch) {
            return (
              <div key={idx} className="flex items-start space-x-2 pl-1.5 my-1">
                <span className="text-cyan-400 font-mono font-bold select-none text-[11px] min-w-[16px]">
                  {numberedMatch[1]}.
                </span>
                <span className="flex-1 text-slate-200">{renderInlineFormatting(numberedMatch[2])}</span>
              </div>
            );
          }

          // Standard paragraph
          return (
            <p key={idx} className="text-slate-200">
              {renderInlineFormatting(line)}
            </p>
          );
        })}
      </div>
    );
  };

  /**
   * Handles inline bold (**text**) and code (`text`) formatting
   */
  const renderInlineFormatting = (text: string): React.ReactNode => {
    // Split by code tags first
    const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);

    return parts.map((part, i) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code
            key={i}
            className="px-1.5 py-0.5 mx-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[11px] border border-slate-700 font-medium"
          >
            {part.slice(1, -1)}
          </code>
        );
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={i} className="font-semibold text-white">
            {part.slice(2, -2)}
          </strong>
        );
      }
      return part;
    });
  };

  if (!copilotOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] md:w-[540px] bg-[#070C18] border-l border-cyan-500/30 shadow-[-10px_0_40px_rgba(0,0,0,0.85)] flex flex-col animate-slide-up">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/90 flex items-center justify-between relative backdrop-blur-md">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-purple-600/20 border border-cyan-500/40 text-cyan-400 relative">
            <Bot className="w-5 h-5 animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-slate-950 animate-ping" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="font-mono text-sm font-bold text-white tracking-wide">
                CYBERGUARD COPILOT
              </h3>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 flex items-center space-x-1">
                <Sparkles className="w-2.5 h-2.5" />
                <span>Gemini 2.0 AI</span>
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans">
              Autonomous AI SOC Analyst & Threat Reasoning Assistant
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-1.5">
          {/* Key Settings Button */}
          <button
            onClick={() => setShowKeyModal(!showKeyModal)}
            title="Configure Gemini API Key"
            className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-cyan-300 border border-slate-700/60 transition-colors"
          >
            <Key className="w-3.5 h-3.5" />
          </button>

          {/* Clear Messages Button */}
          <button
            onClick={handleClearMessages}
            title="Clear Chat History"
            className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700/60 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          {/* Close Drawer Button */}
          <button
            onClick={() => setCopilotOpen(false)}
            className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700/60 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* API Key Configuration Popover */}
        {showKeyModal && (
          <div className="absolute top-full left-0 right-0 z-30 p-4 bg-slate-900 border-b border-cyan-500/30 shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-bold text-white flex items-center space-x-1.5">
                <Key className="w-3.5 h-3.5 text-cyan-400" />
                <span>Google Gemini API Configuration</span>
              </span>
              <button
                onClick={() => setShowKeyModal(false)}
                className="text-slate-400 hover:text-white text-xs"
              >
                ✕
              </button>
            </div>
            <p className="text-[11px] text-slate-400 mb-2.5 leading-relaxed">
              CyberGuard Copilot uses Google Gemini for dynamic cybersecurity analysis. Your API key is stored safely in your browser.
            </p>
            <div className="space-y-2">
              <input
                type="password"
                value={tempKey}
                onChange={(e) => setTempKey(e.target.value)}
                placeholder="Enter Gemini API Key (AQ.Ab8RN6...)"
                className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-xs font-mono text-cyan-200 focus:outline-none"
              />
              {keySavedStatus && (
                <div className="text-[11px] font-mono text-emerald-400 flex items-center space-x-1">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>{keySavedStatus}</span>
                </div>
              )}
              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={handleResetDefaultKey}
                  className="text-[10px] font-mono text-slate-400 hover:text-cyan-300 underline"
                >
                  Reset to Default Key
                </button>
                <button
                  type="button"
                  onClick={handleSaveKey}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-[0_0_10px_rgba(0,240,255,0.3)]"
                >
                  Save & Apply
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Quick Prompts Bar */}
      <div className="px-4 py-2 border-b border-slate-800/80 bg-slate-900/40 overflow-x-auto flex items-center space-x-2 scrollbar-none">
        {quickPrompts.map((prompt, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(prompt)}
            disabled={isThinking}
            className="px-2.5 py-1 rounded-full bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 text-[11px] font-mono whitespace-nowrap transition-all disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Messages Stream */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex flex-col ${
              msg.sender === 'user' ? 'items-end' : 'items-start'
            }`}
          >
            <div
              className={`max-w-[92%] p-3.5 rounded-2xl leading-relaxed ${
                msg.sender === 'user'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-tr-none font-medium shadow-lg'
                  : 'bg-slate-900/95 text-slate-200 border border-slate-800 rounded-tl-none shadow-md'
              }`}
            >
              {/* Message Header Badge for Assistant */}
              {msg.sender === 'assistant' && (
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 text-[10px] font-mono text-slate-400">
                  <div className="flex items-center space-x-1.5 text-cyan-400 font-semibold">
                    <Zap className="w-3 h-3 text-cyan-400" />
                    <span>CYBERGUARD AI</span>
                  </div>
                  {msg.modelUsed && (
                    <span className="text-slate-500 px-1.5 py-0.5 rounded bg-slate-800 text-[9px]">
                      {msg.modelUsed}
                    </span>
                  )}
                </div>
              )}

              {/* Message Body with Clean Formatting */}
              {msg.sender === 'assistant' ? (
                renderFormattedContent(msg.text)
              ) : (
                <div className="whitespace-pre-line text-xs font-sans">
                  {msg.text}
                </div>
              )}

              {/* Action Button */}
              {msg.actionButton && (
                <button
                  onClick={msg.actionButton.action}
                  className="mt-3 w-full py-2 px-3 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-mono text-xs font-semibold flex items-center justify-center space-x-2 transition-all shadow-[0_0_15px_rgba(0,240,255,0.1)] active:scale-[0.99]"
                >
                  <span>{msg.actionButton.label}</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <span className="text-[10px] text-slate-500 font-mono mt-1 px-1">
              {msg.timestamp}
            </span>
          </div>
        ))}

        {/* Thinking Indicator */}
        {isThinking && (
          <div className="flex flex-col items-start">
            <div className="p-3.5 rounded-2xl bg-slate-900/95 border border-cyan-500/30 rounded-tl-none text-slate-200 shadow-md max-w-[85%]">
              <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span className="animate-pulse">Copilot analyzing SOC telemetry & threat graph...</span>
              </div>
              <div className="mt-2 flex space-x-1">
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
            <span className="text-[10px] text-slate-500 font-mono mt-1 px-1">Thinking...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Field */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/95 backdrop-blur-md">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center space-x-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isThinking}
            placeholder={
              isThinking
                ? 'Copilot is formulating response...'
                : 'Ask Copilot anything (e.g. Explain SQL Injection, summarize threat posture)'
            }
            className="flex-1 bg-slate-900 border border-slate-800 focus:border-cyan-500 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none transition-colors disabled:opacity-50"
          />
          <button
            type="submit"
            className="p-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-all shadow-[0_0_15px_rgba(0,240,255,0.3)] disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={!input.trim() || isThinking}
            title="Send query to Copilot"
          >
            {isThinking ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </button>
        </form>
      </div>
    </div>
  );
};
