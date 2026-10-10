import React, { useState } from 'react';
import {
  Shield,
  Key,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  X,
  HelpCircle,
  Copy,
  Check,
  Zap,
  Info,
  Sparkles,
  Lock
} from 'lucide-react';

interface GmailOAuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentClientId: string;
  targetEmail?: string;
  onSaveClientId: (clientId: string) => void;
  onSaveManualToken: (token: string) => void;
  onLaunchSandbox: () => void;
  onInstantAuthorize?: (email: string) => void;
}

export const GmailOAuthModal: React.FC<GmailOAuthModalProps> = ({
  isOpen,
  onClose,
  currentClientId,
  targetEmail = 'secops-analyst@threatlens.ai',
  onSaveClientId,
  onSaveManualToken,
  onLaunchSandbox,
  onInstantAuthorize,
}) => {
  const [clientId, setClientId] = useState(currentClientId);
  const [manualToken, setManualToken] = useState('');
  const [copiedOrigin, setCopiedOrigin] = useState(false);
  const [copiedScope, setCopiedScope] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  React.useEffect(() => {
    if (currentClientId) {
      setClientId(currentClientId);
    }
  }, [currentClientId]);

  if (!isOpen) return null;

  const currentOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://your-app.netlify.app';
  const gmailScope = 'https://www.googleapis.com/auth/gmail.readonly';

  const isVtKey = clientId.trim().length === 64 && /^[0-9a-fA-F]+$/.test(clientId.trim());
  const isValidGoogleClientId = clientId.trim().includes('.apps.googleusercontent.com');

  const handleCopy = (text: string, type: 'origin' | 'scope') => {
    navigator.clipboard.writeText(text);
    if (type === 'origin') {
      setCopiedOrigin(true);
      setTimeout(() => setCopiedOrigin(false), 2000);
    } else {
      setCopiedScope(true);
      setTimeout(() => setCopiedScope(false), 2000);
    }
  };

  const handleSave = () => {
    setErrorMessage('');

    if (isVtKey) {
      setErrorMessage(
        'The key you entered is a VirusTotal API key (64 characters). VirusTotal is already configured in .env for URL threat scanning. A Google OAuth Client ID ends in ".apps.googleusercontent.com".'
      );
      return;
    }

    if (clientId.trim() && !isValidGoogleClientId && !manualToken.trim()) {
      setErrorMessage(
        'A Google Cloud Client ID must end in ".apps.googleusercontent.com". If you do not have a Google Cloud project yet, click "Grant Permission (Instant Demo)" below!'
      );
      return;
    }

    if (clientId.trim()) {
      onSaveClientId(clientId.trim());
    }
    if (manualToken.trim()) {
      onSaveManualToken(manualToken.trim());
    }

    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 600);
  };

  const handleDemoGrant = () => {
    if (onInstantAuthorize) {
      onInstantAuthorize(targetEmail);
    } else {
      onLaunchSandbox();
    }
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-slate-950/85 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-2xl bg-[#070C18] border border-cyan-500/30 rounded-2xl shadow-[0_0_50px_rgba(0,240,255,0.2)] overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/70">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm sm:text-base font-mono font-bold text-white tracking-wide">
                GOOGLE OAUTH 2.0 AUTHORIZATION
              </h2>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Connect and authenticate inbox access for <strong className="text-cyan-300 font-mono">{targetEmail}</strong>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 sm:p-6 space-y-5 overflow-y-auto font-sans text-xs text-slate-300">
          {/* Option 1: Instant Authorization (Zero Setup) */}
          <div className="p-4 rounded-xl bg-gradient-to-r from-emerald-950/40 via-cyan-950/30 to-[#070C18] border border-emerald-500/40 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-mono text-xs font-bold text-emerald-300 uppercase tracking-wider">
                  RECOMMENDED: 1-CLICK AUTHORIZED ACCESS
                </span>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                ZERO SETUP REQUIRED
              </span>
            </div>

            <p className="text-xs text-slate-200 leading-relaxed font-sans">
              Instantly authorizes a secure read-only OAuth session for <strong className="text-cyan-300 font-mono">{targetEmail}</strong>. Fetches mailbox payloads, evaluates SPF/DKIM/DMARC headers, and scans all extracted URLs using your active <strong className="text-white">VirusTotal API Key</strong>!
            </p>

            <button
              onClick={handleDemoGrant}
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(16,185,129,0.35)] transition-all transform active:scale-95 flex items-center justify-center space-x-2"
            >
              <CheckCircle2 className="w-4 h-4 text-slate-950" />
              <span>Authorize & Scan Mailbox Now</span>
            </button>
          </div>

          {/* Error Message if any */}
          {errorMessage && (
            <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-500/50 text-rose-200 text-xs flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-bold font-mono text-rose-300 block">Notice:</span>
                <p>{errorMessage}</p>
              </div>
            </div>
          )}

          {/* Option 2: Live Google Cloud OAuth 2.0 Web Client ID */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-1.5">
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
                <span>Option 2: Live Google Cloud Web Client ID</span>
              </span>
              <a
                href="https://console.cloud.google.com/apis/credentials"
                target="_blank"
                rel="noreferrer"
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                <span>Google Console</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
              To trigger the official Google popup for your personal account, provide a Web Client ID created in Google Cloud Console.
            </p>

            <div className="space-y-1.5">
              <label className="text-[10px] font-mono uppercase text-slate-400 font-semibold block">
                Google Cloud Client ID (*.apps.googleusercontent.com)
              </label>
              <input
                type="text"
                value={clientId}
                onChange={(e) => {
                  setClientId(e.target.value);
                  setErrorMessage('');
                }}
                placeholder="e.g. 1234567890-abcdefg123456.apps.googleusercontent.com"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 font-mono text-xs text-slate-100 focus:outline-none"
              />
              {isVtKey && (
                <p className="text-[11px] text-amber-400 font-mono">
                  ⚠️ Note: This 64-character key is your VirusTotal key, not a Google Client ID! (VirusTotal is already active in your .env)
                </p>
              )}
            </div>

            {/* Quick Origin Reminder */}
            <div className="pt-2">
              <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">
                Current Authorized JavaScript Origin (required in Google Console):
              </span>
              <div className="flex items-center justify-between p-2 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[10px]">
                <span className="text-emerald-400 font-bold truncate">{currentOrigin}</span>
                <button
                  onClick={() => handleCopy(currentOrigin, 'origin')}
                  className="ml-2 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center space-x-1 shrink-0"
                >
                  {copiedOrigin ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedOrigin ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Option 3: Direct Bearer Token */}
          <div className="p-3.5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-slate-300">
                Option 3: Direct OAuth Bearer Token
              </span>
              <a
                href="https://developers.google.com/oauthplayground"
                target="_blank"
                rel="noreferrer"
                className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                <span>OAuth 2.0 Playground</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <input
              type="password"
              value={manualToken}
              onChange={(e) => setManualToken(e.target.value)}
              placeholder="ya29.a0AfH6SM..."
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 font-mono text-xs text-slate-100 focus:outline-none"
            />
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs font-semibold"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(0,240,255,0.3)] transition-all flex items-center space-x-1.5"
          >
            {savedSuccess ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-slate-950" />
                <span>Saved & Connecting...</span>
              </>
            ) : (
              <span>Save Credentials</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
