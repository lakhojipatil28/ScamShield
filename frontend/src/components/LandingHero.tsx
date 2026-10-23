import { Shield, MessageSquare, Mail, Globe, Image as ImageIcon, Lock, Cpu, EyeOff } from 'lucide-react';

interface LandingHeroProps {
  onStartScan: (type?: 'text' | 'email' | 'url' | 'screenshot') => void;
}

export const LandingHero = ({ onStartScan }: LandingHeroProps) => {
  return (
    <div className="relative overflow-hidden border-b border-slate-800 bg-gradient-to-b from-slate-900/60 to-slate-950 py-12 px-4 sm:px-6 lg:px-8">
      {/* Background Accent Gradients */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-3/4 h-36 bg-cyan-500/10 blur-[120px] pointer-events-none" />
      <div className="absolute top-1/3 right-10 w-64 h-64 bg-indigo-500/10 blur-[140px] pointer-events-none" />

      <div className="max-w-5xl mx-auto text-center relative z-10">
        {/* Hackathon Badge */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-cyan-950/70 text-cyan-300 border border-cyan-800/80 mb-6">
          <Cpu className="h-3.5 w-3.5 text-cyan-400" />
          <span>PromptWar Hackathon — Build Beyond AI: Secure, Intelligent & Autonomous</span>
        </div>

        {/* Title */}
        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white mb-4">
          Pre-Emptive AI Defense Against{' '}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-indigo-400">
            Digital Scams & Fraud
          </span>
        </h1>

        {/* Subtitle */}
        <p className="max-w-3xl mx-auto text-base sm:text-lg text-slate-300 leading-relaxed mb-8">
          Analyze suspicious messages, phishing emails, fake job offers, deceptive URLs, and screenshots
          before you click, enter passwords, or transfer funds. Grounded in deterministic security rules
          and Google Gemini AI reasoning.
        </p>

        {/* Quick Action Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4 max-w-4xl mx-auto mb-8 text-left">
          <div
            onClick={() => onStartScan('text')}
            className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 hover:bg-slate-800/80 hover:border-cyan-500/50 cursor-pointer transition-all group"
          >
            <div className="p-2 rounded-lg bg-cyan-950/70 border border-cyan-800/60 w-fit mb-3 group-hover:bg-cyan-900/80 transition-colors">
              <MessageSquare className="h-5 w-5 text-cyan-400" />
            </div>
            <h2 className="text-sm font-semibold text-white mb-1">Suspicious SMS</h2>
            <p className="text-xs text-slate-400">OTP harvesting & bank impersonation alerts</p>
          </div>

          <div
            onClick={() => onStartScan('email')}
            className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 hover:bg-slate-800/80 hover:border-cyan-500/50 cursor-pointer transition-all group"
          >
            <div className="p-2 rounded-lg bg-indigo-950/70 border border-indigo-800/60 w-fit mb-3 group-hover:bg-indigo-900/80 transition-colors">
              <Mail className="h-5 w-5 text-indigo-400" />
            </div>
            <h2 className="text-sm font-semibold text-white mb-1">Fake Job / Email</h2>
            <p className="text-xs text-slate-400">Registration fees & telegram job traps</p>
          </div>

          <div
            onClick={() => onStartScan('url')}
            className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 hover:bg-slate-800/80 hover:border-cyan-500/50 cursor-pointer transition-all group"
          >
            <div className="p-2 rounded-lg bg-emerald-950/70 border border-emerald-800/60 w-fit mb-3 group-hover:bg-emerald-900/80 transition-colors">
              <Globe className="h-5 w-5 text-emerald-400" />
            </div>
            <h2 className="text-sm font-semibold text-white mb-1">Safe URL Check</h2>
            <p className="text-xs text-slate-400">Lookalike homographs, SSRF & open redirects</p>
          </div>

          <div
            onClick={() => onStartScan('screenshot')}
            className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 hover:bg-slate-800/80 hover:border-cyan-500/50 cursor-pointer transition-all group"
          >
            <div className="p-2 rounded-lg bg-purple-950/70 border border-purple-800/60 w-fit mb-3 group-hover:bg-purple-900/80 transition-colors">
              <ImageIcon className="h-5 w-5 text-purple-400" />
            </div>
            <h2 className="text-sm font-semibold text-white mb-1">Screenshot OCR</h2>
            <p className="text-xs text-slate-400">Multimodal Gemini vision text extraction</p>
          </div>
        </div>

        {/* Security & Privacy Assurance */}
        <div className="inline-flex flex-wrap items-center justify-center gap-4 text-xs text-slate-400 border border-slate-800/80 rounded-full px-5 py-2 bg-slate-900/40">
          <span className="flex items-center gap-1.5">
            <Lock className="h-3.5 w-3.5 text-cyan-400" />
            Zero-Credential Storage (OTPs & passwords redacted)
          </span>
          <span className="hidden sm:inline text-slate-700">•</span>
          <span className="flex items-center gap-1.5">
            <EyeOff className="h-3.5 w-3.5 text-indigo-400" />
            Safe URL Parsing (no outbound link crawling)
          </span>
          <span className="hidden sm:inline text-slate-700">•</span>
          <span className="flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5 text-emerald-400" />
            Anti-Prompt Injection Enforced
          </span>
        </div>
      </div>
    </div>
  );
};
