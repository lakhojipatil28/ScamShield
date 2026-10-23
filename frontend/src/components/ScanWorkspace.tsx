import { useState, useRef } from 'react';
import {
  MessageSquare,
  Mail,
  Globe,
  Upload,
  Sparkles,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  FileText,
  X,
} from 'lucide-react';
import type { ScanResponse, ScanType } from '../types';
import { scanText, scanEmail, scanUrl, scanScreenshot } from '../services/api';

interface ScanWorkspaceProps {
  initialScanType?: ScanType;
  onScanComplete: (result: ScanResponse) => void;
}

export const ScanWorkspace = ({
  initialScanType = 'text',
  onScanComplete,
}: ScanWorkspaceProps) => {
  const [activeTab, setActiveTab] = useState<ScanType>(initialScanType);
  const [isLoading, setIsLoading] = useState(false);
  const [progressStep, setProgressStep] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Form states
  const [textContent, setTextContent] = useState('');
  const [textContext, setTextContext] = useState('');

  const [emailSender, setEmailSender] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const [emailPlatform, setEmailPlatform] = useState('');

  const [urlInput, setUrlInput] = useState('');

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Quick Preset Samples for Hackathon Judges
  const loadPreset = (presetKey: string) => {
    setErrorMessage(null);
    switch (presetKey) {
      case 'otp_phishing':
        setActiveTab('text');
        setTextContent(
          'URGENT from Chase Bank: Your online banking account has been temporarily locked due to irregular login attempts from an unknown device in Russia. Text back your 6-digit one-time passcode (OTP) within 15 minutes to unlock your debit card.'
        );
        setTextContext('SMS from shortcode +1 (800) 555-0199');
        break;

      case 'legit_2fa':
        setActiveTab('text');
        setTextContent(
          'Your Google verification code is 842910. Never share this code with anyone. Google employees will never call or text you to request this verification code.'
        );
        setTextContext('Standard transactional 2FA push notice');
        break;

      case 'job_scam':
        setActiveTab('email');
        setEmailSender('hr-team@apex-logistics-recruiting.buzz');
        setEmailSubject('Official Job Offer: Remote Data Processing Associate ($850/Day)');
        setEmailBody(
          'Congratulations! Following our evaluation of your profile, you have been selected for the position of Remote Operations Associate at Apex Logistics Global.\n\nCompensation: $850 per day (approx. 2-3 hours of flexible work daily).\n\nTo begin onboarding and dispatch your pre-configured Apple MacBook M3 workstation, all new hires are required to remit a $150 refundable equipment handling deposit via Apple Gift Card or Bitcoin ATM. This deposit will be reimbursed on your first paycheck.\n\nPlease contact our hiring director directly on Telegram @ApexHiringDirector to finalize onboarding.'
        );
        setEmailPlatform('Received via unsolicited Gmail message');
        break;

      case 'irs_threat':
        setActiveTab('text');
        setTextContent(
          'FINAL WARNING: This is Senior Agent Davis from the Internal Revenue IRS. An active federal arrest warrant has been authorized for unpaid tax evasion. You are summoned to court. Contact our emergency duty desk immediately or local police officers will be dispatched to your current residence.'
        );
        setTextContext('Automated SMS threatening legal prosecution');
        break;

      case 'lookalike_url':
        setActiveTab('url');
        setUrlInput('http://paypa1.com/cgi-bin/webscr?cmd=_login-run&dispatch=verify');
        break;

      case 'ssrf_url':
        setActiveTab('url');
        setUrlInput('http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token');
        break;

      default:
        break;
    }
  };

  const handleFileSelect = (file: File) => {
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
      setErrorMessage('Unsupported file format. Please upload PNG, JPEG, or WebP images.');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setErrorMessage('File size exceeds the 5MB maximum limit.');
      return;
    }
    setErrorMessage(null);
    setSelectedFile(file);
    const objectUrl = URL.createObjectURL(file);
    setPreviewUrl(objectUrl);
  };

  const clearFile = () => {
    setSelectedFile(null);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setIsLoading(true);
    setProgressStep(1);

    const stepTimer = setInterval(() => {
      setProgressStep((prev) => (prev < 4 ? prev + 1 : prev));
    }, 400);

    try {
      let result: ScanResponse;

      if (activeTab === 'text') {
        if (!textContent.trim()) throw new Error('Please enter text content to analyze.');
        result = await scanText(textContent, textContext || undefined);
      } else if (activeTab === 'email') {
        if (!emailBody.trim()) throw new Error('Please enter the email body or job description.');
        result = await scanEmail(
          emailBody,
          emailSender || undefined,
          emailSubject || undefined,
          emailPlatform || undefined
        );
      } else if (activeTab === 'url') {
        if (!urlInput.trim()) throw new Error('Please enter a URL to inspect.');
        result = await scanUrl(urlInput.trim());
      } else if (activeTab === 'screenshot') {
        if (!selectedFile) throw new Error('Please upload an image screenshot.');
        result = await scanScreenshot(selectedFile);
      } else {
        throw new Error('Invalid scan type selected.');
      }

      clearInterval(stepTimer);
      setProgressStep(4);
      setTimeout(() => {
        setIsLoading(false);
        onScanComplete(result);
      }, 300);
    } catch (err: any) {
      clearInterval(stepTimer);
      setIsLoading(false);
      setProgressStep(0);
      setErrorMessage(err.message || 'An error occurred during scan.');
    }
  };

  const resetForm = () => {
    setTextContent('');
    setTextContext('');
    setEmailSender('');
    setEmailSubject('');
    setEmailBody('');
    setEmailPlatform('');
    setUrlInput('');
    clearFile();
    setErrorMessage(null);
    setProgressStep(0);
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      {/* Quick Test Demo Presets */}
      <div className="mb-6 p-4 rounded-xl border border-slate-800 bg-slate-900/50">
        <div className="flex items-center gap-2 mb-2.5">
          <Sparkles className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            One-Click Test Presets (Instant Hackathon Demo)
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => loadPreset('otp_phishing')}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-red-950/60 text-red-300 border border-red-800/60 hover:bg-red-900/80 transition-colors cursor-pointer"
          >
            Bank OTP Phishing
          </button>
          <button
            type="button"
            onClick={() => loadPreset('job_scam')}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-purple-950/60 text-purple-300 border border-purple-800/60 hover:bg-purple-900/80 transition-colors cursor-pointer"
          >
            Remote Job Upfront Fee
          </button>
          <button
            type="button"
            onClick={() => loadPreset('irs_threat')}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-amber-950/60 text-amber-300 border border-amber-800/60 hover:bg-amber-900/80 transition-colors cursor-pointer"
          >
            IRS Extortion / Arrest
          </button>
          <button
            type="button"
            onClick={() => loadPreset('lookalike_url')}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-indigo-950/60 text-indigo-300 border border-indigo-800/60 hover:bg-indigo-900/80 transition-colors cursor-pointer"
          >
            Typosquat Lookalike (paypa1.com)
          </button>
          <button
            type="button"
            onClick={() => loadPreset('ssrf_url')}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-rose-950/60 text-rose-300 border border-rose-800/60 hover:bg-rose-900/80 transition-colors cursor-pointer"
          >
            SSRF Metadata Probe
          </button>
          <button
            type="button"
            onClick={() => loadPreset('legit_2fa')}
            className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/80 transition-colors cursor-pointer"
          >
            Benign 2FA Code (Control)
          </button>
        </div>
      </div>

      {/* Main Workspace Card */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 shadow-2xl overflow-hidden backdrop-blur-sm">
        {/* Tab Selection */}
        <div className="flex border-b border-slate-800 bg-slate-950/60 p-2 gap-2 overflow-x-auto">
          <button
            type="button"
            onClick={() => {
              setActiveTab('text');
              setErrorMessage(null);
            }}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
              activeTab === 'text'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <MessageSquare className="h-4 w-4" />
            <span>Message / SMS</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('email');
              setErrorMessage(null);
            }}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
              activeTab === 'email'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <Mail className="h-4 w-4" />
            <span>Email / Job Offer</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('url');
              setErrorMessage(null);
            }}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
              activeTab === 'url'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <Globe className="h-4 w-4" />
            <span>URL Risk Analyzer</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('screenshot');
              setErrorMessage(null);
            }}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
              activeTab === 'screenshot'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
            }`}
          >
            <Upload className="h-4 w-4" />
            <span>Screenshot OCR</span>
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6">
          {/* Error Message Alert */}
          {errorMessage && (
            <div className="mb-6 p-4 rounded-xl bg-red-950/80 border border-red-800 text-red-200 flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
              <div className="text-sm">
                <p className="font-semibold text-red-300">Input Validation Alert</p>
                <p>{errorMessage}</p>
              </div>
            </div>
          )}

          {/* TAB 1: TEXT MESSAGE */}
          {activeTab === 'text' && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Suspicious Message Content <span className="text-cyan-400">*</span>
                </label>
                <textarea
                  value={textContent}
                  onChange={(e) => setTextContent(e.target.value)}
                  rows={6}
                  placeholder="Paste suspicious SMS, WhatsApp message, or direct message text here..."
                  className="w-full rounded-xl border border-slate-700 bg-slate-950/80 p-3.5 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
                  maxLength={25000}
                />
                <div className="flex justify-between items-center text-xs text-slate-500 mt-1">
                  <span>Sensitive details (OTPs, credit cards) will be automatically redacted before processing.</span>
                  <span>{textContent.length} / 25,000</span>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Context or Origin (Optional)
                </label>
                <input
                  type="text"
                  value={textContext}
                  onChange={(e) => setTextContext(e.target.value)}
                  placeholder="e.g. Unknown foreign number (+44), unsolicited iMessage, Telegram group"
                  className="w-full rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                />
              </div>
            </div>
          )}

          {/* TAB 2: EMAIL / JOB */}
          {activeTab === 'email' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">
                    Claimed Sender
                  </label>
                  <input
                    type="text"
                    value={emailSender}
                    onChange={(e) => setEmailSender(e.target.value)}
                    placeholder="e.g. hr@company-careers.top or Bank Alerts"
                    className="w-full rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">
                    Subject Line
                  </label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    placeholder="e.g. Immediate Action Required / Offer Letter"
                    className="w-full rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Email Body / Job Description <span className="text-cyan-400">*</span>
                </label>
                <textarea
                  value={emailBody}
                  onChange={(e) => setEmailBody(e.target.value)}
                  rows={7}
                  placeholder="Paste full email body or job posting details here..."
                  className="w-full rounded-xl border border-slate-700 bg-slate-950/80 p-3.5 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                  maxLength={50000}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Platform or Delivery Vector
                </label>
                <input
                  type="text"
                  value={emailPlatform}
                  onChange={(e) => setEmailPlatform(e.target.value)}
                  placeholder="e.g. Unsolicited LinkedIn InMail, Upwork invite, cold email"
                  className="w-full rounded-xl border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>
            </div>
          )}

          {/* TAB 3: URL SCANNER */}
          {activeTab === 'url' && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Web Address / URL to Inspect <span className="text-cyan-400">*</span>
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Globe className="h-5 w-5" />
                  </div>
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="https://example.com/login?redirect=..."
                    className="w-full rounded-xl border border-slate-700 bg-slate-950/80 pl-11 pr-4 py-3.5 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                  />
                </div>
                <p className="text-xs text-slate-400 mt-2">
                  Guaranteed safe: ScamShield performs offline syntactic and homograph inspection.
                  It will <strong className="text-slate-300">never</strong> browse, click, or issue server-side requests to the URL.
                </p>
              </div>
            </div>
          )}

          {/* TAB 4: SCREENSHOT OCR */}
          {activeTab === 'screenshot' && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Upload Screenshot of Suspicious Message or Ad <span className="text-cyan-400">*</span>
                </label>

                {!selectedFile ? (
                  <div
                    onClick={() => fileInputRef.current?.click()}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                        handleFileSelect(e.dataTransfer.files[0]);
                      }
                    }}
                    className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-2xl p-8 text-center cursor-pointer transition-all bg-slate-950/50 hover:bg-slate-900/40"
                  >
                    <div className="p-3 bg-slate-900 rounded-full w-fit mx-auto mb-3 border border-slate-800">
                      <Upload className="h-6 w-6 text-cyan-400" />
                    </div>
                    <p className="text-sm font-medium text-slate-200 mb-1">
                      Click to upload or drag & drop image
                    </p>
                    <p className="text-xs text-slate-500">
                      Supports PNG, JPEG, or WebP up to 5 MB
                    </p>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/png,image/jpeg,image/webp"
                      className="hidden"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          handleFileSelect(e.target.files[0]);
                        }
                      }}
                    />
                  </div>
                ) : (
                  <div className="relative rounded-2xl border border-slate-700 bg-slate-950/90 p-4">
                    <button
                      type="button"
                      onClick={clearFile}
                      className="absolute top-3 right-3 p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 transition-colors cursor-pointer"
                      title="Remove image"
                    >
                      <X className="h-4 w-4" />
                    </button>
                    <div className="flex items-center gap-4">
                      {previewUrl && (
                        <img
                          src={previewUrl}
                          alt="Screenshot preview"
                          className="h-24 w-32 object-cover rounded-lg border border-slate-800"
                        />
                      )}
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <FileText className="h-4 w-4 text-cyan-400" />
                          <span className="text-sm font-medium text-slate-200">{selectedFile.name}</span>
                        </div>
                        <p className="text-xs text-slate-400">
                          {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.type}
                        </p>
                        <p className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
                          <CheckCircle2 className="h-3.5 w-3.5" /> Ready for Gemini Multimodal OCR
                        </p>
                      </div>
                    </div>
                  </div>
                )}
                <p className="text-xs text-slate-400 mt-2">
                  Privacy guarantee: Uploaded image bytes are processed in-memory and discarded. Raw screenshots are never permanently stored.
                </p>
              </div>
            </div>
          )}

          {/* Investigation Progress Stages */}
          {isLoading && (
            <div className="mt-6 p-4 rounded-xl border border-cyan-800/60 bg-slate-950/80">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                  <Sparkles className="h-3.5 w-3.5 animate-spin" />
                  Bounded Security Workflow in Progress...
                </span>
                <span className="text-xs text-slate-400">Step {progressStep} of 4</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mb-3">
                <div
                  className="bg-gradient-to-r from-cyan-500 to-indigo-500 h-full transition-all duration-300"
                  style={{ width: `${(progressStep / 4) * 100}%` }}
                />
              </div>
              <div className="text-xs text-slate-300 space-y-1">
                <p className={progressStep >= 1 ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
                  ✓ 1. Validating input syntax & sanitizing sensitive credentials
                </p>
                <p className={progressStep >= 2 ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
                  ✓ 2. Executing deterministic rules (SSRF, lookalikes, OTP solicitation)
                </p>
                <p className={progressStep >= 3 ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
                  ✓ 3. Requesting structured Gemini AI threat assessment
                </p>
                <p className={progressStep >= 4 ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
                  ✓ 4. Reconciling corroboration matrix & building action plan
                </p>
              </div>
            </div>
          )}

          {/* Form Actions */}
          <div className="mt-8 flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={resetForm}
              disabled={isLoading}
              className="flex items-center gap-2 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Reset Inputs
            </button>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full sm:w-auto px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold text-sm shadow-lg shadow-cyan-500/25 transition-all flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Sparkles className="h-4 w-4 animate-spin" />
                  Analyzing Threat...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 fill-white" />
                  Analyze Threat Now
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
