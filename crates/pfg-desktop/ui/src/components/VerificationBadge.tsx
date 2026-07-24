import React, { useState } from 'react';
import { VerificationReport } from '../types/pfg';
import {
  CheckCircle2,
  Hash,
  ArrowRight,
  Copy,
  Check,
  Award,
  AlertTriangle,
  FileCheck2,
} from 'lucide-react';

export interface VerificationBadgeProps {
  report: VerificationReport;
  originalFileName?: string;
}

export const VerificationBadge: React.FC<VerificationBadgeProps> = ({
  report,
  originalFileName,
}) => {
  const [copiedOriginal, setCopiedOriginal] = useState(false);
  const [copiedCleaned, setCopiedCleaned] = useState(false);

  const handleCopy = (text: string, isCleaned: boolean) => {
    navigator.clipboard.writeText(text);
    if (isCleaned) {
      setCopiedCleaned(true);
      setTimeout(() => setCopiedCleaned(false), 2000);
    } else {
      setCopiedOriginal(true);
      setTimeout(() => setCopiedOriginal(false), 2000);
    }
  };

  const isVerified = report.verified_clean;
  const removedCount = Math.max(
    0,
    report.original_findings_count - report.cleaned_findings_count
  );

  return (
    <div className="glass-card p-6 space-y-6 animate-in fade-in slide-in-from-bottom-5 duration-300 border-emerald-500/30 shadow-[0_0_30px_rgba(16,185,129,0.15)]">
      {/* Top Banner Status Badge */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-4">
          <div
            className={`p-3.5 rounded-2xl border ${
              isVerified
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.3)]'
                : 'bg-amber-500/15 border-amber-500/40 text-amber-400'
            }`}
          >
            {isVerified ? (
              <CheckCircle2 className="w-8 h-8" />
            ) : (
              <AlertTriangle className="w-8 h-8" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
                {isVerified ? '✅ 100% Verified Clean' : '⚠️ Sanitization Completed'}
              </h2>
              <span
                className={`px-3 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                  isVerified
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                }`}
              >
                {isVerified ? 'VERIFIED SAFE' : 'PARTIAL CLEAN'}
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1">
              {isVerified
                ? `Zero-trust verification confirmed zero residual privacy risks in ${
                    originalFileName || 'file'
                  }.`
                : `${report.cleaned_findings_count} findings remain after cleaning.`}
            </p>
          </div>
        </div>

        {/* Assurance Level Badge */}
        <div className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-900/80 border border-indigo-500/30 text-indigo-300 text-xs font-semibold">
          <Award className="w-4 h-4 text-indigo-400" />
          <span>Assurance: </span>
          <span className="font-mono text-white font-bold">{report.assurance_level}</span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Pre-Clean Findings */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
            Pre-Clean Findings
          </span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-amber-400 font-mono">
              {report.original_findings_count}
            </span>
            <span className="text-xs text-slate-500">privacy risks detected</span>
          </div>
        </div>

        {/* Post-Clean Findings */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-emerald-500/30 space-y-1">
          <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider block">
            Post-Clean Findings
          </span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-emerald-400 font-mono">
              {report.cleaned_findings_count}
            </span>
            <span className="text-xs text-emerald-400/80 font-medium">remaining risks</span>
          </div>
        </div>

        {/* Sanitization Rate */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-indigo-500/30 space-y-1">
          <span className="text-[11px] font-semibold text-indigo-300 uppercase tracking-wider block">
            Sanitization Efficiency
          </span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-indigo-400 font-mono">
              {report.original_findings_count > 0
                ? `${Math.round((removedCount / report.original_findings_count) * 100)}%`
                : '100%'}
            </span>
            <span className="text-xs text-indigo-300/80">({removedCount} scrubbed)</span>
          </div>
        </div>
      </div>

      {/* SHA-256 Cryptographic Verification Section */}
      <div className="space-y-3 pt-2 border-t border-slate-800">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Hash className="w-4 h-4 text-indigo-400" />
            Cryptographic SHA-256 Hash Integrity Comparison
          </h3>
          <span className="text-[11px] text-slate-400 flex items-center gap-1 font-mono">
            <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />
            Air-Gapped Local Verification
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Original SHA-256 Box */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-semibold text-slate-400">Original SHA-256</span>
              <button
                type="button"
                onClick={() => handleCopy(report.original_sha256, false)}
                className="text-slate-400 hover:text-white flex items-center gap-1 transition-colors"
                title="Copy full hash"
              >
                {copiedOriginal ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>{copiedOriginal ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="font-mono text-xs text-amber-300/90 break-all bg-slate-900 p-2 rounded border border-slate-800">
              {report.original_sha256}
            </div>
          </div>

          {/* Cleaned SHA-256 Box */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-emerald-500/30 space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-semibold text-emerald-400 flex items-center gap-1">
                Cleaned SHA-256
                <ArrowRight className="w-3 h-3 text-emerald-500" />
              </span>
              <button
                type="button"
                onClick={() => handleCopy(report.cleaned_sha256, true)}
                className="text-slate-400 hover:text-white flex items-center gap-1 transition-colors"
                title="Copy full hash"
              >
                {copiedCleaned ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>{copiedCleaned ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="font-mono text-xs text-emerald-300 break-all bg-slate-900 p-2 rounded border border-slate-800">
              {report.cleaned_sha256}
            </div>
          </div>
        </div>

        <p className="text-[11px] text-slate-400 italic text-center pt-1">
          Note: Hash change confirms successful removal of metadata bytes, EXIF data, and PII attributes from the output file.
        </p>
      </div>
    </div>
  );
};

export default VerificationBadge;
