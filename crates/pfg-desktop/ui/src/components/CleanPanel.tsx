import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { CleanProfile, ScanReport, VerificationReport } from '../types/pfg';
import {
  Wand2,
  Shield,
  Lock,
  Sliders,
  Folder,
  Loader2,
  AlertCircle,
  Sparkles,
  Info,
} from 'lucide-react';

export interface CleanPanelProps {
  selectedFilePath: string;
  fileObj?: File | null;
  report?: ScanReport | null;
  onCleanSuccess: (report: VerificationReport) => void;
}

export const CleanPanel: React.FC<CleanPanelProps> = ({
  selectedFilePath,
  report,
  onCleanSuccess,
}) => {
  const [profile, setProfile] = useState<CleanProfile>('Balanced');
  const [safeName, setSafeName] = useState<boolean>(false);
  const [outputDir, setOutputDir] = useState<string>('');
  const [isCleaning, setIsCleaning] = useState<boolean>(false);
  const [cleanError, setCleanError] = useState<string | null>(null);

  const handleClean = async () => {
    if (!selectedFilePath || isCleaning) return;

    setIsCleaning(true);
    setCleanError(null);

    const cleanOutputDir = outputDir.trim() ? outputDir.trim() : null;

    try {
      const res = await invoke<VerificationReport>('clean_file_cmd', {
        path: selectedFilePath,
        profile: profile,
        outputDir: cleanOutputDir,
        output_dir: cleanOutputDir,
        safeName: safeName,
        safe_name: safeName,
      });

      onCleanSuccess(res);
    } catch (err) {
      console.error('Tauri IPC clean_file_cmd error:', err);
      setCleanError(`Sanitization failed: ${typeof err === 'string' ? err : JSON.stringify(err)}`);
    } finally {
      setIsCleaning(false);
    }
  };

  return (
    <div className="glass-card p-6 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
            <Wand2 className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              Sanitization Settings
            </h3>
            <p className="text-xs text-slate-400">
              Configure metadata scrubbing profile and output options
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Target File:</span>
          <span className="text-xs font-mono text-indigo-300 bg-slate-900 px-2.5 py-1 rounded border border-slate-800 font-semibold truncate max-w-[200px]">
            {report?.input.display_name || selectedFilePath.split('/').pop() || selectedFilePath}
          </span>
        </div>
      </div>

      {cleanError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-3 animate-in fade-in duration-200">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold block">Sanitization Failed</span>
            <p>{cleanError}</p>
          </div>
        </div>
      )}

      {/* Profile Selector */}
      <div className="space-y-3">
        <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Sliders className="w-4 h-4 text-indigo-400" />
          Select Sanitization Profile
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Balanced Profile Card */}
          <button
            type="button"
            onClick={() => setProfile('Balanced')}
            className={`p-4 rounded-xl border text-left transition-all relative overflow-hidden ${
              profile === 'Balanced'
                ? 'bg-indigo-600/15 border-indigo-500 text-white shadow-lg shadow-indigo-500/10'
                : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold text-sm flex items-center gap-2">
                <Shield className="w-4 h-4 text-indigo-400" />
                Balanced Profile
              </span>
              {profile === 'Balanced' && (
                <span className="w-2 h-2 rounded-full bg-indigo-400 shadow-[0_0_8px_rgba(129,140,248,0.8)]" />
              )}
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Scrubs PII, location data, camera serials, author fields, and sensitive metadata.
              Preserves color profiles (`iCCP`) and physical dimensions (`pHYs`).
            </p>
          </button>

          {/* Strict Profile Card */}
          <button
            type="button"
            onClick={() => setProfile('Strict')}
            className={`p-4 rounded-xl border text-left transition-all relative overflow-hidden ${
              profile === 'Strict'
                ? 'bg-purple-600/15 border-purple-500 text-white shadow-lg shadow-purple-500/10'
                : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold text-sm flex items-center gap-2">
                <Lock className="w-4 h-4 text-purple-400" />
                Strict Profile
              </span>
              {profile === 'Strict' && (
                <span className="w-2 h-2 rounded-full bg-purple-400 shadow-[0_0_8px_rgba(192,132,252,0.8)]" />
              )}
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Purges all non-essential metadata, custom properties, comments, thumbnails, and annotations for maximum reduction.
            </p>
          </button>
        </div>
      </div>

      {/* Output Options */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-800">
        {/* Output Folder Option */}
        <div className="space-y-2">
          <label className="text-xs font-semibold text-slate-300 flex items-center gap-2">
            <Folder className="w-4 h-4 text-indigo-400" />
            Custom Output Directory (Optional)
          </label>
          <input
            type="text"
            value={outputDir}
            onChange={(e) => setOutputDir(e.target.value)}
            placeholder="Default: Same folder as original file"
            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 transition-colors font-mono"
          />
        </div>

        {/* Safe Name Option */}
        <div className="space-y-2">
          <label className="text-xs font-semibold text-slate-300 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-indigo-400" />
            Filename Anonymization
          </label>
          <button
            type="button"
            onClick={() => setSafeName(!safeName)}
            className={`w-full p-2.5 rounded-xl border text-xs font-medium flex items-center justify-between transition-colors ${
              safeName
                ? 'bg-indigo-600/10 border-indigo-500/40 text-indigo-300'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>Safe Hash Filename ({safeName ? 'Enabled' : 'Disabled'})</span>
            <span
              className={`w-4 h-4 rounded border flex items-center justify-center text-[10px] ${
                safeName ? 'bg-indigo-600 border-indigo-500 text-white' : 'border-slate-700'
              }`}
            >
              {safeName ? '✓' : ''}
            </span>
          </button>
        </div>
      </div>

      {/* Clean Button Action */}
      <div className="pt-4 border-t border-slate-800 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Info className="w-4 h-4 text-indigo-400 shrink-0" />
          <span>Post-cleaning verification will re-audit output file before finalizing.</span>
        </div>

        <button
          type="button"
          onClick={handleClean}
          disabled={isCleaning}
          className="px-6 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold text-xs uppercase tracking-wider shadow-lg shadow-indigo-600/25 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-all shrink-0"
        >
          {isCleaning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Sanitizing File...</span>
            </>
          ) : (
            <>
              <Wand2 className="w-4 h-4" />
              <span>Clean File</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};

export default CleanPanel;
