import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  FolderSearch,
  Sparkles,
  Files,
  ShieldCheck,
  AlertTriangle,
  XCircle,
  Eye,
  Loader2,
  Sliders,
  Filter,
  Layers,
  FileText,
  RefreshCw,
  FolderOpen
} from 'lucide-react';
import { BatchScanReport, BatchCleanReport, ScanReport, CleanProfile } from '../types/pfg';

export interface BatchDashboardProps {
  mode: 'single' | 'batch';
  onModeToggle: (mode: 'single' | 'batch') => void;
  onScanDirectory: (dirPath: string, recursive: boolean, jobs: number | null, ignorePatterns: string[]) => void;
  onCleanDirectory: (dirPath: string, recursive: boolean, jobs: number | null, profile: CleanProfile, inPlace: boolean) => void;
  isLoading: boolean;
  isCleaning: boolean;
  batchScanReport: BatchScanReport | null;
  batchCleanReport: BatchCleanReport | null;
  onInspectFile: (report: ScanReport, filePath: string) => void;
  error: string | null;
  onResetBatch?: () => void;
}

export const BatchDashboard: React.FC<BatchDashboardProps> = ({
  mode,
  onModeToggle,
  onScanDirectory,
  onCleanDirectory,
  isLoading,
  isCleaning,
  batchScanReport,
  batchCleanReport,
  onInspectFile,
  error,
  onResetBatch,
}) => {
  const [dirPath, setDirPath] = useState<string>('/home/user/documents/photos');
  const [recursive, setRecursive] = useState<boolean>(true);
  const [jobs, setJobs] = useState<number>(4);
  const [ignorePatternsStr, setIgnorePatternsStr] = useState<string>('*.tmp, .git, node_modules');
  const [profile, setProfile] = useState<CleanProfile>('Balanced');
  const [inPlace, setInPlace] = useState<boolean>(true);

  const handleBrowseFolder = async () => {
    try {
      const selected = await invoke<string | null>('select_folder_dialog_cmd');
      if (selected) {
        setDirPath(selected);
      }
    } catch (_e) {
      // Ignored
    }
  };

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!dirPath.trim() || isLoading || isCleaning) return;
    const ignorePatterns = ignorePatternsStr
      .split(',')
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    onScanDirectory(dirPath.trim(), recursive, jobs > 0 ? jobs : null, ignorePatterns);
  };

  const handleCleanSubmit = () => {
    if (!dirPath.trim() || isCleaning || isLoading) return;
    onCleanDirectory(dirPath.trim(), recursive, jobs > 0 ? jobs : null, profile, inPlace);
  };

  // Helper to determine status for a file in the scan report table
  const getFileStatus = (report: ScanReport) => {
    if (batchCleanReport) {
      const vReport = batchCleanReport.file_reports.find(
        (r) => r.original_sha256 === report.input.sha256
      );
      if (vReport) {
        return vReport.verified
          ? { label: 'Verified Clean', color: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' }
          : { label: 'Clean Failed', color: 'bg-red-500/20 text-red-300 border-red-500/30' };
      }
    }
    if (report.findings.length === 0) {
      return { label: 'Clean', color: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' };
    }
    if (report.summary.critical > 0) {
      return { label: `${report.findings.length} Critical Risk`, color: 'badge-critical' };
    }
    if (report.summary.high > 0) {
      return { label: `${report.findings.length} High Risk`, color: 'badge-high' };
    }
    return { label: `${report.findings.length} Findings`, color: 'badge-medium' };
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Controls: Mode Switcher & Mode Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 glass-card p-5">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-gradient-to-tr from-purple-600 to-indigo-600 shadow-md text-white">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              Batch Directory Privacy Scanner
            </h2>
            <p className="text-xs text-slate-400">
              Bulk analyze directories recursively, aggregate privacy risks, and sanitize entire document sets.
            </p>
          </div>
        </div>

        {/* Mode Switcher Tabs */}
        <div className="inline-flex p-1 bg-slate-900/80 rounded-xl border border-slate-800 self-stretch md:self-auto">
          <button
            type="button"
            onClick={() => onModeToggle('single')}
            className={`flex-1 md:flex-none px-4 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
              mode === 'single'
                ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <FileText className="w-4 h-4" />
            Single File Mode
          </button>
          <button
            type="button"
            onClick={() => onModeToggle('batch')}
            className={`flex-1 md:flex-none px-4 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
              mode === 'batch'
                ? 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-md shadow-purple-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <FolderSearch className="w-4 h-4" />
            Batch Directory Mode
          </button>
        </div>
      </div>

      {/* Directory Scan Input & Options Panel */}
      <section className="glass-card p-6 space-y-6">
        <form onSubmit={handleScanSubmit} className="space-y-4">
          <div className="flex flex-col md:flex-row gap-3 items-stretch">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                <FolderOpen className="w-5 h-5" />
              </div>
              <input
                type="text"
                value={dirPath}
                onChange={(e) => setDirPath(e.target.value)}
                placeholder="/path/to/target/directory"
                className="w-full pl-11 pr-4 py-3 bg-slate-950/80 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
                disabled={isLoading || isCleaning}
              />
            </div>

            <button
              type="button"
              onClick={handleBrowseFolder}
              disabled={isLoading || isCleaning}
              className="btn-secondary py-3 px-4 text-xs font-semibold flex items-center justify-center gap-2 whitespace-nowrap text-slate-300 border-slate-700 hover:border-indigo-500/60"
            >
              <FolderOpen className="w-4 h-4 text-indigo-400" />
              <span>Browse Folder</span>
            </button>

            <div className="flex items-center gap-2">
              <button
                type="submit"
                disabled={isLoading || isCleaning || !dirPath.trim()}
                className="btn-primary py-3 px-6 text-sm font-semibold flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Scanning Directory...
                  </>
                ) : (
                  <>
                    <FolderSearch className="w-4 h-4" />
                    Scan Directory
                  </>
                )}
              </button>

              {batchScanReport && onResetBatch && (
                <button
                  type="button"
                  onClick={onResetBatch}
                  className="btn-secondary py-3 px-4 text-xs flex items-center gap-1.5"
                  title="Reset Batch Results"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Reset
                </button>
              )}
            </div>
          </div>

          {/* Config options grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2 border-t border-slate-800/80">
            <label className="flex items-center gap-2.5 cursor-pointer text-xs font-medium text-slate-300">
              <input
                type="checkbox"
                checked={recursive}
                onChange={(e) => setRecursive(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 bg-slate-900 text-indigo-600 focus:ring-indigo-500/50"
              />
              <span className="flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-indigo-400" />
                Recursive Subdirectories
              </span>
            </label>

            <label className="flex items-center gap-2 text-xs font-medium text-slate-300">
              <Sliders className="w-3.5 h-3.5 text-indigo-400" />
              <span>Parallel Workers:</span>
              <input
                type="number"
                min={1}
                max={32}
                value={jobs}
                onChange={(e) => setJobs(parseInt(e.target.value, 10) || 1)}
                className="w-16 px-2 py-1 bg-slate-900 border border-slate-700 rounded text-center text-xs font-mono font-bold text-indigo-300 focus:outline-none focus:border-indigo-500"
              />
            </label>

            <label className="flex items-center gap-2 text-xs font-medium text-slate-300 sm:col-span-2">
              <Filter className="w-3.5 h-3.5 text-indigo-400 flex-shrink-0" />
              <span className="flex-shrink-0">Ignore Patterns:</span>
              <input
                type="text"
                value={ignorePatternsStr}
                onChange={(e) => setIgnorePatternsStr(e.target.value)}
                placeholder="*.tmp, .git, node_modules"
                className="w-full px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </label>
          </div>
        </form>

        {error && (
          <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
            <span className="font-mono">{error}</span>
          </div>
        )}
      </section>

      {/* Summary Statistics Metrics Cards */}
      {batchScanReport && (
        <section className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Files Scanned */}
            <div className="glass-card p-5 space-y-2 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Files Scanned
                </span>
                <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
                  <Files className="w-5 h-5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-white font-mono">
                  {batchScanReport.files_scanned}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  ({batchScanReport.files_skipped} skipped)
                </span>
              </div>
              <p className="text-[11px] text-slate-400 truncate">
                Path: <span className="font-mono text-slate-300">{batchScanReport.target_path}</span>
              </p>
            </div>

            {/* Card 2: Total Findings */}
            <div className="glass-card p-5 space-y-2 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Total Findings
                </span>
                <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
                  <AlertTriangle className="w-5 h-5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-amber-400 font-mono">
                  {batchScanReport.total_findings}
                </span>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap">
                {batchScanReport.summary.critical > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                    {batchScanReport.summary.critical} Crit
                  </span>
                )}
                {batchScanReport.summary.high > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-300 border border-orange-500/30">
                    {batchScanReport.summary.high} High
                  </span>
                )}
                {batchScanReport.summary.medium > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    {batchScanReport.summary.medium} Med
                  </span>
                )}
              </div>
            </div>

            {/* Card 3: Verified Clean Count */}
            <div className="glass-card p-5 space-y-2 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Verified Clean
                </span>
                <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
                  <ShieldCheck className="w-5 h-5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-emerald-400 font-mono">
                  {batchCleanReport
                    ? batchCleanReport.verified_clean_count
                    : batchScanReport.reports.filter((r) => r.findings.length === 0).length}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  / {batchScanReport.files_scanned} files
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                {batchCleanReport ? 'Post-sanitization zero residue verified' : 'Pre-cleaning scan status'}
              </p>
            </div>

            {/* Card 4: Failed / Skipped Count */}
            <div className="glass-card p-5 space-y-2 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Failed / Skipped
                </span>
                <div className="p-2 rounded-lg bg-slate-800 text-slate-400">
                  <XCircle className="w-5 h-5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-300 font-mono">
                  {batchCleanReport
                    ? batchCleanReport.failed_files + batchCleanReport.skipped_files
                    : batchScanReport.files_skipped}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                {batchCleanReport
                  ? `${batchCleanReport.failed_files} failed, ${batchCleanReport.skipped_files} skipped`
                  : `${batchScanReport.files_skipped} ignored or unparseable`}
              </p>
            </div>
          </div>

          {/* Clean All Trigger Bar */}
          <div className="glass-card p-5 flex flex-col md:flex-row items-center justify-between gap-4 border border-indigo-500/30 bg-gradient-to-r from-slate-900/90 via-indigo-950/20 to-purple-950/20">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <Sparkles className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>Batch Directory Sanitization Trigger</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                    AIR-GAPPED
                  </span>
                </h3>
                <p className="text-xs text-slate-400">
                  Sanitize all metadata, EXIF GPS tags, author identities, and comments across all scanned files.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4 w-full md:w-auto">
              <div className="flex items-center gap-3 text-xs">
                <label className="flex items-center gap-1.5 text-slate-300">
                  <span>Profile:</span>
                  <select
                    value={profile}
                    onChange={(e) => setProfile(e.target.value as CleanProfile)}
                    className="px-2 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs font-semibold text-indigo-300 focus:outline-none focus:border-indigo-500"
                    disabled={isCleaning}
                  >
                    <option value="Balanced">Balanced (Standard EXIF/XMP)</option>
                    <option value="Strict">Strict (Full Scrub)</option>
                  </select>
                </label>

                <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={inPlace}
                    onChange={(e) => setInPlace(e.target.checked)}
                    className="w-3.5 h-3.5 rounded border-slate-700 bg-slate-900 text-indigo-600"
                    disabled={isCleaning}
                  />
                  <span>In-Place</span>
                </label>
              </div>

              <button
                type="button"
                onClick={handleCleanSubmit}
                disabled={isCleaning || isLoading || batchScanReport.total_findings === 0}
                className="btn-primary py-2.5 px-5 text-sm font-semibold flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/25 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isCleaning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Sanitizing Directory...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    Clean All Files ({batchScanReport.files_scanned})
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Scanned Files Table */}
          <div className="glass-card overflow-hidden space-y-3 p-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <FileText className="w-4 h-4 text-indigo-400" />
                Directory File Inventory ({batchScanReport.reports.length} Files)
              </h3>
              <span className="text-xs font-mono text-slate-400">
                Click "Inspect" to view detailed finding breakdown
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono tracking-wider text-[11px] bg-slate-900/60">
                    <th className="py-3 px-4 font-semibold">File Name / Path</th>
                    <th className="py-3 px-4 font-semibold">Format</th>
                    <th className="py-3 px-4 font-semibold">Findings</th>
                    <th className="py-3 px-4 font-semibold">Status</th>
                    <th className="py-3 px-4 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {(batchScanReport.file_results && batchScanReport.file_results.length > 0
                    ? batchScanReport.file_results.filter((res) => res.report !== null && res.report !== undefined)
                    : batchScanReport.reports.map((r) => ({ file_path: r.input.display_name, report: r }))
                  ).map((item, idx) => {
                    const fileReport = item.report!;
                    const filePath = item.file_path;
                    const status = getFileStatus(fileReport);
                    return (
                      <tr
                        key={`${filePath}-${idx}`}
                        className="hover:bg-slate-800/40 transition-colors group"
                      >
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <FileText className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                            <div>
                              <span className="font-semibold text-slate-100 block group-hover:text-indigo-300 transition-colors" title={filePath}>
                                {fileReport.input.display_name}
                              </span>
                              <span className="text-[10px] font-mono text-slate-500 block truncate max-w-xs">
                                {filePath}
                              </span>
                            </div>
                          </div>
                        </td>

                        <td className="py-3 px-4 font-mono">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-indigo-300 border border-slate-700 uppercase">
                            {fileReport.detected_format}
                          </span>
                        </td>

                        <td className="py-3 px-4 font-mono">
                          <div className="flex items-center gap-1.5">
                            <span className="font-bold text-slate-200">
                              {fileReport.findings.length}
                            </span>
                            {fileReport.summary.critical > 0 && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-500/20 text-red-300">
                                {fileReport.summary.critical} C
                              </span>
                            )}
                            {fileReport.summary.high > 0 && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-orange-500/20 text-orange-300">
                                {fileReport.summary.high} H
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-3 px-4">
                          <span className={`badge-severity ${status.color}`}>
                            {status.label}
                          </span>
                        </td>

                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => onInspectFile(fileReport, filePath)}
                            className="btn-secondary py-1.5 px-3 text-xs flex items-center justify-center gap-1 inline-flex hover:border-indigo-500/50 hover:text-indigo-300"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}
    </div>
  );
};

export default BatchDashboard;
