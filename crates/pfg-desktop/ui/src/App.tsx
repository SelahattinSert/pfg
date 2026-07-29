import React, { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  ScanReport,
  VerificationReport,
  BatchScanReport,
  BatchCleanReport,
  CleanProfile,
} from './types/pfg';
import DropZone from './components/DropZone';
import FindingsList from './components/FindingsList';
import CleanPanel from './components/CleanPanel';
import VerificationBadge from './components/VerificationBadge';
import BatchDashboard from './components/BatchDashboard';
import {
  Shield,
  FileText,
  Hash,
  HardDrive,
  RefreshCw,
  Sparkles,
  CheckCircle2,
  FolderSearch,
} from 'lucide-react';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export const App: React.FC = () => {
  const [mode, setMode] = useState<'single' | 'batch'>('single');
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [selectedFileSize, setSelectedFileSize] = useState<number | null>(null);
  const [selectedFileObj, setSelectedFileObj] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isCleaningBatch, setIsCleaningBatch] = useState<boolean>(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [batchScanReport, setBatchScanReport] = useState<BatchScanReport | null>(null);
  const [batchCleanReport, setBatchCleanReport] = useState<BatchCleanReport | null>(null);
  const [verificationReport, setVerificationReport] = useState<VerificationReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showRawValues, setShowRawValues] = useState<boolean>(false);



  const handleScanFile = useCallback(
    async (filePath: string, fileObj?: File, includeValues: boolean = showRawValues) => {
      setSelectedFilePath(filePath);
      setSelectedFileObj(fileObj || null);
      const name = fileObj ? fileObj.name : filePath.split('/').pop() || filePath;
      setSelectedFileName(name);
      if (fileObj) {
        setSelectedFileSize(fileObj.size);
      } else {
        setSelectedFileSize(null);
      }

      setIsLoading(true);
      setError(null);
      setVerificationReport(null); // Reset post-cleaning verification on new scan

      try {
        const res = await invoke<ScanReport>('scan_file_cmd', {
          path: filePath,
          includeValues: includeValues,
          include_values: includeValues,
        });
        setReport(res);
        if (res.input.size) {
          setSelectedFileSize(res.input.size);
        }
      } catch (err) {
        console.error('Tauri IPC scan_file_cmd error:', err);
        setError(`Scanning failed: ${typeof err === 'string' ? err : JSON.stringify(err)}`);
        setReport(null);
      } finally {
        setIsLoading(false);
      }
    },
    [showRawValues]
  );

  const handleScanDirectory = useCallback(
    async (path: string, recursive: boolean, jobs: number | null, ignorePatterns: string[]) => {
      setIsLoading(true);
      setError(null);
      setBatchCleanReport(null);

      try {
        const res = await invoke<BatchScanReport>('scan_directory_cmd', {
          path,
          recursive,
          jobs,
          ignorePatterns,
          ignore_patterns: ignorePatterns,
        });
        setBatchScanReport(res);
      } catch (err) {
        console.warn('Tauri IPC scan_directory_cmd failed or running in non-Tauri mode:', err);
        const isTauriErr = String(err).includes('ipc') || String(err).includes('window.__TAURI');
        if (isTauriErr || typeof window === 'undefined' || !(window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
          setError('Batch directory scanning requires the native Tauri desktop app. Browser mode only supports single file scanning via drag & drop.');
          setBatchScanReport(null);
        } else {
          setError(typeof err === 'string' ? err : String(err));
          setBatchScanReport(null);
        }
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  const handleCleanDirectory = useCallback(
    async (
      path: string,
      recursive: boolean,
      jobs: number | null,
      profile: CleanProfile,
      inPlace: boolean
    ) => {
      setIsCleaningBatch(true);
      setError(null);

      try {
        const res = await invoke<BatchCleanReport>('clean_directory_cmd', {
          path,
          recursive,
          jobs,
          profile,
          inPlace,
          in_place: inPlace,
        });
        setBatchCleanReport(res);
      } catch (err) {
        console.warn('Tauri IPC clean_directory_cmd failed or running in non-Tauri mode:', err);
        const isTauriErr = String(err).includes('ipc') || String(err).includes('window.__TAURI');
        if (isTauriErr || typeof window === 'undefined' || !(window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
          setError('Batch directory cleaning requires the native Tauri desktop app. Browser mode only supports single file cleaning via drag & drop.');
        } else {
          setError(typeof err === 'string' ? err : String(err));
        }
      } finally {
        setIsCleaningBatch(false);
      }
    },
    [batchScanReport]
  );

  const handleInspectFileFromBatch = useCallback((fileReport: ScanReport) => {
    const fullPath = fileReport.input.display_name;
    setSelectedFilePath(fullPath);
    setSelectedFileName(fullPath.split('/').pop() || fullPath);
    setSelectedFileSize(fileReport.input.size);
    setReport(fileReport);
    setVerificationReport(null);
    setMode('single');
  }, []);

  const handleToggleRawValues = useCallback(
    (newShow: boolean) => {
      setShowRawValues(newShow);
      if (selectedFilePath) {
        handleScanFile(selectedFilePath, selectedFileObj || undefined, newShow);
      }
    },
    [selectedFilePath, selectedFileObj, handleScanFile]
  );

  const handleClear = useCallback(() => {
    setSelectedFilePath(null);
    setSelectedFileName(null);
    setSelectedFileSize(null);
    setSelectedFileObj(null);
    setReport(null);
    setVerificationReport(null);
    setError(null);
  }, []);

  const handleResetBatch = useCallback(() => {
    setBatchScanReport(null);
    setBatchCleanReport(null);
    setError(null);
  }, []);

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 font-sans selection:bg-indigo-500 selection:text-white">
      {/* Background Lighting Effects */}
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-indigo-600/10 rounded-full blur-[128px] pointer-events-none" />
      <div className="fixed top-1/3 right-1/4 w-96 h-96 bg-purple-600/10 rounded-full blur-[128px] pointer-events-none" />

      {/* Main Container */}
      <div className="max-w-6xl mx-auto px-4 py-8 space-y-8 relative z-10">
        {/* App Navbar Header */}
        <header className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-2xl bg-gradient-to-tr from-indigo-600 to-purple-600 shadow-lg shadow-indigo-500/20 text-white">
              <Shield className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-indigo-100 to-slate-300 tracking-tight">
                  Privacy File Guard
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  v0.1.0 Desktop
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Local-first zero-trust privacy scanner & EXIF/PII sanitizer
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto justify-between sm:justify-end">
            {/* Header Mode Switcher Toggle */}
            <div className="inline-flex p-1 bg-slate-900/90 rounded-xl border border-slate-800">
              <button
                type="button"
                onClick={() => setMode('single')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
                  mode === 'single'
                    ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                Single File
              </button>
              <button
                type="button"
                onClick={() => setMode('batch')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
                  mode === 'batch'
                    ? 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-md shadow-purple-600/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <FolderSearch className="w-3.5 h-3.5" />
                Batch Mode
              </button>
            </div>

            <span className="hidden lg:inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Air-Gapped Offline Protection
            </span>
          </div>
        </header>

        {/* View Switcher based on Mode state */}
        {mode === 'batch' ? (
          <BatchDashboard
            mode={mode}
            onModeToggle={(m) => setMode(m)}
            onScanDirectory={handleScanDirectory}
            onCleanDirectory={handleCleanDirectory}
            isLoading={isLoading}
            isCleaning={isCleaningBatch}
            batchScanReport={batchScanReport}
            batchCleanReport={batchCleanReport}
            onInspectFile={handleInspectFileFromBatch}
            error={error}
            onResetBatch={handleResetBatch}
          />
        ) : (
          /* Single File Mode Layout */
          <div className="space-y-8 animate-in fade-in duration-300">
            {/* Section 1: DropZone Component */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-indigo-400" />
                  Target File Selection
                </h2>
                {report && (
                  <button
                    type="button"
                    onClick={handleClear}
                    className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    Scan New File
                  </button>
                )}
              </div>

              <DropZone
                onFileSelect={(path, fileObj) => handleScanFile(path, fileObj)}
                isLoading={isLoading}
                selectedFilePath={selectedFilePath}
                selectedFileName={selectedFileName}
                selectedFileSize={selectedFileSize}
                error={error}
                onClear={handleClear}
              />
            </section>

            {/* Section 2: Scan Report File Summary Header */}
            {report && (
              <div className="space-y-8 animate-in fade-in slide-in-from-bottom-3 duration-300">
                <section className="glass-card p-6 space-y-4">
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                    <div className="flex items-center gap-3">
                      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-indigo-400">
                        <FileText className="w-6 h-6" />
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-white flex items-center gap-2">
                          <span>{report.input.display_name}</span>
                          <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 uppercase">
                            {report.detected_format}
                          </span>
                        </h3>
                        <div className="flex items-center gap-4 text-xs text-slate-400 font-mono mt-0.5">
                          <span className="flex items-center gap-1">
                            <HardDrive className="w-3.5 h-3.5" />
                            {formatBytes(report.input.size)}
                          </span>
                          <span className="flex items-center gap-1">
                            <Hash className="w-3.5 h-3.5" />
                            <span className="truncate max-w-[200px]" title={report.input.sha256}>
                              {report.input.sha256.substring(0, 16)}...
                            </span>
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Severity Breakdown Summary Badges */}
                    <div className="flex items-center gap-2 flex-wrap">
                      {report.summary.critical > 0 && (
                        <span className="badge-severity badge-critical">
                          {report.summary.critical} Critical
                        </span>
                      )}
                      {report.summary.high > 0 && (
                        <span className="badge-severity badge-high">
                          {report.summary.high} High
                        </span>
                      )}
                      {report.summary.medium > 0 && (
                        <span className="badge-severity badge-medium">
                          {report.summary.medium} Medium
                        </span>
                      )}
                      {report.summary.low > 0 && (
                        <span className="badge-severity badge-low">
                          {report.summary.low} Low
                        </span>
                      )}
                      {report.summary.informational > 0 && (
                        <span className="badge-severity badge-informational">
                          {report.summary.informational} Info
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Section 3: FindingsList Component */}
                  <FindingsList
                    findings={report.findings}
                    summary={report.summary}
                    showRawValues={showRawValues}
                    onToggleRawValues={handleToggleRawValues}
                    detectedFormat={report.detected_format}
                  />
                </section>

                {/* Section 4: CleanPanel Component */}
                <section className="space-y-6">
                  <CleanPanel
                    selectedFilePath={selectedFilePath || report.input.display_name}
                    fileObj={selectedFileObj}
                    report={report}
                    onCleanSuccess={(verReport) => setVerificationReport(verReport)}
                  />

                  {/* Section 5: VerificationBadge Component */}
                  {verificationReport && (
                    <VerificationBadge
                      report={verificationReport}
                      originalFileName={report.input.display_name}
                    />
                  )}
                </section>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
