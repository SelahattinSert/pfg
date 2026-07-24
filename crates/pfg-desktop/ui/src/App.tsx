import React, { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  ScanReport,
  Finding,
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
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isCleaningBatch, setIsCleaningBatch] = useState<boolean>(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [batchScanReport, setBatchScanReport] = useState<BatchScanReport | null>(null);
  const [batchCleanReport, setBatchCleanReport] = useState<BatchCleanReport | null>(null);
  const [verificationReport, setVerificationReport] = useState<VerificationReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showRawValues, setShowRawValues] = useState<boolean>(false);

  // Fallback mock scan report for browser dev mode
  const createMockReport = (_path: string, fileName: string, size?: number): ScanReport => {
    const ext = fileName.split('.').pop()?.toLowerCase() || 'jpeg';
    const mockFindings: Finding[] = [
      {
        id: 'finding-1',
        category: 'location',
        severity: 'high',
        source: 'exif',
        key: 'GPSLatitude',
        display_value: '37° 46\' 29.8" N',
        raw_value_available: true,
        location: { header: { segment: 'EXIF_IFD0' } },
        risk_explanation: 'Contains precise physical GPS location metadata that exposes user geographical coordinates.',
        removable: true,
      },
      {
        id: 'finding-2',
        category: 'device',
        severity: 'medium',
        source: 'exif',
        key: 'MakeAndModel',
        display_value: 'Apple iPhone 15 Pro Max (iOS 17.4.1)',
        raw_value_available: true,
        location: { header: { segment: 'EXIF_IFD0' } },
        risk_explanation: 'Reveals exact hardware model and firmware version, enabling targeted device fingerprinting.',
        removable: true,
      },
      {
        id: 'finding-3',
        category: 'identity',
        severity: 'critical',
        source: 'xmp',
        key: 'AuthorName',
        display_value: 'Selahattin (selahattin@example.com)',
        raw_value_available: true,
        location: { offset: { byte_offset: 1024 } },
        risk_explanation: 'Exposes personally identifiable information (PII) full name and email address.',
        removable: true,
      },
      {
        id: 'finding-4',
        category: 'software',
        severity: 'low',
        source: 'iptc',
        key: 'SoftwareAgent',
        display_value: 'Adobe Photoshop 2024 (Macintosh)',
        raw_value_available: true,
        location: { header: { segment: 'IPTC_APP13' } },
        risk_explanation: 'Discloses software editor and operating system environment details.',
        removable: true,
      },
      {
        id: 'finding-5',
        category: 'document-history',
        severity: 'informational',
        source: 'pdf_info',
        key: 'CreationDate',
        display_value: '2026-07-24T14:30:00Z',
        raw_value_available: true,
        location: { pdf_object: { object_number: 42 } },
        risk_explanation: 'Contains original creation timestamp and editing session history.',
        removable: true,
      },
    ];

    return {
      schema_version: 1,
      tool_version: '0.1.0',
      operation: 'scan_file',
      input: {
        name: fileName,
        size: size || 2450800,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      detected_format: ext,
      support_level: 'FullSupport',
      findings: mockFindings,
      summary: {
        critical: 1,
        high: 1,
        medium: 1,
        low: 1,
        informational: 1,
      },
    };
  };

  // Mock batch scan report fallback for browser preview mode
  const createMockBatchReport = (targetPath: string): BatchScanReport => {
    const mockReports = [
      createMockReport(`${targetPath}/family_vacation_2026.jpg`, 'family_vacation_2026.jpg', 3200000),
      createMockReport(`${targetPath}/project_proposal.pdf`, 'project_proposal.pdf', 1500000),
      createMockReport(`${targetPath}/financial_q2.xlsx`, 'financial_q2.xlsx', 890000),
      createMockReport(`${targetPath}/clean_document.pdf`, 'clean_document.pdf', 450000),
    ];
    // Set 4th report to clean
    mockReports[3].findings = [];
    mockReports[3].summary = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };

    return {
      target_path: targetPath,
      files_scanned: 4,
      files_skipped: 0,
      total_findings: 15,
      reports: mockReports,
      summary: {
        critical: 3,
        high: 3,
        medium: 3,
        low: 3,
        informational: 3,
      },
    };
  };

  // Mock batch clean report fallback
  const createMockBatchCleanReport = (batchReport: BatchScanReport): BatchCleanReport => {
    return {
      target_path: batchReport.target_path,
      total_files: batchReport.files_scanned,
      cleaned_files: batchReport.files_scanned,
      skipped_files: 0,
      failed_files: 0,
      verified_clean_count: batchReport.files_scanned,
      file_reports: batchReport.reports.map((r) => ({
        original_sha256: r.input.sha256,
        cleaned_sha256: 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef',
        original_findings_count: r.findings.length,
        cleaned_findings_count: 0,
        verified_clean: true,
        assurance_level: 'HighAssurance',
      })),
    };
  };

  const handleScanFile = useCallback(
    async (filePath: string, fileObj?: File, includeValues: boolean = showRawValues) => {
      setSelectedFilePath(filePath);
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
        console.warn('Tauri IPC scan_file_cmd failed or running in non-Tauri browser mode:', err);
        const isTauriErr = String(err).includes('ipc') || String(err).includes('window.__TAURI');
        if (isTauriErr || typeof window === 'undefined' || !(window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
          console.info('Using fallback mock scan report for preview mode.');
          const mock = createMockReport(filePath, name, fileObj?.size);
          setReport(mock);
        } else {
          setError(typeof err === 'string' ? err : String(err));
          setReport(null);
        }
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
          console.info('Using fallback mock batch scan report for preview mode.');
          const mockBatch = createMockBatchReport(path);
          setBatchScanReport(mockBatch);
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
          console.info('Using fallback mock batch clean report for preview mode.');
          if (batchScanReport) {
            const mockClean = createMockBatchCleanReport(batchScanReport);
            setBatchCleanReport(mockClean);
          }
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
    setSelectedFilePath(fileReport.input.name);
    setSelectedFileName(fileReport.input.name);
    setSelectedFileSize(fileReport.input.size);
    setReport(fileReport);
    setVerificationReport(null);
    setMode('single');
  }, []);

  const handleToggleRawValues = useCallback(
    (newShow: boolean) => {
      setShowRawValues(newShow);
      if (selectedFilePath) {
        handleScanFile(selectedFilePath, undefined, newShow);
      }
    },
    [selectedFilePath, handleScanFile]
  );

  const handleClear = useCallback(() => {
    setSelectedFilePath(null);
    setSelectedFileName(null);
    setSelectedFileSize(null);
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
                          <span>{report.input.name}</span>
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
                    selectedFilePath={selectedFilePath || report.input.name}
                    report={report}
                    onCleanSuccess={(verReport) => setVerificationReport(verReport)}
                  />

                  {/* Section 5: VerificationBadge Component */}
                  {verificationReport && (
                    <VerificationBadge
                      report={verificationReport}
                      originalFileName={report.input.name}
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
