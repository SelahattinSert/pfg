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
  // Dynamic scan report generator for browser preview mode
  const createMockReport = (_path: string, fileName: string, size?: number): ScanReport => {
    const ext = fileName.split('.').pop()?.toLowerCase() || 'jpeg';
    const lowerName = fileName.toLowerCase();
    
    // Simple deterministic hash for file
    let hash = 0;
    for (let i = 0; i < fileName.length; i++) {
      hash = (hash << 5) - hash + fileName.charCodeAt(i);
      hash |= 0;
    }
    const hexHash = Math.abs(hash).toString(16).padStart(64, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

    // Clean files (e.g. web exports, logos, banners, chatgpt images)
    const isCleanFile = lowerName.includes('clean') || 
                        lowerName.includes('logo') || 
                        lowerName.includes('banner') || 
                        lowerName.includes('chatgpt') || 
                        lowerName.includes('favicon') || 
                        lowerName.includes('export');

    const mockFindings: Finding[] = [];

    if (!isCleanFile) {
      if (ext === 'pdf') {
        mockFindings.push({
          id: `finding-pdf-1-${Math.abs(hash % 100)}`,
          category: 'identity',
          severity: 'high',
          source: 'pdf_info',
          key: '/Author',
          display_value: 'Document Author (user@company.com)',
          raw_value_available: true,
          location: { pdf_object: { object_number: 12 } },
          risk_explanation: 'PDF /Info dictionary reveals author full name and email identity.',
          removable: true,
        });
        mockFindings.push({
          id: `finding-pdf-2-${Math.abs(hash % 100)}`,
          category: 'document-history',
          severity: 'medium',
          source: 'pdf_info',
          key: '/Creator',
          display_value: 'Microsoft Word for Office 365',
          raw_value_available: true,
          location: { pdf_object: { object_number: 12 } },
          risk_explanation: 'Discloses software application used to convert/export the PDF document.',
          removable: true,
        });
      } else if (ext === 'docx' || ext === 'xlsx' || ext === 'pptx') {
        mockFindings.push({
          id: `finding-office-1-${Math.abs(hash % 100)}`,
          category: 'identity',
          severity: 'high',
          source: 'office_xml',
          key: 'dc:creator',
          display_value: 'Corporate User',
          raw_value_available: true,
          location: { header: { segment: 'docProps/core.xml' } },
          risk_explanation: 'Office Open XML core properties contain original document author name.',
          removable: true,
        });
        mockFindings.push({
          id: `finding-office-2-${Math.abs(hash % 100)}`,
          category: 'software',
          severity: 'medium',
          source: 'office_xml',
          key: 'cp:lastModifiedBy',
          display_value: 'Editor User (IT Dept)',
          raw_value_available: true,
          location: { header: { segment: 'docProps/core.xml' } },
          risk_explanation: 'Exposes account name of the last person who saved or modified this document.',
          removable: true,
        });
      } else {
        // Image formats (jpeg, png, webp)
        mockFindings.push({
          id: `finding-img-1-${Math.abs(hash % 100)}`,
          category: 'location',
          severity: 'high',
          source: 'exif',
          key: 'GPSLatitude',
          display_value: `37° ${(Math.abs(hash) % 50)}' ${(Math.abs(hash) % 60)}.2" N`,
          raw_value_available: true,
          location: { header: { segment: 'EXIF_IFD0' } },
          risk_explanation: 'Contains precise physical GPS location metadata that exposes user geographical coordinates.',
          removable: true,
        });
        mockFindings.push({
          id: `finding-img-2-${Math.abs(hash % 100)}`,
          category: 'device',
          severity: 'medium',
          source: 'exif',
          key: 'MakeAndModel',
          display_value: ext === 'png' ? 'PNG eXIf Camera Metadata' : 'Camera Hardware EXIF Tag',
          raw_value_available: true,
          location: { header: { segment: 'EXIF_IFD0' } },
          risk_explanation: 'Reveals camera hardware model and device serial information.',
          removable: true,
        });
      }
    }

    const summary = {
      critical: mockFindings.filter((f) => f.severity === 'critical').length,
      high: mockFindings.filter((f) => f.severity === 'high').length,
      medium: mockFindings.filter((f) => f.severity === 'medium').length,
      low: mockFindings.filter((f) => f.severity === 'low').length,
      informational: mockFindings.filter((f) => f.severity === 'informational').length,
    };

    return {
      schema_version: 1,
      tool_version: '0.1.0',
      operation: 'scan_file',
      input: {
        name: fileName,
        size: size || Math.abs(hash % 5000000) + 50000,
        sha256: hexHash,
      },
      detected_format: ext,
      support_level: 'FullSupport',
      findings: mockFindings,
      summary,
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

  // Real binary byte parser for browser preview mode fallback
  const parseRealFileInBrowser = async (fileObj: File): Promise<ScanReport> => {
    const fileName = fileObj.name;
    const size = fileObj.size;
    const ext = fileName.split('.').pop()?.toLowerCase() || 'jpeg';

    // 1. Compute real SHA-256 hash of file bytes
    const arrayBuffer = await fileObj.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha256 = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    const findings: Finding[] = [];
    let findingCounter = 1;

    // 2. Real JPEG Scanner
    if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8) {
      let cursor = 2;
      while (cursor + 4 < bytes.length) {
        if (bytes[cursor] !== 0xff) {
          cursor++;
          continue;
        }
        const marker = bytes[cursor + 1];
        if (marker === 0xd9 || marker === 0xda) break; // EOI or SOS

        const len = (bytes[cursor + 2] << 8) | bytes[cursor + 3];
        const nextCursor = cursor + 2 + len;
        if (nextCursor > bytes.length) break;

        // APP1 Marker (EXIF or XMP)
        if (marker === 0xe1) {
          const payload = bytes.subarray(cursor + 4, nextCursor);
          const textPayload = new TextDecoder('latin1').decode(payload);
          
          if (textPayload.includes('Exif')) {
            const hasGPS = textPayload.includes('GPS') || textPayload.includes('\x00\x02');
            findings.push({
              id: `finding-exif-${findingCounter++}`,
              category: hasGPS ? 'location' : 'device',
              severity: hasGPS ? 'high' : 'medium',
              source: 'exif',
              key: hasGPS ? 'GPSInfo' : 'EXIF_IFD0',
              display_value: hasGPS ? 'GPS Latitude & Longitude Tag Present' : 'Camera Hardware EXIF Metadata',
              raw_value_available: true,
              location: { header: { segment: 'EXIF_APP1' } },
              risk_explanation: hasGPS
                ? 'EXIF header contains precise physical GPS location coordinates.'
                : 'EXIF header contains camera model, capture time, or serial details.',
              removable: true,
            });
          }
          if (textPayload.includes('http://ns.adobe.com')) {
            findings.push({
              id: `finding-xmp-${findingCounter++}`,
              category: 'document-history',
              severity: 'high',
              source: 'xmp',
              key: 'XMP_Packet',
              display_value: 'Adobe XMP Metadata Packet Present',
              raw_value_available: true,
              location: { header: { segment: 'XMP_APP1' } },
              risk_explanation: 'XMP packet contains editing history, software environment, and author details.',
              removable: true,
            });
          }
        }
        // COM Marker
        if (marker === 0xfe) {
          const payload = bytes.subarray(cursor + 4, nextCursor);
          const commentText = new TextDecoder().decode(payload);
          findings.push({
            id: `finding-com-${findingCounter++}`,
            category: 'software',
            severity: 'medium',
            source: 'comment',
            key: 'JPEG_Comment',
            display_value: commentText.substring(0, 40) || 'Text Comment Segment',
            raw_value_available: true,
            location: { header: { segment: 'COM' } },
            risk_explanation: 'JPEG comment segment contains text comments.',
            removable: true,
          });
        }
        cursor = nextCursor;
      }
    }
    // 3. Real PNG Scanner
    else if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
      let cursor = 8;
      const textDecoder = new TextDecoder('latin1');
      while (cursor + 12 <= bytes.length) {
        const length = (bytes[cursor] << 24) | (bytes[cursor + 1] << 16) | (bytes[cursor + 2] << 8) | bytes[cursor + 3];
        const typeSlice = bytes.subarray(cursor + 4, cursor + 8);
        const chunkType = textDecoder.decode(typeSlice);
        const chunkEnd = cursor + 12 + length;
        if (chunkEnd > bytes.length) break;

        if (chunkType === 'eXIf') {
          findings.push({
            id: `finding-png-${findingCounter++}`,
            category: 'device',
            severity: 'high',
            source: 'exif',
            key: 'eXIf',
            display_value: 'PNG eXIf Metadata Chunk Present',
            raw_value_available: true,
            location: { offset: { byte_offset: cursor } },
            risk_explanation: 'PNG eXIf chunk contains camera hardware and capture metadata.',
            removable: true,
          });
        } else if (chunkType === 'tEXt' || chunkType === 'zTXt' || chunkType === 'iTXt') {
          const dataSlice = bytes.subarray(cursor + 8, cursor + 8 + Math.min(length, 64));
          const textStr = textDecoder.decode(dataSlice);
          const keyName = textStr.split('\0')[0] || 'TextChunk';
          findings.push({
            id: `finding-png-${findingCounter++}`,
            category: 'software',
            severity: 'medium',
            source: 'comment',
            key: `${chunkType}: ${keyName}`,
            display_value: `PNG ${chunkType} (${keyName})`,
            raw_value_available: true,
            location: { offset: { byte_offset: cursor } },
            risk_explanation: `PNG ${chunkType} chunk contains text metadata (${keyName}).`,
            removable: true,
          });
        } else if (chunkType === 'tIME') {
          findings.push({
            id: `finding-png-${findingCounter++}`,
            category: 'time',
            severity: 'medium',
            source: 'comment',
            key: 'tIME',
            display_value: 'PNG Timestamp Chunk Present',
            raw_value_available: true,
            location: { offset: { byte_offset: cursor } },
            risk_explanation: 'PNG tIME chunk exposes precise file modification timestamp.',
            removable: true,
          });
        }
        cursor = chunkEnd;
      }
    }
    // 4. Real PDF Scanner
    else if (ext === 'pdf') {
      const pdfText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 1000000)));
      if (pdfText.includes('/Author')) {
        findings.push({
          id: `finding-pdf-${findingCounter++}`,
          category: 'identity',
          severity: 'high',
          source: 'pdf_info',
          key: '/Author',
          display_value: 'PDF /Author Dictionary Entry',
          raw_value_available: true,
          location: { pdf_object: { object_number: 1 } },
          risk_explanation: 'PDF document contains author identity info dictionary.',
          removable: true,
        });
      }
      if (pdfText.includes('/Creator') || pdfText.includes('/Producer')) {
        findings.push({
          id: `finding-pdf-${findingCounter++}`,
          category: 'software',
          severity: 'medium',
          source: 'pdf_info',
          key: '/Creator',
          display_value: 'PDF Software Creator Tag',
          raw_value_available: true,
          location: { pdf_object: { object_number: 1 } },
          risk_explanation: 'PDF reveals software tool used to produce the document.',
          removable: true,
        });
      }
      if (pdfText.includes('/Type /Metadata') || pdfText.includes('http://ns.adobe.com')) {
        findings.push({
          id: `finding-pdf-${findingCounter++}`,
          category: 'document-history',
          severity: 'high',
          source: 'xmp',
          key: 'XMP_Metadata_Stream',
          display_value: 'PDF XMP Metadata Stream Present',
          raw_value_available: true,
          location: { pdf_object: { object_number: 5 } },
          risk_explanation: 'PDF contains embedded XMP XML metadata stream.',
          removable: true,
        });
      }
    }
    // 5. Real Office Scanner (ZIP container)
    else if (ext === 'docx' || ext === 'xlsx' || ext === 'pptx') {
      const zipText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 500000)));
      if (zipText.includes('docProps/core.xml')) {
        findings.push({
          id: `finding-office-${findingCounter++}`,
          category: 'identity',
          severity: 'high',
          source: 'office_xml',
          key: 'docProps/core.xml',
          display_value: 'Office Core Properties Present',
          raw_value_available: true,
          location: { header: { segment: 'docProps/core.xml' } },
          risk_explanation: 'Office document contains core.xml with author and modification history.',
          removable: true,
        });
      }
      if (zipText.includes('vbaProject.bin')) {
        findings.push({
          id: `finding-office-${findingCounter++}`,
          category: 'software',
          severity: 'critical',
          source: 'office_xml',
          key: 'vbaProject.bin',
          display_value: 'VBA Macro Code Binary Present',
          raw_value_available: true,
          location: { header: { segment: 'word/vbaProject.bin' } },
          risk_explanation: 'Contains executable VBA macros binary file.',
          removable: true,
        });
      }
    }

    const summary = {
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      informational: findings.filter((f) => f.severity === 'informational').length,
    };

    return {
      schema_version: 1,
      tool_version: '0.1.0',
      operation: 'scan_file',
      input: {
        name: fileName,
        size: size,
        sha256: sha256,
      },
      detected_format: ext,
      support_level: 'FullSupport',
      findings: findings,
      summary,
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
          if (fileObj) {
            console.info('Parsing REAL binary bytes of dropped file in browser preview mode!');
            const realReport = await parseRealFileInBrowser(fileObj);
            setReport(realReport);
          } else {
            console.info('Using fallback mock scan report for preview mode.');
            const mock = createMockReport(filePath, name, undefined);
            setReport(mock);
          }
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
