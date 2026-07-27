import React, { useState, useRef, DragEvent, ChangeEvent } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  UploadCloud,
  FileText,
  Loader2,
  AlertCircle,
  FolderOpen,
  RefreshCw,
  CheckCircle2,
} from 'lucide-react';

export interface DropZoneProps {
  onFileSelect: (filePath: string, fileObj?: File) => void;
  isLoading: boolean;
  selectedFilePath?: string | null;
  selectedFileName?: string | null;
  selectedFileSize?: number | null;
  error?: string | null;
  onClear?: () => void;
}

const SUPPORTED_FORMATS = [
  { name: 'JPEG', ext: '.jpg, .jpeg', badge: 'JPEG' },
  { name: 'PNG', ext: '.png', badge: 'PNG' },
  { name: 'WebP', ext: '.webp', badge: 'WebP' },
  { name: 'PDF', ext: '.pdf', badge: 'PDF' },
  { name: 'DOCX', ext: '.docx', badge: 'DOCX' },
  { name: 'XLSX', ext: '.xlsx', badge: 'XLSX' },
  { name: 'PPTX', ext: '.pptx', badge: 'PPTX' },
];

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export const DropZone: React.FC<DropZoneProps> = ({
  onFileSelect,
  isLoading,
  selectedFilePath,
  selectedFileName,
  selectedFileSize,
  error,
  onClear,
}) => {
  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    let unlistenFn: (() => void) | undefined;
    const setupListener = async () => {
      try {
        const { getCurrentWebviewWindow } = await import('@tauri-apps/api/webviewWindow');
        const appWindow = getCurrentWebviewWindow();
        unlistenFn = await appWindow.onDragDropEvent((event) => {
          if (event.payload.type === 'drop') {
            setIsDragActive(false);
            const paths = event.payload.paths;
            if (paths && paths.length > 0) {
              onFileSelect(paths[0]);
            }
          } else if (event.payload.type === 'enter' || event.payload.type === 'over') {
            setIsDragActive(true);
          } else {
            setIsDragActive(false);
          }
        });
      } catch (_e) {
        // Fallback for non-Tauri browser dev mode
      }
    };
    setupListener();
    return () => {
      if (unlistenFn) unlistenFn();
    };
  }, [onFileSelect]);

  const handleDragEnter = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragActive) {
      setIsDragActive(true);
    }
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    if (isLoading) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const rawPath = (file as unknown as { path?: string }).path || '';
      // If path is absolute (starts with / or letter:\), use it directly
      if (rawPath && (rawPath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(rawPath))) {
        onFileSelect(rawPath, file);
      } else {
        // Fallback to native OS dialog to guarantee full absolute path resolution
        handleBrowseClick();
      }
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      const rawPath = (file as unknown as { path?: string }).path || '';
      if (rawPath && (rawPath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(rawPath))) {
        onFileSelect(rawPath, file);
      } else {
        handleBrowseClick();
      }
    }
  };

  const handleBrowseClick = async () => {
    if (isLoading) return;
    try {
      const selectedPath = await invoke<string | null>('select_file_dialog_cmd');
      if (selectedPath) {
        onFileSelect(selectedPath);
        return;
      }
    } catch (_err) {
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
        fileInputRef.current.click();
      }
    }
  };

  return (
    <div className="w-full">
      {/* Hidden native file input */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileChange}
        accept=".jpg,.jpeg,.png,.webp,.pdf,.docx,.xlsx,.pptx"
        className="hidden"
      />

      {/* Main Container */}
      <div
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={!selectedFilePath && !isLoading ? handleBrowseClick : undefined}
        className={`relative overflow-hidden rounded-2xl border-2 transition-all duration-300 p-8 text-center glass-card ${
          isDragActive
            ? 'border-indigo-500 bg-indigo-500/10 shadow-[0_0_30px_rgba(99,102,241,0.3)] scale-[1.01]'
            : selectedFilePath
            ? 'border-emerald-500/40 bg-slate-900/60'
            : 'border-dashed border-slate-700 hover:border-indigo-400/60 hover:bg-slate-800/40 cursor-pointer'
        }`}
      >
        {/* Ambient Glow Background Effect */}
        <div className="absolute -top-24 -left-24 w-48 h-48 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -right-24 w-48 h-48 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* State 1: Loading Animation */}
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-6 space-y-4">
            <div className="relative flex items-center justify-center">
              <div className="w-16 h-16 rounded-full border-4 border-indigo-500/20 border-t-indigo-500 animate-spin" />
              <Loader2 className="w-8 h-8 text-indigo-400 animate-spin absolute" />
            </div>
            <div className="space-y-1">
              <h3 className="text-lg font-semibold text-white tracking-wide">
                Analyzing File Security & Privacy
              </h3>
              <p className="text-sm text-slate-400">
                Parsing metadata, EXIF/XMP tags, embedded objects & PII...
              </p>
            </div>
            {selectedFileName && (
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-950/50 border border-indigo-500/30 text-indigo-300 text-xs font-mono">
                <FileText className="w-3.5 h-3.5" />
                <span>{selectedFileName}</span>
              </div>
            )}
          </div>
        ) : selectedFilePath ? (
          /* State 2: Selected File Active State */
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 py-2 text-left">
            <div className="flex items-center gap-4">
              <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex-shrink-0">
                <CheckCircle2 className="w-7 h-7" />
              </div>
              <div className="space-y-1 overflow-hidden">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-white truncate max-w-md text-base">
                    {selectedFileName || selectedFilePath}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    SCANNED
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                  <span>{selectedFilePath}</span>
                  {selectedFileSize != null && (
                    <>
                      <span>•</span>
                      <span>{formatBytes(selectedFileSize)}</span>
                    </>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 w-full md:w-auto">
              <button
                type="button"
                onClick={handleBrowseClick}
                className="btn-secondary flex-1 md:flex-none text-xs flex items-center justify-center gap-1.5 py-2 px-3"
              >
                <FolderOpen className="w-3.5 h-3.5" />
                Change File
              </button>
              {onClear && (
                <button
                  type="button"
                  onClick={onClear}
                  className="btn-secondary flex-1 md:flex-none text-xs flex items-center justify-center gap-1.5 py-2 px-3 text-slate-400 hover:text-white"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Reset
                </button>
              )}
            </div>
          </div>
        ) : (
          /* State 3: Ready for Drag-and-Drop / Browse */
          <div className="flex flex-col items-center justify-center py-4 space-y-4">
            <div className="p-4 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 shadow-inner">
              <UploadCloud className="w-10 h-10 animate-bounce" />
            </div>

            <div className="space-y-1">
              <h3 className="text-xl font-bold text-white tracking-tight">
                Drag & Drop file to inspect privacy risks
              </h3>
              <p className="text-sm text-slate-400">
                Or click below to select a file from your computer
              </p>
            </div>

            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                handleBrowseClick();
              }}
              className="btn-primary py-2.5 px-6 text-sm font-semibold shadow-lg shadow-indigo-500/25 hover:shadow-indigo-500/40"
            >
              <FolderOpen className="w-4 h-4" />
              Browse Files
            </button>

            {/* Supported Format Badges */}
            <div className="pt-4 border-t border-slate-800/80 w-full max-w-xl">
              <p className="text-xs font-medium text-slate-400 mb-2.5 uppercase tracking-wider">
                Supported File Formats
              </p>
              <div className="flex flex-wrap items-center justify-center gap-2">
                {SUPPORTED_FORMATS.map((fmt) => (
                  <span
                    key={fmt.name}
                    title={fmt.ext}
                    className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-slate-800/80 text-indigo-300 border border-slate-700/60 hover:border-indigo-500/40 hover:bg-slate-800 transition-colors"
                  >
                    {fmt.badge}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Error Alert inside DropZone */}
        {error && (
          <div className="mt-4 p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-2 text-left">
            <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-400" />
            <span className="font-mono">{error}</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default DropZone;
