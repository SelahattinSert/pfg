import React, { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  ScanReport,
  Finding,
  FindingCategory,
  FindingSeverity,
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



  // ─── EXIF TIFF/IFD Binary Helpers ───
  function readU16(data: Uint8Array, off: number, le: boolean): number {
    return le
      ? data[off] | (data[off + 1] << 8)
      : (data[off] << 8) | data[off + 1];
  }
  function readU32(data: Uint8Array, off: number, le: boolean): number {
    return le
      ? data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | ((data[off + 3] << 24) >>> 0)
      : (((data[off] << 24) >>> 0) | (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3]);
  }
  function readAscii(data: Uint8Array, off: number, count: number): string {
    let s = '';
    for (let i = 0; i < count && off + i < data.length; i++) {
      const c = data[off + i];
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s.trim();
  }
  function readRational(data: Uint8Array, off: number, le: boolean): number {
    const num = readU32(data, off, le);
    const den = readU32(data, off + 4, le);
    return den === 0 ? 0 : num / den;
  }
  function readTagValue(data: Uint8Array, tiffBase: number, type: number, count: number, valueOffset: number, le: boolean): string | null {
    const off = tiffBase + valueOffset;
    if (off >= data.length) return null;
    if (type === 2) { // ASCII
      const totalBytes = count;
      const actualOff = totalBytes <= 4 ? off : tiffBase + readU32(data, off, le);
      if (actualOff >= data.length) return null;
      return readAscii(data, actualOff, totalBytes);
    }
    if (type === 3 && count === 1) return String(readU16(data, off, le)); // SHORT
    if (type === 4 && count === 1) return String(readU32(data, off, le)); // LONG
    return null;
  }
  function formatDMS(data: Uint8Array, tiffBase: number, off: number, le: boolean, ref: string): string {
    const deg = readRational(data, tiffBase + off, le);
    const min = readRational(data, tiffBase + off + 8, le);
    const sec = readRational(data, tiffBase + off + 16, le);
    return `${deg.toFixed(0)}° ${min.toFixed(0)}' ${sec.toFixed(1)}" ${ref}`;
  }

  type ExifResult = { tag: number; name: string; value: string; category: FindingCategory; severity: FindingSeverity; risk: string };

  function parseExifIFD(
    data: Uint8Array, tiffBase: number, ifdOffset: number, le: boolean,
    tagMap: Record<number, { name: string; category: FindingCategory; severity: FindingSeverity; risk: string }>
  ): ExifResult[] {
    const results: ExifResult[] = [];
    const abs = tiffBase + ifdOffset;
    if (abs + 2 > data.length) return results;
    const entryCount = readU16(data, abs, le);
    for (let i = 0; i < entryCount; i++) {
      const entryOff = abs + 2 + i * 12;
      if (entryOff + 12 > data.length) break;
      const tag = readU16(data, entryOff, le);
      const type = readU16(data, entryOff + 2, le);
      const count = readU32(data, entryOff + 4, le);
      const info = tagMap[tag];
      if (!info) continue;
      // For values > 4 bytes, the entry contains an offset; otherwise inline
      const typeSize: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 10: 8 };
      const totalBytes = (typeSize[type] || 1) * count;
      let valueOff: number;
      if (totalBytes <= 4) {
        valueOff = entryOff + 8 - tiffBase; // relative to tiffBase
      } else {
        valueOff = readU32(data, entryOff + 8, le);
      }
      const val = readTagValue(data, tiffBase, type, count, valueOff, le);
      if (val && val.length > 0) {
        results.push({ tag, name: info.name, value: val, category: info.category, severity: info.severity, risk: info.risk });
      }
    }
    return results;
  }

  // Real binary byte parser for browser mode
  const parseRealFileInBrowser = async (fileObj: File): Promise<ScanReport> => {
    const fileName = fileObj.name;
    const size = fileObj.size;
    const ext = fileName.split('.').pop()?.toLowerCase() || 'jpeg';

    const arrayBuffer = await fileObj.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha256 = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    const findings: Finding[] = [];
    let fc = 1;

    type TagInfo = { name: string; category: FindingCategory; severity: FindingSeverity; risk: string };
    type MetaPattern = { key: string; pattern: RegExp; cat: FindingCategory; sev: FindingSeverity; risk: string };
    const ifd0Tags: Record<number, TagInfo> = {
      0x010f: { name: 'Make', category: 'device', severity: 'medium', risk: 'Reveals camera/phone manufacturer identity.' },
      0x0110: { name: 'Model', category: 'device', severity: 'medium', risk: 'Reveals specific camera/phone hardware model.' },
      0x0131: { name: 'Software', category: 'software', severity: 'low', risk: 'Discloses image editing or capture software name and version.' },
      0x0132: { name: 'DateTime', category: 'time', severity: 'medium', risk: 'Exposes the date and time the image was last modified.' },
      0x013b: { name: 'Artist', category: 'identity', severity: 'high', risk: 'Contains the name of the photographer or image creator.' },
      0x8298: { name: 'Copyright', category: 'identity', severity: 'high', risk: 'Contains copyright holder name which may identify the owner.' },
    };
    const exifSubTags: Record<number, TagInfo> = {
      0x9003: { name: 'DateTimeOriginal', category: 'time', severity: 'medium', risk: 'Reveals the exact date and time the photo was originally taken.' },
      0x9004: { name: 'DateTimeDigitized', category: 'time', severity: 'medium', risk: 'Reveals when the image was digitized/scanned.' },
      0xa434: { name: 'LensModel', category: 'device', severity: 'low', risk: 'Identifies the specific lens model used to capture the image.' },
      0xa420: { name: 'ImageUniqueID', category: 'unique-identifier', severity: 'high', risk: 'Unique tracking identifier that can correlate images across sessions.' },
    };

    // ── JPEG Scanner ──
    if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8) {
      let cursor = 2;
      while (cursor + 4 < bytes.length) {
        if (bytes[cursor] !== 0xff) { cursor++; continue; }
        const marker = bytes[cursor + 1];
        if (marker === 0xd9 || marker === 0xda) break;
        const len = (bytes[cursor + 2] << 8) | bytes[cursor + 3];
        const nextCursor = cursor + 2 + len;
        if (nextCursor > bytes.length) break;

        // APP1 — EXIF
        if (marker === 0xe1) {
          const payload = bytes.subarray(cursor + 4, nextCursor);
          const sig = readAscii(payload, 0, 6);

          if (sig.startsWith('Exif')) {
            const tiffBase = cursor + 4 + 6; // after "Exif\0\0"
            if (tiffBase + 8 < bytes.length) {
              const bom = String.fromCharCode(bytes[tiffBase], bytes[tiffBase + 1]);
              const le = bom === 'II';
              const ifd0Off = readU32(bytes, tiffBase + 4, le);

              // Parse IFD0
              const ifd0Results = parseExifIFD(bytes, tiffBase, ifd0Off, le, ifd0Tags);
              for (const r of ifd0Results) {
                findings.push({
                  id: `finding-${fc++}`, category: r.category, severity: r.severity,
                  source: 'exif', key: r.name, display_value: r.value,
                  raw_value_available: true, location: { header: { segment: 'EXIF_IFD0' } },
                  risk_explanation: r.risk, removable: true,
                });
              }

              // Find GPS IFD pointer (tag 0x8825) and EXIF SubIFD pointer (tag 0x8769)
              const ifd0Abs = tiffBase + ifd0Off;
              if (ifd0Abs + 2 <= bytes.length) {
                const ifd0Count = readU16(bytes, ifd0Abs, le);
                let gpsIfdOff = 0, exifSubOff = 0;
                for (let i = 0; i < ifd0Count; i++) {
                  const eOff = ifd0Abs + 2 + i * 12;
                  if (eOff + 12 > bytes.length) break;
                  const t = readU16(bytes, eOff, le);
                  if (t === 0x8825) gpsIfdOff = readU32(bytes, eOff + 8, le);
                  if (t === 0x8769) exifSubOff = readU32(bytes, eOff + 8, le);
                }

                // Parse EXIF SubIFD
                if (exifSubOff > 0) {
                  const subResults = parseExifIFD(bytes, tiffBase, exifSubOff, le, exifSubTags);
                  for (const r of subResults) {
                    findings.push({
                      id: `finding-${fc++}`, category: r.category, severity: r.severity,
                      source: 'exif', key: r.name, display_value: r.value,
                      raw_value_available: true, location: { header: { segment: 'EXIF_SubIFD' } },
                      risk_explanation: r.risk, removable: true,
                    });
                  }
                }

                // Parse GPS IFD
                if (gpsIfdOff > 0) {
                  const gpsAbs = tiffBase + gpsIfdOff;
                  if (gpsAbs + 2 <= bytes.length) {
                    const gpsCount = readU16(bytes, gpsAbs, le);
                    let latRef = '', lonRef = '', latOff = 0, lonOff = 0, altOff = 0;
                    for (let i = 0; i < gpsCount; i++) {
                      const eOff = gpsAbs + 2 + i * 12;
                      if (eOff + 12 > bytes.length) break;
                      const t = readU16(bytes, eOff, le);
                      if (t === 0x0001) latRef = readAscii(bytes, eOff + 8, 2);
                      if (t === 0x0002) latOff = readU32(bytes, eOff + 8, le);
                      if (t === 0x0003) lonRef = readAscii(bytes, eOff + 8, 2);
                      if (t === 0x0004) lonOff = readU32(bytes, eOff + 8, le);
                      if (t === 0x0006) altOff = readU32(bytes, eOff + 8, le);
                    }
                    if (latOff > 0) {
                      const latStr = formatDMS(bytes, tiffBase, latOff, le, latRef || 'N');
                      findings.push({
                        id: `finding-${fc++}`, category: 'location', severity: 'high',
                        source: 'exif', key: 'GPSLatitude', display_value: latStr,
                        raw_value_available: true, location: { header: { segment: 'EXIF_GPS_IFD' } },
                        risk_explanation: 'Contains precise GPS latitude that pinpoints the exact location where this photo was taken.', removable: true,
                      });
                    }
                    if (lonOff > 0) {
                      const lonStr = formatDMS(bytes, tiffBase, lonOff, le, lonRef || 'E');
                      findings.push({
                        id: `finding-${fc++}`, category: 'location', severity: 'high',
                        source: 'exif', key: 'GPSLongitude', display_value: lonStr,
                        raw_value_available: true, location: { header: { segment: 'EXIF_GPS_IFD' } },
                        risk_explanation: 'Contains precise GPS longitude that pinpoints the exact location where this photo was taken.', removable: true,
                      });
                    }
                    if (altOff > 0) {
                      const alt = readRational(bytes, tiffBase + altOff, le);
                      findings.push({
                        id: `finding-${fc++}`, category: 'location', severity: 'medium',
                        source: 'exif', key: 'GPSAltitude', display_value: `${alt.toFixed(1)} m`,
                        raw_value_available: true, location: { header: { segment: 'EXIF_GPS_IFD' } },
                        risk_explanation: 'Contains GPS altitude (elevation) data.', removable: true,
                      });
                    }
                  }
                }
              }
            }
          }
          // XMP packet — extract real values from XML
          else if (sig.startsWith('http:') || new TextDecoder('latin1').decode(payload).includes('http://ns.adobe.com')) {
            const xmpText = new TextDecoder('utf-8').decode(payload);
            const xmpFindings: MetaPattern[] = [
              { key: 'xmp:CreatorTool', pattern: /xmp:CreatorTool[=>"\s]+([^<"]+)/i, cat: 'software', sev: 'medium', risk: 'XMP reveals the software used to create or edit this file.' },
              { key: 'dc:creator', pattern: /dc:creator[^>]*>[\s\S]*?<rdf:li[^>]*>([^<]+)/i, cat: 'identity', sev: 'high', risk: 'XMP dc:creator contains the author/creator name.' },
              { key: 'xmp:CreateDate', pattern: /xmp:CreateDate[=>"\s]+([^<"]+)/i, cat: 'time', sev: 'medium', risk: 'XMP reveals the original creation date and time.' },
              { key: 'xmp:ModifyDate', pattern: /xmp:ModifyDate[=>"\s]+([^<"]+)/i, cat: 'time', sev: 'medium', risk: 'XMP reveals the last modification date and time.' },
              { key: 'photoshop:DateCreated', pattern: /photoshop:DateCreated[=>"\s]+([^<"]+)/i, cat: 'time', sev: 'medium', risk: 'Photoshop metadata reveals creation date.' },
              { key: 'tiff:Make', pattern: /tiff:Make[=>"\s]+([^<"]+)/i, cat: 'device', sev: 'medium', risk: 'XMP TIFF namespace reveals camera manufacturer.' },
              { key: 'tiff:Model', pattern: /tiff:Model[=>"\s]+([^<"]+)/i, cat: 'device', sev: 'medium', risk: 'XMP TIFF namespace reveals camera model.' },
              { key: 'xmpMM:DocumentID', pattern: /xmpMM:DocumentID[=>"\s]+([^<"]+)/i, cat: 'unique-identifier', sev: 'high', risk: 'XMP DocumentID is a unique tracking identifier for this file.' },
              { key: 'xmpMM:InstanceID', pattern: /xmpMM:InstanceID[=>"\s]+([^<"]+)/i, cat: 'unique-identifier', sev: 'high', risk: 'XMP InstanceID tracks specific save instances of this file.' },
            ];
            for (const xf of xmpFindings) {
              const m = xf.pattern.exec(xmpText);
              if (m && m[1]) {
                findings.push({
                  id: `finding-${fc++}`, category: xf.cat, severity: xf.sev,
                  source: 'xmp', key: xf.key, display_value: m[1].trim(),
                  raw_value_available: true, location: { header: { segment: 'XMP_APP1' } },
                  risk_explanation: xf.risk, removable: true,
                });
              }
            }
            if (findings.filter(f => f.source === 'xmp').length === 0) {
              findings.push({
                id: `finding-${fc++}`, category: 'document-history', severity: 'medium',
                source: 'xmp', key: 'XMP_Packet', display_value: `XMP metadata (${payload.length} bytes)`,
                raw_value_available: true, location: { header: { segment: 'XMP_APP1' } },
                risk_explanation: 'Contains an XMP metadata packet with potential tracking and identity data.', removable: true,
              });
            }
          }
        }
        // COM Marker
        if (marker === 0xfe) {
          const commentText = new TextDecoder().decode(bytes.subarray(cursor + 4, nextCursor));
          findings.push({
            id: `finding-${fc++}`, category: 'software', severity: 'medium',
            source: 'comment', key: 'JPEG_Comment', display_value: commentText.substring(0, 80) || 'Empty comment',
            raw_value_available: true, location: { header: { segment: 'COM' } },
            risk_explanation: 'JPEG comment segment may contain software identifiers or author notes.', removable: true,
          });
        }
        cursor = nextCursor;
      }
    }
    // ── PNG Scanner ──
    else if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
      let cursor = 8;
      const td = new TextDecoder('latin1');
      while (cursor + 12 <= bytes.length) {
        const length = (bytes[cursor] << 24) | (bytes[cursor + 1] << 16) | (bytes[cursor + 2] << 8) | bytes[cursor + 3];
        const chunkType = td.decode(bytes.subarray(cursor + 4, cursor + 8));
        const chunkEnd = cursor + 12 + length;
        if (chunkEnd > bytes.length) break;

        if (chunkType === 'eXIf' && length > 8) {
          // Parse TIFF inside eXIf chunk
          const tiffBase = cursor + 8;
          const bom = String.fromCharCode(bytes[tiffBase], bytes[tiffBase + 1]);
          const le = bom === 'II';
          if (tiffBase + 8 < bytes.length) {
            const ifd0Off = readU32(bytes, tiffBase + 4, le);
            const ifd0Results = parseExifIFD(bytes, tiffBase, ifd0Off, le, ifd0Tags);
            for (const r of ifd0Results) {
              findings.push({
                id: `finding-${fc++}`, category: r.category, severity: r.severity,
                source: 'exif', key: r.name, display_value: r.value,
                raw_value_available: true, location: { offset: { byte_offset: cursor } },
                risk_explanation: r.risk, removable: true,
              });
            }
          }
        } else if (chunkType === 'tEXt' || chunkType === 'zTXt' || chunkType === 'iTXt') {
          const dataSlice = bytes.subarray(cursor + 8, cursor + 8 + Math.min(length, 256));
          const textStr = td.decode(dataSlice);
          const parts = textStr.split('\0');
          const keyName = parts[0] || 'TextChunk';
          const value = parts.length > 1 ? parts[parts.length - 1].substring(0, 80) : '';
          findings.push({
            id: `finding-${fc++}`, category: 'software', severity: 'medium',
            source: 'comment', key: keyName, display_value: value || `(${length} bytes)`,
            raw_value_available: true, location: { offset: { byte_offset: cursor } },
            risk_explanation: `PNG ${chunkType} chunk "${keyName}" contains embedded text metadata.`, removable: true,
          });
        } else if (chunkType === 'tIME' && length === 7) {
          const year = readU16(bytes, cursor + 8, false);
          const month = bytes[cursor + 10];
          const day = bytes[cursor + 11];
          const hour = bytes[cursor + 12];
          const minute = bytes[cursor + 13];
          const second = bytes[cursor + 14];
          findings.push({
            id: `finding-${fc++}`, category: 'time', severity: 'medium',
            source: 'comment', key: 'tIME',
            display_value: `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')} ${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}:${String(second).padStart(2, '0')}`,
            raw_value_available: true, location: { offset: { byte_offset: cursor } },
            risk_explanation: 'PNG tIME chunk exposes precise file modification timestamp.', removable: true,
          });
        } else if (chunkType === 'iCCP') {
          const profSlice = bytes.subarray(cursor + 8, cursor + 8 + Math.min(length, 80));
          const profName = td.decode(profSlice).split('\0')[0] || 'ICC Profile';
          findings.push({
            id: `finding-${fc++}`, category: 'software', severity: 'low',
            source: 'comment', key: 'iCCP', display_value: profName,
            raw_value_available: true, location: { offset: { byte_offset: cursor } },
            risk_explanation: 'Embedded ICC color profile may identify capture device or editing software.', removable: true,
          });
        }
        cursor = chunkEnd;
      }
    }
    // ── PDF Scanner ──
    else if (ext === 'pdf') {
      const pdfText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 1000000)));
      const pdfPatterns: MetaPattern[] = [
        { key: '/Author', pattern: /\/Author\s*\(([^)]+)\)/i, cat: 'identity', sev: 'high', risk: 'PDF /Author reveals the document author identity.' },
        { key: '/Creator', pattern: /\/Creator\s*\(([^)]+)\)/i, cat: 'software', sev: 'medium', risk: 'PDF /Creator reveals the application used to create the document.' },
        { key: '/Producer', pattern: /\/Producer\s*\(([^)]+)\)/i, cat: 'software', sev: 'medium', risk: 'PDF /Producer reveals the PDF conversion library or tool.' },
        { key: '/Title', pattern: /\/Title\s*\(([^)]+)\)/i, cat: 'document-history', sev: 'medium', risk: 'PDF /Title may contain internal document titles or project names.' },
        { key: '/Subject', pattern: /\/Subject\s*\(([^)]+)\)/i, cat: 'document-history', sev: 'low', risk: 'PDF /Subject may reveal document topic or classification.' },
        { key: '/CreationDate', pattern: /\/CreationDate\s*\(([^)]+)\)/i, cat: 'time', sev: 'medium', risk: 'PDF /CreationDate reveals when the document was originally created.' },
        { key: '/ModDate', pattern: /\/ModDate\s*\(([^)]+)\)/i, cat: 'time', sev: 'medium', risk: 'PDF /ModDate reveals when the document was last modified.' },
      ];
      for (const pp of pdfPatterns) {
        const m = pp.pattern.exec(pdfText);
        if (m && m[1]) {
          findings.push({
            id: `finding-${fc++}`, category: pp.cat, severity: pp.sev,
            source: 'pdf_info', key: pp.key, display_value: m[1].trim(),
            raw_value_available: true, location: { pdf_object: { object_number: 1 } },
            risk_explanation: pp.risk, removable: true,
          });
        }
      }
      if (pdfText.includes('/Type /Metadata') || pdfText.includes('http://ns.adobe.com')) {
        findings.push({
          id: `finding-${fc++}`, category: 'document-history', severity: 'high',
          source: 'xmp', key: 'XMP_Metadata_Stream', display_value: 'Embedded XMP metadata stream',
          raw_value_available: true, location: { pdf_object: { object_number: 5 } },
          risk_explanation: 'PDF contains an embedded XMP XML metadata stream with potential tracking data.', removable: true,
        });
      }
    }
    // ── Office Scanner ──
    else if (ext === 'docx' || ext === 'xlsx' || ext === 'pptx') {
      const zipText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 500000)));
      if (zipText.includes('docProps/core.xml')) {
        const corePatterns: MetaPattern[] = [
          { key: 'dc:creator', pattern: /<dc:creator>([^<]+)/i, cat: 'identity', sev: 'high', risk: 'Office core.xml reveals the document author name.' },
          { key: 'cp:lastModifiedBy', pattern: /<cp:lastModifiedBy>([^<]+)/i, cat: 'identity', sev: 'high', risk: 'Reveals the account name of the last editor.' },
          { key: 'dcterms:created', pattern: /<dcterms:created[^>]*>([^<]+)/i, cat: 'time', sev: 'medium', risk: 'Reveals original document creation timestamp.' },
          { key: 'dcterms:modified', pattern: /<dcterms:modified[^>]*>([^<]+)/i, cat: 'time', sev: 'medium', risk: 'Reveals last modification timestamp.' },
          { key: 'dc:description', pattern: /<dc:description>([^<]+)/i, cat: 'document-history', sev: 'low', risk: 'May contain internal notes or document description.' },
        ];
        for (const cp of corePatterns) {
          const m = cp.pattern.exec(zipText);
          if (m && m[1]) {
            findings.push({
              id: `finding-${fc++}`, category: cp.cat, severity: cp.sev,
              source: 'office_xml', key: cp.key, display_value: m[1].trim(),
              raw_value_available: true, location: { header: { segment: 'docProps/core.xml' } },
              risk_explanation: cp.risk, removable: true,
            });
          }
        }
      }
      if (zipText.includes('vbaProject.bin')) {
        findings.push({
          id: `finding-${fc++}`, category: 'software', severity: 'critical',
          source: 'office_xml', key: 'vbaProject.bin', display_value: 'Executable VBA macro binary detected',
          raw_value_available: true, location: { header: { segment: 'word/vbaProject.bin' } },
          risk_explanation: 'Contains executable VBA macros that may run arbitrary code.', removable: true,
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
      input: { display_name: fileName, size, sha256 },
      detected_format: ext,
      support_level: 'FullSupport',
      findings,
      summary,
    };
  };

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
        console.warn('Tauri IPC scan_file_cmd failed or running in non-Tauri browser mode:', err);
        const isTauriErr = String(err).includes('ipc') || String(err).includes('window.__TAURI');
        if (isTauriErr || typeof window === 'undefined' || !(window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__) {
          if (fileObj) {
            console.info('Parsing real binary bytes of dropped file in browser mode.');
            const realReport = await parseRealFileInBrowser(fileObj);
            setReport(realReport);
          } else {
            setError('Tauri IPC is not available. Please drop a file to scan in browser mode, or run the native Tauri desktop app.');
            setReport(null);
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
