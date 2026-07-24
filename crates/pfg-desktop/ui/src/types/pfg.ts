/**
 * Privacy File Guard (PFG) Desktop UI TypeScript Types
 * Synchronized with Rust models in `pfg-model` and `pfg-core`.
 */

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export type FindingCategory =
  | 'location'
  | 'identity'
  | 'device'
  | 'time'
  | 'software'
  | 'document-history'
  | 'comments'
  | 'embedded-content'
  | 'thumbnail'
  | 'unique-identifier'
  | 'network'
  | 'credentials'
  | 'filesystem'
  | 'technical'
  | 'unknown';

export type FindingSource =
  | 'exif'
  | 'xmp'
  | 'iptc'
  | 'comment'
  | 'pdf_info'
  | 'pdf_object'
  | 'file_system'
  | 'office_xml';

export type FindingLocation =
  | { header: { segment: string } }
  | { offset: { byte_offset: number } }
  | { pdf_object: { object_number: number } };

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  source: FindingSource;
  key: string;
  display_value: string | null;
  raw_value_available: boolean;
  location: FindingLocation;
  risk_explanation: string;
  removable: boolean;
}

export interface InputFileMetadata {
  name: string;
  size: number;
  sha256: string;
}

export interface FindingSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface ScanReport {
  schema_version: number;
  tool_version: string;
  operation: string;
  input: InputFileMetadata;
  detected_format: string;
  support_level: string;
  findings: Finding[];
  summary: FindingSummary;
}

export interface VerificationReport {
  original_sha256: string;
  cleaned_sha256: string;
  original_findings_count: number;
  cleaned_findings_count: number;
  verified_clean: boolean;
  assurance_level: string;
}

export interface BatchScanOptions {
  recursive: boolean;
  jobs?: number | null;
  include_values: boolean;
  ignore_patterns: string[];
}

export type CleanProfile = 'Balanced' | 'Strict';

export interface BatchCleanOptions {
  recursive: boolean;
  jobs?: number | null;
  profile: CleanProfile;
  output_dir?: string | null;
  in_place: boolean;
  safe_name: boolean;
  overwrite: boolean;
}

export interface BatchScanReport {
  target_path: string;
  files_scanned: number;
  files_skipped: number;
  total_findings: number;
  reports: ScanReport[];
  summary: FindingSummary;
}

export interface BatchCleanReport {
  target_path: string;
  total_files: number;
  cleaned_files: number;
  skipped_files: number;
  failed_files: number;
  verified_clean_count: number;
  file_reports: VerificationReport[];
}

export interface ScanOptions {
  include_values: boolean;
}

export interface CleanOptions {
  profile: CleanProfile;
  output_path?: string | null;
  in_place: boolean;
  safe_name: boolean;
  overwrite: boolean;
}
