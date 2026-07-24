import React, { useState, useMemo } from 'react';
import {
  Finding,
  FindingCategory,
  FindingLocation,
  FindingSummary,
  Severity,
} from '../types/pfg';
import {
  ShieldAlert,
  ShieldCheck,
  Eye,
  EyeOff,
  Search,
  MapPin,
  User,
  Smartphone,
  Clock,
  Code,
  History,
  MessageSquare,
  Layers,
  Image as ImageIcon,
  Key,
  Wifi,
  Lock,
  HardDrive,
  Terminal,
  HelpCircle,
  AlertTriangle,
  CheckCircle2,
  FileCode2,
} from 'lucide-react';

export interface FindingsListProps {
  findings: Finding[];
  summary?: FindingSummary;
  showRawValues: boolean;
  onToggleRawValues: (show: boolean) => void;
  detectedFormat?: string;
}

type FilterSeverity = 'all' | Severity;

function formatLocation(location: FindingLocation): string {
  if ('header' in location) {
    return `Header: ${location.header.segment}`;
  }
  if ('offset' in location) {
    const hex = location.offset.byte_offset.toString(16).toUpperCase();
    return `Offset: 0x${hex} (${location.offset.byte_offset} bytes)`;
  }
  if ('pdf_object' in location) {
    return `PDF Object #${location.pdf_object.object_number}`;
  }
  return 'Unknown Location';
}

function getCategoryIcon(category: FindingCategory) {
  switch (category) {
    case 'location':
      return <MapPin className="w-3.5 h-3.5" />;
    case 'identity':
      return <User className="w-3.5 h-3.5" />;
    case 'device':
      return <Smartphone className="w-3.5 h-3.5" />;
    case 'time':
      return <Clock className="w-3.5 h-3.5" />;
    case 'software':
      return <Code className="w-3.5 h-3.5" />;
    case 'document-history':
      return <History className="w-3.5 h-3.5" />;
    case 'comments':
      return <MessageSquare className="w-3.5 h-3.5" />;
    case 'embedded-content':
      return <Layers className="w-3.5 h-3.5" />;
    case 'thumbnail':
      return <ImageIcon className="w-3.5 h-3.5" />;
    case 'unique-identifier':
      return <Key className="w-3.5 h-3.5" />;
    case 'network':
      return <Wifi className="w-3.5 h-3.5" />;
    case 'credentials':
      return <Lock className="w-3.5 h-3.5" />;
    case 'filesystem':
      return <HardDrive className="w-3.5 h-3.5" />;
    case 'technical':
      return <Terminal className="w-3.5 h-3.5" />;
    default:
      return <HelpCircle className="w-3.5 h-3.5" />;
  }
}

function getSeverityBadgeClass(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'badge-severity badge-critical';
    case 'high':
      return 'badge-severity badge-high';
    case 'medium':
      return 'badge-severity badge-medium';
    case 'low':
      return 'badge-severity badge-low';
    case 'informational':
      return 'badge-severity badge-informational';
  }
}

export const FindingsList: React.FC<FindingsListProps> = ({
  findings,
  summary,
  showRawValues,
  onToggleRawValues,
  detectedFormat,
}) => {
  const [activeFilter, setActiveFilter] = useState<FilterSeverity>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Calculate severity counts
  const counts = useMemo(() => {
    if (summary) {
      return {
        all: findings.length,
        critical: summary.critical,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        informational: summary.informational,
      };
    }
    return {
      all: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      informational: findings.filter((f) => f.severity === 'informational').length,
    };
  }, [findings, summary]);

  // Filter findings based on tab & search query
  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      if (activeFilter !== 'all' && finding.severity !== activeFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchKey = finding.key.toLowerCase().includes(q);
        const matchCat = finding.category.toLowerCase().includes(q);
        const matchRisk = finding.risk_explanation.toLowerCase().includes(q);
        const matchVal = finding.display_value?.toLowerCase().includes(q) ?? false;
        return matchKey || matchCat || matchRisk || matchVal;
      }
      return true;
    });
  }, [findings, activeFilter, searchQuery]);

  const filterTabs: { id: FilterSeverity; label: string; count: number; colorClass?: string }[] = [
    { id: 'all', label: 'All', count: counts.all },
    { id: 'critical', label: 'Critical', count: counts.critical, colorClass: 'text-red-400' },
    { id: 'high', label: 'High', count: counts.high, colorClass: 'text-orange-400' },
    { id: 'medium', label: 'Medium', count: counts.medium, colorClass: 'text-amber-400' },
    { id: 'low', label: 'Low', count: counts.low, colorClass: 'text-blue-400' },
    { id: 'informational', label: 'Info', count: counts.informational, colorClass: 'text-sky-400' },
  ];

  if (findings.length === 0) {
    return (
      <div className="glass-card p-10 text-center flex flex-col items-center justify-center space-y-4">
        <div className="p-4 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
          <ShieldCheck className="w-12 h-12" />
        </div>
        <div className="space-y-1">
          <h3 className="text-xl font-bold text-white">No Privacy Risks Detected</h3>
          <p className="text-sm text-slate-400 max-w-md">
            This file was scanned thoroughly. No sensitive EXIF tags, PII, GPS coordinates, or credentials were found.
          </p>
        </div>
        {detectedFormat && (
          <span className="px-3 py-1 rounded-full bg-slate-800 text-xs font-mono text-slate-300 border border-slate-700">
            Format: {detectedFormat.toUpperCase()}
          </span>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Controls Bar */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 glass-card p-5">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white">Detected Findings</h2>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                {findings.length} total
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Review privacy issues, location tags, and sensitive attributes found in this file.
            </p>
          </div>
        </div>

        {/* Unmasked Values Toggle Button */}
        <div className="flex items-center gap-3 w-full lg:w-auto justify-end">
          <button
            type="button"
            onClick={() => onToggleRawValues(!showRawValues)}
            className={`btn-secondary text-xs flex items-center gap-2 py-2 px-3.5 transition-all ${
              showRawValues
                ? 'border-indigo-500/50 bg-indigo-500/10 text-indigo-300 shadow-[0_0_15px_rgba(99,102,241,0.2)]'
                : 'text-slate-300'
            }`}
          >
            {showRawValues ? (
              <>
                <EyeOff className="w-4 h-4 text-indigo-400" />
                <span>Mask Raw Values</span>
              </>
            ) : (
              <>
                <Eye className="w-4 h-4 text-slate-400" />
                <span>Reveal Raw Values</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Filter Tabs & Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto p-1.5 rounded-xl bg-slate-950/60 border border-slate-800 scrollbar-none">
          {filterTabs.map((tab) => {
            const isActive = activeFilter === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveFilter(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 whitespace-nowrap ${
                  isActive
                    ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <span>{tab.label}</span>
                <span
                  className={`px-1.5 py-0.2 rounded-full text-[10px] ${
                    isActive
                      ? 'bg-indigo-700/80 text-white'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search Input */}
        <div className="relative min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search findings, keys, risks..."
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/60 focus:ring-1 focus:ring-indigo-500/60 transition-colors"
          />
        </div>
      </div>

      {/* Findings Cards List */}
      {filteredFindings.length === 0 ? (
        <div className="glass-card p-8 text-center text-slate-400 text-sm">
          No findings match the selected filter or search criteria.
        </div>
      ) : (
        <div className="space-y-3.5">
          {filteredFindings.map((finding) => (
            <div
              key={finding.id}
              className="glass-card p-5 hover:border-slate-700/80 transition-all duration-200 space-y-3"
            >
              {/* Card Top Header */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-3">
                  {/* Severity Badge */}
                  <span className={getSeverityBadgeClass(finding.severity)}>
                    {finding.severity}
                  </span>

                  {/* Category Pill */}
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-medium bg-slate-800/80 text-slate-300 border border-slate-700/50">
                    {getCategoryIcon(finding.category)}
                    <span className="capitalize">{finding.category}</span>
                  </span>

                  {/* Source Tag */}
                  <span className="text-xs font-mono text-slate-500">
                    [{finding.source}]
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {finding.removable && (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      <CheckCircle2 className="w-3 h-3" />
                      Auto-Sanitizable
                    </span>
                  )}
                  {/* Location badge */}
                  <span className="text-xs font-mono text-slate-400 bg-slate-900/80 px-2.5 py-1 rounded-md border border-slate-800">
                    {formatLocation(finding.location)}
                  </span>
                </div>
              </div>

              {/* Key Name & Value */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
                    <FileCode2 className="w-4 h-4 text-indigo-400" />
                    {finding.key}
                  </h4>
                </div>

                {/* Value Box */}
                <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto">
                  {showRawValues ? (
                    finding.display_value ? (
                      <span className="text-indigo-300 font-medium break-all">
                        {finding.display_value}
                      </span>
                    ) : (
                      <span className="text-slate-500 italic">
                        [Raw value binary or unextractable]
                      </span>
                    )
                  ) : (
                    <div className="flex items-center justify-between text-slate-500">
                      <span>••••••••••••••••••••••••</span>
                      <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-600 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        Masked PII
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Risk Explanation Callout */}
              <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-amber-200/90 text-xs flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="font-semibold text-amber-300">Privacy & Security Risk: </span>
                  <span>{finding.risk_explanation}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default FindingsList;
