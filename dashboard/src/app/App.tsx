import { useState } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  ChevronDown,
  ChevronUp,
  Download,
  Terminal,
  Package,
  GitBranch,
  Clock,
  Filter,
  ExternalLink,
  Circle,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────

export type VexStatus =
  | "EXPLOITABLE"
  | "NOT_AFFECTED"
  | "NOT_EXPLOITABLE"
  | "UNDER_INVESTIGATION"
  | "exploitable"
  | "not_affected"
  | "not_exploitable"
  | "under_investigation";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

interface SbomComponent {
  name: string;
  version: string;
  purl: string;
  licenses: string[];
}

interface VexEntry {
  id: string;
  cve: string;
  cwe: string[];
  severity: Severity;
  cvss: number;
  description: string;
  component: string;
  version: string;
  vexStatus: string;
  justification: string;
  pocAvailable: boolean;
  pocVector: string;
  codeqlQuery: string;
  affectedLines: string[];
  recommendation: string;
}

interface AnalysisResult {
  packageName: string;
  packageVersion: string;
  analyzedAt: string;
  commitSha: string;
  sbomComponents: SbomComponent[];
  vexEntries: VexEntry[];
  pipelineLog: string[];
  stats: Record<string, number>;
}

// ─── Helper components ──────────────────────────────────────────────────────

const VEX_CONFIG: Record<
  string,
  { label: string; color: string; bg: string; border: string; icon: React.ReactNode }
> = {
  EXPLOITABLE: {
    label: "EXPLOITABLE",
    color: "text-red-400",
    bg: "bg-red-950/40",
    border: "border-red-900/60",
    icon: <XCircle className="w-3.5 h-3.5" />,
  },
  NOT_EXPLOITABLE: {
    label: "NOT_EXPLOITABLE",
    color: "text-blue-400",
    bg: "bg-blue-950/40",
    border: "border-blue-900/60",
    icon: <CheckCircle2 className="w-3.5 h-3.5" />,
  },
  UNDER_INVESTIGATION: {
    label: "UNDER_INVESTIGATION",
    color: "text-yellow-400",
    bg: "bg-yellow-950/40",
    border: "border-yellow-900/60",
    icon: <Clock className="w-3.5 h-3.5" />,
  },
  NOT_AFFECTED: {
    label: "NOT_AFFECTED",
    color: "text-green-400",
    bg: "bg-green-950/40",
    border: "border-green-900/60",
    icon: <CheckCircle2 className="w-3.5 h-3.5" />,
  },
};

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-blue-400",
};

function VexBadge({ status }: { status: string }) {
  const upperStatus = (status || "").toUpperCase();
  const cfg = VEX_CONFIG[upperStatus] || VEX_CONFIG["NOT_AFFECTED"];
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-bold tracking-widest border ${cfg.color} ${cfg.bg} ${cfg.border}`}
    >
      {cfg.icon}
      {cfg.label}
    </span>
  );
}

function SeverityBadge({ severity, cvss }: { severity: Severity; cvss: number }) {
  return (
    <span className={`font-mono text-xs font-bold ${SEVERITY_COLOR[severity] || "text-gray-400"}`}>
      {severity} {(cvss || 0).toFixed(1)}
    </span>
  );
}

function VexCard({ entry }: { entry: VexEntry }) {
  const [open, setOpen] = useState(false);
  const upperStatus = (entry.vexStatus || "").toUpperCase();
  const cfg = VEX_CONFIG[upperStatus] || VEX_CONFIG["NOT_AFFECTED"];

  return (
    <div className={`border ${cfg.border} ${cfg.bg} transition-all duration-150`}>
      <button
        className="w-full text-left px-4 py-3 flex items-start gap-3 hover:brightness-125 transition-all"
        onClick={() => setOpen((v) => !v)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <VexBadge status={entry.vexStatus} />
            <span className="font-mono text-xs text-gray-300">{entry.id}</span>
            <a
              href={`https://nvd.nist.gov/vuln/detail/${entry.cve}`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-xs text-blue-400 hover:text-blue-300 flex items-center gap-0.5"
              onClick={(e) => e.stopPropagation()}
            >
              {entry.cve}
              <ExternalLink className="w-2.5 h-2.5" />
            </a>
            <SeverityBadge severity={entry.severity} cvss={entry.cvss} />
            {entry.cwe?.map((c) => (
              <span key={c} className="font-mono text-[10px] text-gray-400 border border-gray-700 px-1">
                {c}
              </span>
            ))}
          </div>
          <p className="text-sm text-gray-300 leading-snug">{entry.description}</p>
          <p className="mt-1 font-mono text-[11px] text-gray-400">
            {entry.component}@{entry.version}
          </p>
        </div>
        <div className="shrink-0 text-gray-400 mt-0.5">
          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {open && (
        <div className="border-t border-white/5 px-4 py-4 space-y-4 text-sm">
          <div>
            <p className="font-mono text-[10px] text-gray-300 uppercase tracking-widest mb-1">
              VEX Justification
            </p>
            <p className="text-gray-300 leading-relaxed">{entry.justification}</p>
          </div>

          {entry.affectedLines && entry.affectedLines.length > 0 && (
            <div>
              <p className="font-mono text-[10px] text-gray-300 uppercase tracking-widest mb-1">
                Affected Locations
              </p>
              <div className="flex flex-wrap gap-1">
                {entry.affectedLines.map((line) => (
                  <span
                    key={line}
                    className="font-mono text-[11px] bg-gray-900 border border-gray-700 px-2 py-0.5 text-orange-400"
                  >
                    {line}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p className="font-mono text-[10px] text-gray-300 uppercase tracking-widest mb-1">
                CodeQL Query
              </p>
              <span className="font-mono text-[11px] bg-gray-900 border border-gray-700 px-2 py-1 text-purple-400 inline-block">
                {entry.codeqlQuery}
              </span>
            </div>

            {entry.pocAvailable && entry.pocVector && (
              <div>
                <p className="font-mono text-[10px] text-gray-300 uppercase tracking-widest mb-1">
                  PoC Vector
                </p>
                <code className="block font-mono text-[11px] bg-gray-900 border border-red-900/40 px-2 py-1 text-red-300 whitespace-pre-wrap break-all">
                  {entry.pocVector}
                </code>
              </div>
            )}
          </div>

          <div className="border-t border-white/5 pt-3">
            <p className="font-mono text-[10px] text-gray-300 uppercase tracking-widest mb-1">
              Recommendation
            </p>
            <p className="text-gray-300">{entry.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Stats bar ──────────────────────────────────────────────────────────────

function StatBar({ stats, vexEntries }: { stats?: Record<string, number>; vexEntries?: VexEntry[] }) {
  const getCount = (keyUpper: string, keyLower: string) => {
    if (stats && stats[keyLower] !== undefined) return stats[keyLower];
    if (stats && stats[keyUpper] !== undefined) return stats[keyUpper];
    return vexEntries?.filter((e) => (e.vexStatus || "").toUpperCase() === keyUpper).length || 0;
  };

  const items = [
    { label: "EXPLOITABLE", count: getCount("EXPLOITABLE", "exploitable"), color: "text-red-400", dot: "bg-red-400" },
    { label: "NOT_EXPLOITABLE", count: getCount("NOT_EXPLOITABLE", "not_exploitable"), color: "text-blue-400", dot: "bg-blue-400" },
    { label: "UNDER_INVESTIGATION", count: getCount("UNDER_INVESTIGATION", "under_investigation"), color: "text-yellow-400", dot: "bg-yellow-400" },
    { label: "NOT_AFFECTED", count: getCount("NOT_AFFECTED", "not_affected"), color: "text-green-400", dot: "bg-green-400" },
  ];

  const total = stats?.total ?? vexEntries?.length ?? 0;

  return (
    <div className="flex flex-wrap gap-4 py-3 px-4 border border-gray-700 bg-gray-950">
      <div className="font-mono text-xs text-gray-300">
        <span className="text-white font-bold text-sm">{total}</span> CVEs analyzed
      </div>
      {items.map((item) => (
        <div key={item.label} className="flex items-center gap-1.5 font-mono text-xs">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${item.dot}`} />
          <span className={`font-bold ${item.color}`}>{item.count}</span>
          <span className="text-gray-400">{item.label}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Main App ───────────────────────────────────────────────────────────────

const FILTER_OPTIONS = ["ALL", "EXPLOITABLE", "NOT_EXPLOITABLE", "UNDER_INVESTIGATION", "NOT_AFFECTED"] as const;
type FilterOption = (typeof FILTER_OPTIONS)[number];

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [filter, setFilter] = useState<FilterOption>("ALL");
  const [sbomOpen, setSbomOpen] = useState(false);

  const isValidGithubUrl = (u: string) =>
    /^https:\/\/github\.com\/[^/]+\/[^/]+/.test(u.trim());

  async function runAnalysis() {
    if (!isValidGithubUrl(url)) return;

    setResult(null);
    setFilter("ALL");

    try {
      const response = await fetch("http://localhost:5000/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        throw new Error("서버 응답 에러");
      }

      const data: AnalysisResult = await response.json();
      setResult(data);
    } catch (error) {
      console.error("API 연동 에러:", error);
      alert("백엔드 서버에서 결과를 가져오지 못했습니다. Express 서버가 켜져 있는지 확인하세요.");
    }
  }

  const filtered =
    result?.vexEntries?.filter((e) => {
      if (filter === "ALL") return true;
      return (e.vexStatus || "").toUpperCase() === filter;
    }) ?? [];

  const dangerCount = result?.vexEntries
    ? result.vexEntries.filter((e) => {
        const s = (e.vexStatus || "").toUpperCase();
        return s === "EXPLOITABLE" || s === "AFFECTED";
      }).length
    : 0;

  return (
    <div
      className="min-h-screen bg-background text-foreground"
      style={{ fontFamily: "'JetBrains Mono', monospace" }}
    >
      {/* Header */}
      <header className="border-b border-border px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-primary" />
          <span className="font-bold tracking-widest text-sm uppercase">
            VEX Analyzer
          </span>
          <span className="text-gray-500 text-xs">|</span>
          <span className="text-gray-400 text-xs tracking-wide">
            SBOM · CodeQL · PoC · VEX
          </span>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-gray-500 tracking-widest">
          <Circle className="w-2 h-2 fill-green-500 text-green-500" />
          ONLINE
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 space-y-6">
        {/* Input */}
        <div className="space-y-3">
          <label className="text-[10px] text-gray-300 tracking-widest uppercase block">
            GitHub Package URL
          </label>
          <div className="flex gap-2">
            <div className="flex-1 flex items-center border border-gray-700 bg-gray-950 focus-within:border-primary transition-colors">
              <GitBranch className="w-4 h-4 text-gray-400 ml-3 shrink-0" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") runAnalysis();
                }}
                placeholder="https://github.com/org/package"
                className="flex-1 bg-transparent px-3 py-3 text-sm outline-none text-gray-200 placeholder-gray-700"
                style={{ fontFamily: "inherit" }}
                spellCheck={false}
                autoComplete="off"
              />
            </div>
            <button
              onClick={runAnalysis}
              disabled={!isValidGithubUrl(url)}
              className="flex items-center gap-2 px-5 py-3 bg-gray-950 hover:bg-gray-900 text-gray-200 border border-gray-700 font-bold text-xs tracking-widest uppercase disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer shrink-0"
            >
              <Search className="w-3.5 h-3.5 text-gray-400" />
              Analyze
            </button>
          </div>
          {url && !isValidGithubUrl(url) && (
            <p className="text-[11px] text-red-500">
              Enter a valid GitHub URL: https://github.com/org/repo
            </p>
          )}
        </div>

        {/* Results */}
        {result && (
          <div className="space-y-4">
            {/* Package info */}
            <div className="border border-gray-700 bg-gray-950 p-4 flex flex-wrap items-start gap-6">
              <div>
                <p className="text-[10px] text-gray-400 uppercase tracking-widest mb-0.5">Package</p>
                <p className="text-sm font-bold text-white">{result.packageName}</p>
                <p className="text-[11px] text-gray-400">v{result.packageVersion}</p>
              </div>
              <div>
                <p className="text-[10px] text-gray-400 uppercase tracking-widest mb-0.5">Commit</p>
                <p className="font-mono text-xs text-purple-400">{result.commitSha?.slice(0, 12)}</p>
              </div>
              <div>
                <p className="text-[10px] text-gray-400 uppercase tracking-widest mb-0.5">Analyzed</p>
                <p className="text-xs text-gray-400">
                  {result.analyzedAt ? new Date(result.analyzedAt).toLocaleString("ko-KR") : "-"}
                </p>
              </div>
              <div>
                <p className="text-[10px] text-gray-400 uppercase tracking-widest mb-0.5">SBOM Format</p>
                <p className="text-xs text-cyan-400">CycloneDX 1.5</p>
              </div>
              <div>
                <p className="text-[10px] text-gray-400 uppercase tracking-widest mb-0.5">VEX Format</p>
                <p className="text-xs text-purple-400">OpenVEX 0.2.0</p>
              </div>
              <div className="ml-auto">
                <button
                  onClick={() => {
                    const blob = new Blob(
                      [JSON.stringify(result, null, 2)],
                      { type: "application/json" }
                    );
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = `vex-${result.commitSha?.slice(0, 8) || "result"}.json`;
                    a.click();
                  }}
                  className="flex items-center gap-1.5 px-3 py-2 border border-gray-700 text-[10px] tracking-widest text-gray-400 hover:border-gray-500 hover:text-white transition-all"
                >
                  <Download className="w-3 h-3" />
                  EXPORT VEX JSON
                </button>
              </div>
            </div>

            {/* Risk alert */}
            {dangerCount > 0 && (
              <div className="border border-red-900 bg-red-950/30 px-4 py-3 flex items-center gap-3">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <p className="text-sm text-red-300">
                  <span className="font-bold">{dangerCount} vulnerabilities</span> require immediate attention —{" "}
                  {dangerCount} critical/exploitable issue(s) detected.
                </p>
              </div>
            )}

            {/* Stats */}
            <StatBar stats={result.stats} vexEntries={result.vexEntries} />

            {/* SBOM accordion */}
            <div className="border border-gray-700">
              <button
                onClick={() => setSbomOpen((v) => !v)}
                className="w-full flex items-center justify-between px-4 py-3 text-[10px] tracking-widest uppercase text-gray-300 hover:text-gray-300 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Package className="w-3 h-3" />
                  SBOM — {result.sbomComponents?.length || 0} Components
                </div>
                {sbomOpen ? (
                  <ChevronUp className="w-3 h-3" />
                ) : (
                  <ChevronDown className="w-3 h-3" />
                )}
              </button>
              {sbomOpen && (
                <div className="border-t border-gray-700 overflow-x-auto">
                  <table className="w-full text-[11px] font-mono">
                    <thead>
                      <tr className="border-b border-gray-700 bg-gray-950">
                        {["Component", "Version", "PURL", "License"].map((h) => (
                          <th
                            key={h}
                            className="text-left px-4 py-2 text-[10px] text-gray-400 uppercase tracking-widest font-bold"
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {result.sbomComponents?.map((c, i) => (
                        <tr
                          key={c.purl || i}
                          className={`border-b border-gray-700/50 ${i % 2 === 0 ? "bg-transparent" : "bg-gray-950/50"} hover:bg-gray-900/50 transition-colors`}
                        >
                          <td className="px-4 py-2 text-cyan-400">{c.name}</td>
                          <td className="px-4 py-2 text-gray-400">{c.version}</td>
                          <td className="px-4 py-2 text-gray-400 text-[10px]">{c.purl}</td>
                          <td className="px-4 py-2 text-gray-300">{c.licenses?.join(", ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* VEX findings */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-[10px] text-gray-300 uppercase tracking-widest">
                  <Shield className="w-3 h-3" />
                  VEX Findings
                </div>
                <div className="flex items-center gap-1">
                  <Filter className="w-3 h-3 text-gray-400" />
                  <div className="flex">
                    {FILTER_OPTIONS.map((f) => (
                      <button
                        key={f}
                        onClick={() => setFilter(f)}
                        className={`px-2 py-1 text-[10px] font-mono tracking-widest border-r border-gray-700 last:border-0 transition-colors ${
                          filter === f
                            ? "bg-gray-800 text-white"
                            : "text-gray-400 hover:text-white"
                        }`}
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="space-y-1">
                {filtered.length === 0 && (
                  <div className="text-center py-8 text-gray-500 text-sm">
                    No findings for this filter.
                  </div>
                )}
                {filtered.map((entry) => (
                  <VexCard key={entry.id} entry={entry} />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!result && (
          <div className="border border-dashed border-gray-700 py-16 text-center">
            <Terminal className="w-8 h-8 text-gray-500 mx-auto mb-3" />
            <p className="text-gray-400 text-sm">
              Enter a GitHub JS package URL to begin SBOM + CodeQL + PoC analysis
            </p>
            <p className="text-gray-500 text-[11px] mt-1">
              Results will be tagged with OpenVEX status: EXPLOITABLE · NOT_EXPLOITABLE · UNDER_INVESTIGATION · NOT_AFFECTED
            </p>
          </div>
        )}
      </main>

      <footer className="border-t border-gray-700/50 px-6 py-4 mt-12">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <p className="text-[10px] text-gray-500 tracking-widest">
            VEX ANALYZER — SBOM · CODEQL · POC INFERENCE
          </p>
          <div className="flex items-center gap-3 text-[10px] text-gray-500">
            <span>CycloneDX 1.5</span>
            <span>·</span>
            <span>OpenVEX 0.2.0</span>
            <span>·</span>
            <span>SARIF 2.1</span>
          </div>
        </div>
      </footer>
    </div>
  );
}