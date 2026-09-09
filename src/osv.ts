export type Ecosystem = "npm" | "PyPI" | "crates.io" | "Maven" | "Go" | "RubyGems";

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { name: string; ecosystem: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
  aliases?: string[];
}

export interface AuditResult {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  vulns: OsvVuln[];
}

const OSV_API = "https://api.osv.dev/v1";
const BATCH_SIZE = 1000;

export async function queryOsvBatch(
  packages: Array<{ name: string; version: string; ecosystem: Ecosystem }>
): Promise<AuditResult[]> {
  const results: AuditResult[] = [];

  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const body = {
      queries: batch.map((p) => ({
        version: p.version,
        package: { name: p.name, ecosystem: p.ecosystem },
      })),
    };

    const res = await fetch(`${OSV_API}/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      throw new Error(`OSV API error: ${res.status} ${await res.text()}`);
    }

    const data = (await res.json()) as { results: Array<{ vulns?: OsvVuln[] }> };

    for (let j = 0; j < batch.length; j++) {
      const pkg = batch[j];
      const vulns = data.results[j]?.vulns ?? [];
      if (pkg) {
        results.push({ name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, vulns });
      }
    }
  }

  return results;
}

export function getSeverity(vuln: OsvVuln): "critical" | "high" | "medium" | "low" | "unknown" {
  // Try CVSS scores first
  for (const s of vuln.severity ?? []) {
    if (s.type === "CVSS_V3" || s.type === "CVSS_V2") {
      const score = parseFloat(s.score);
      if (!isNaN(score)) {
        if (score >= 9.0) return "critical";
        if (score >= 7.0) return "high";
        if (score >= 4.0) return "medium";
        return "low";
      }
    }
  }

  // Fall back to text heuristics in summary
  const text = (vuln.summary ?? vuln.details ?? "").toLowerCase();
  if (text.includes("critical") || text.includes("rce") || text.includes("remote code")) return "critical";
  if (text.includes("high") || text.includes("sql injection") || text.includes("auth bypass")) return "high";
  if (text.includes("medium") || text.includes("xss") || text.includes("csrf")) return "medium";
  if (text.includes("low") || text.includes("info")) return "low";

  return "unknown";
}

export function getFixedVersion(vuln: OsvVuln, pkgName: string): string | null {
  for (const affected of vuln.affected ?? []) {
    if (affected.package.name.toLowerCase() !== pkgName.toLowerCase()) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}
