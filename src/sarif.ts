import { getSeverity, getFixedVersion } from "./osv.js";
import type { AuditResult, OsvVuln } from "./osv.js";

// ── SARIF 2.1.0 types (minimal) ───────────────────────────────────────────────

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties: { "problem.severity": string; tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
    };
  }>;
}

function severityToLevel(sev: string): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

function cveUrl(vuln: OsvVuln): string {
  const cve = (vuln.aliases ?? []).find((a) => a.startsWith("CVE-"));
  return cve
    ? `https://nvd.nist.gov/vuln/detail/${cve}`
    : `https://osv.dev/vulnerability/${vuln.id}`;
}

function manifestUri(ecosystem: string): string {
  if (ecosystem === "npm") return "package.json";
  if (ecosystem === "PyPI") return "requirements.txt";
  return "pom.xml";
}

export function buildSarif(toolVersion: string, results: AuditResult[]): object {
  const rulesMap = new Map<string, SarifRule>();
  const sarifResults: SarifResult[] = [];

  for (const pkg of results) {
    for (const vuln of pkg.vulns) {
      if (!rulesMap.has(vuln.id)) {
        rulesMap.set(vuln.id, {
          id: vuln.id,
          name: vuln.id.replace(/[^a-zA-Z0-9]/g, ""),
          shortDescription: { text: vuln.summary ?? vuln.id },
          helpUri: cveUrl(vuln),
          properties: {
            "problem.severity": getSeverity(vuln),
            tags: ["security", "supply-chain", "dependency"],
          },
        });
      }

      const sev = getSeverity(vuln);
      const fixed = getFixedVersion(vuln, pkg.name);
      const cveIds = (vuln.aliases ?? []).filter((a) => a.startsWith("CVE-")).join(", ");

      const msg = [
        `${pkg.name}@${pkg.version} has a known vulnerability.`,
        vuln.summary ? `Summary: ${vuln.summary}` : "",
        cveIds ? `CVE: ${cveIds}` : "",
        fixed ? `Fix: upgrade to ${pkg.name}@${fixed}` : "",
      ]
        .filter(Boolean)
        .join(" ");

      sarifResults.push({
        ruleId: vuln.id,
        level: severityToLevel(sev),
        message: { text: msg },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: manifestUri(pkg.ecosystem),
                uriBaseId: "%SRCROOT%",
              },
            },
          },
        ],
      });
    }
  }

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "@guardbee/mcp-dependency-auditor",
            version: toolVersion,
            informationUri: "https://guardbee.ai",
            rules: Array.from(rulesMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };
}
