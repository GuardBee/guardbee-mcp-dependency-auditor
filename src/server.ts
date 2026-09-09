import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { parseNpmManifest } from "./parsers/npm.js";
import { parsePipRequirements } from "./parsers/pip.js";
import { queryOsvBatch, getSeverity, getFixedVersion, type Ecosystem } from "./osv.js";
import type { AuditResult } from "./osv.js";

function formatReport(
  results: AuditResult[],
  ecosystem: string,
  durationMs: number
): string {
  const vulnerable = results.filter((r) => r.vulns.length > 0);
  const totalVulns = results.reduce((s, r) => s + r.vulns.length, 0);

  if (totalVulns === 0) {
    return `✅ No known vulnerabilities found in ${results.length} ${ecosystem} packages (${durationMs}ms).`;
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const r of vulnerable) {
    for (const v of r.vulns) {
      counts[getSeverity(v)]++;
    }
  }

  const lines: string[] = [
    `⚠️  Found ${totalVulns} vulnerabilit${totalVulns === 1 ? "y" : "ies"} in ${vulnerable.length}/${results.length} ${ecosystem} packages (${durationMs}ms)`,
    `   Critical: ${counts.critical}  High: ${counts.high}  Medium: ${counts.medium}  Low: ${counts.low}  Unknown: ${counts.unknown}`,
    "",
  ];

  for (const result of vulnerable) {
    for (const vuln of result.vulns) {
      const sev = getSeverity(vuln);
      const fixed = getFixedVersion(vuln, result.name);
      const cveIds = (vuln.aliases ?? []).filter((a) => a.startsWith("CVE-")).join(", ");
      const nvdUrl = cveIds
        ? `https://nvd.nist.gov/vuln/detail/${cveIds.split(", ")[0]}`
        : `https://osv.dev/vulnerability/${vuln.id}`;

      lines.push(`[${sev.toUpperCase()}] ${result.name}@${result.version}`);
      lines.push(`  ID      : ${vuln.id}${cveIds ? ` (${cveIds})` : ""}`);
      lines.push(`  Summary : ${vuln.summary ?? "No summary available"}`);
      if (fixed) lines.push(`  Fix     : upgrade to ${result.name}@${fixed}`);
      lines.push(`  Details : ${nvdUrl}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

export async function startServer() {
  const server = new McpServer({
    name: "guardbee-dependency-auditor",
    version: "0.1.0",
  });

  server.tool(
    "audit_npm",
    "Audit npm dependencies from a package.json (and optionally package-lock.json) for known CVEs using the OSV database",
    {
      directory: z.string().describe("Path to the directory containing package.json"),
      includeDevDeps: z
        .boolean()
        .optional()
        .describe("Include devDependencies in the audit (default: false)"),
    },
    async ({ directory, includeDevDeps = false }) => {
      const start = Date.now();
      let deps = parseNpmManifest(directory);

      if (deps.length === 0) {
        return {
          content: [{ type: "text", text: `No package.json found or no dependencies in ${directory}` }],
        };
      }

      if (!includeDevDeps) deps = deps.filter((d) => !d.isDev);

      const packages = deps.map((d) => ({ name: d.name, version: d.version, ecosystem: "npm" as Ecosystem }));
      const results = await queryOsvBatch(packages);
      const report = formatReport(results, "npm", Date.now() - start);

      return { content: [{ type: "text", text: report }] };
    }
  );

  server.tool(
    "audit_pip",
    "Audit Python dependencies from requirements.txt or pyproject.toml for known CVEs using the OSV database",
    {
      directory: z.string().describe("Path to the directory containing requirements.txt or pyproject.toml"),
    },
    async ({ directory }) => {
      const start = Date.now();
      const deps = parsePipRequirements(directory);

      if (deps.length === 0) {
        return {
          content: [{ type: "text", text: `No requirements.txt or pyproject.toml found in ${directory}` }],
        };
      }

      const packages = deps.map((d) => ({ name: d.name, version: d.version, ecosystem: "PyPI" as Ecosystem }));
      const results = await queryOsvBatch(packages);
      const report = formatReport(results, "pip", Date.now() - start);

      return { content: [{ type: "text", text: report }] };
    }
  );

  server.tool(
    "audit_package",
    "Audit a single package by name, version, and ecosystem",
    {
      name: z.string().describe("Package name"),
      version: z.string().describe("Package version (e.g. 1.2.3)"),
      ecosystem: z
        .enum(["npm", "PyPI", "crates.io", "Maven", "Go", "RubyGems"])
        .describe("Package ecosystem"),
    },
    async ({ name, version, ecosystem }) => {
      const start = Date.now();
      const results = await queryOsvBatch([{ name, version, ecosystem: ecosystem as Ecosystem }]);
      const report = formatReport(results, ecosystem, Date.now() - start);
      return { content: [{ type: "text", text: report }] };
    }
  );

  server.tool(
    "audit_directory",
    "Auto-detect and audit all supported manifests (package.json, requirements.txt) in a directory",
    {
      directory: z.string().describe("Path to the project root directory"),
      includeDevDeps: z.boolean().optional().describe("Include dev dependencies for npm (default: false)"),
    },
    async ({ directory, includeDevDeps = false }) => {
      const start = Date.now();
      const lines: string[] = [];

      // npm
      let npmDeps = parseNpmManifest(directory);
      if (npmDeps.length > 0) {
        if (!includeDevDeps) npmDeps = npmDeps.filter((d) => !d.isDev);
        const npmPkgs = npmDeps.map((d) => ({ name: d.name, version: d.version, ecosystem: "npm" as Ecosystem }));
        const npmResults = await queryOsvBatch(npmPkgs);
        lines.push("── npm ─────────────────────────────────────────");
        lines.push(formatReport(npmResults, "npm", 0));
      }

      // pip
      const pipDeps = parsePipRequirements(directory);
      if (pipDeps.length > 0) {
        const pipPkgs = pipDeps.map((d) => ({ name: d.name, version: d.version, ecosystem: "PyPI" as Ecosystem }));
        const pipResults = await queryOsvBatch(pipPkgs);
        lines.push("── pip ─────────────────────────────────────────");
        lines.push(formatReport(pipResults, "pip", 0));
      }

      if (lines.length === 0) {
        return {
          content: [{ type: "text", text: `No supported manifest files found in ${directory}` }],
        };
      }

      lines.unshift(`🔍 Audited project in ${directory} (${Date.now() - start}ms)\n`);
      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
