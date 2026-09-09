#!/usr/bin/env node
import { startServer } from "./server.js";
import { parseNpmManifest } from "./parsers/npm.js";
import { parsePipRequirements } from "./parsers/pip.js";
import { queryOsvBatch, getSeverity, getFixedVersion, type Ecosystem } from "./osv.js";
import type { AuditResult } from "./osv.js";
import { buildSarif } from "./sarif.js";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
function getVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf8")) as { version: string };
    return pkg.version;
  } catch { return "0.0.0"; }
}

// ── Severity helpers ───────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function meetsThreshold(sev: string, threshold: string): boolean {
  return (SEVERITY_RANK[sev] ?? 4) <= (SEVERITY_RANK[threshold] ?? 1);
}

// ── Output ─────────────────────────────────────────────────────────────────────

function printText(results: AuditResult[], label: string, durationMs: number): void {
  const vulnerable = results.filter((r) => r.vulns.length > 0);
  const total = results.length;

  if (vulnerable.length === 0) {
    console.log(`✅ No vulnerabilities found in ${total} ${label} packages (${durationMs}ms)`);
    return;
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const r of vulnerable) {
    for (const v of r.vulns) {
      const s = getSeverity(v);
      counts[s] = (counts[s] ?? 0) + 1;
    }
  }

  console.log(`⚠️  Found vulnerabilities in ${vulnerable.length}/${total} ${label} packages (${durationMs}ms)`);
  console.log(`   Critical: ${counts.critical}  High: ${counts.high}  Medium: ${counts.medium}  Low: ${counts.low}`);
  console.log("");

  for (const r of vulnerable) {
    for (const v of r.vulns) {
      const sev = getSeverity(v);
      const fixed = getFixedVersion(v, r.name);
      const cveIds = (v.aliases ?? []).filter((a) => a.startsWith("CVE-")).join(", ");
      const url = cveIds
        ? `https://nvd.nist.gov/vuln/detail/${cveIds.split(", ")[0]}`
        : `https://osv.dev/vulnerability/${v.id}`;

      console.log(`[${sev.toUpperCase()}] ${r.name}@${r.version}`);
      console.log(`  ID      : ${v.id}${cveIds ? ` (${cveIds})` : ""}`);
      console.log(`  Summary : ${v.summary ?? "No summary available"}`);
      if (fixed) console.log(`  Fix     : upgrade to ${r.name}@${fixed}`);
      console.log(`  Details : ${url}`);
      console.log("");
    }
  }
}

// ── CLI ────────────────────────────────────────────────────────────────────────

function parseArgs(args: string[]): { positionals: string[]; failOn: string; includeDev: boolean; format: string } {
  const positionals: string[] = [];
  let failOn = "high";
  let includeDev = false;
  let format = "text";

  for (const arg of args) {
    if (arg.startsWith("--fail-on=")) failOn = arg.split("=")[1] ?? "high";
    else if (arg.startsWith("--format=")) format = arg.split("=")[1] ?? "text";
    else if (arg === "--include-dev") includeDev = true;
    else if (!arg.startsWith("--")) positionals.push(arg);
  }

  return { positionals, failOn, includeDev, format };
}

function exitCode(results: AuditResult[], failOn: string): number {
  for (const r of results) {
    for (const v of r.vulns) {
      if (meetsThreshold(getSeverity(v), failOn)) return 1;
    }
  }
  return 0;
}

async function runCli(cmd: string, rawArgs: string[]): Promise<void> {
  const { positionals, failOn, includeDev, format } = parseArgs(rawArgs);

  // ── audit-pkg ──────────────────────────────────────────────────────────────
  if (cmd === "audit-pkg") {
    const [name, version, ecosystem] = positionals;
    if (!name || !version || !ecosystem) {
      console.error("Usage: guardbee-dependency-auditor audit-pkg <name> <version> <ecosystem>");
      console.error("  ecosystems: npm, PyPI, crates.io, Maven, Go, RubyGems");
      process.exit(2);
    }
    const results = await queryOsvBatch([{ name, version, ecosystem: ecosystem as Ecosystem }]);
    if (format === "json") {
      console.log(JSON.stringify(results, null, 2));
    } else if (format === "sarif") {
      console.log(JSON.stringify(buildSarif(getVersion(), results), null, 2));
    } else {
      printText(results, ecosystem, 0);
    }
    process.exit(exitCode(results, failOn));
  }

  // ── audit / audit-npm / audit-pip ─────────────────────────────────────────
  const dir = positionals[0];
  if (!dir) {
    console.error(`Usage: guardbee-dependency-auditor ${cmd} <directory> [--fail-on=high] [--include-dev] [--format=text|json]`);
    process.exit(2);
  }

  const start = Date.now();
  const allResults: AuditResult[] = [];

  if (cmd !== "audit-pip") {
    let deps = parseNpmManifest(dir);
    if (!includeDev) deps = deps.filter((d) => !d.isDev);
    if (deps.length > 0) {
      const pkgs = deps.map((d) => ({ name: d.name, version: d.version, ecosystem: "npm" as Ecosystem }));
      allResults.push(...(await queryOsvBatch(pkgs)));
    }
  }

  if (cmd !== "audit-npm") {
    const deps = parsePipRequirements(dir);
    if (deps.length > 0) {
      const pkgs = deps.map((d) => ({ name: d.name, version: d.version, ecosystem: "PyPI" as Ecosystem }));
      allResults.push(...(await queryOsvBatch(pkgs)));
    }
  }

  if (allResults.length === 0) {
    console.error(`No supported manifest files found in: ${dir}`);
    process.exit(2);
  }

  if (format === "json") {
    console.log(JSON.stringify({ results: allResults, durationMs: Date.now() - start }, null, 2));
  } else if (format === "sarif") {
    console.log(JSON.stringify(buildSarif(getVersion(), allResults), null, 2));
  } else {
    printText(allResults, cmd === "audit-npm" ? "npm" : cmd === "audit-pip" ? "pip" : "total", Date.now() - start);
  }

  process.exit(exitCode(allResults, failOn));
}

function printHelp(): void {
  console.log(`@guardbee/mcp-dependency-auditor

Usage (MCP server):
  guardbee-dependency-auditor [serve]

Usage (CLI):
  guardbee-dependency-auditor audit <dir>      Auto-detect npm/pip manifests
  guardbee-dependency-auditor audit-npm <dir>  Audit npm only
  guardbee-dependency-auditor audit-pip <dir>  Audit pip only
  guardbee-dependency-auditor audit-pkg <name> <version> <ecosystem>

Options:
  --fail-on=<level>   Exit 1 if findings at this severity or above (default: high)
                      Levels: critical | high | medium | low
  --include-dev       Include devDependencies (npm only)
  --format=<fmt>      Output format: text (default) | json

Exit codes:
  0  No findings at or above --fail-on threshold
  1  Findings found at or above threshold
  2  Error / bad arguments
`);
}

// ── Entry point ────────────────────────────────────────────────────────────────

const [, , firstArg, ...rest] = process.argv;

if (!firstArg || firstArg === "serve") {
  startServer().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
} else if (firstArg === "--help" || firstArg === "-h") {
  printHelp();
  process.exit(0);
} else if (["audit", "audit-npm", "audit-pip", "audit-pkg"].includes(firstArg)) {
  runCli(firstArg, rest).catch((err) => {
    console.error("Error:", (err as Error).message);
    process.exit(2);
  });
} else {
  console.error(`Unknown command: ${firstArg}`);
  console.error("Run with --help for usage.");
  process.exit(2);
}
