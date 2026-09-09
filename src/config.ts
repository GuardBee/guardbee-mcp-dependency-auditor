import { readFileSync, existsSync } from "fs";
import { resolve, join } from "path";

// ── guardbee.yml schema (dependency-auditor section) ──────────────────────────
//
// dependency-auditor:
//   fail-on: high          # critical | high | medium | low
//   include-dev: false
//   ignore:                # CVE / GHSA IDs to ignore
//     - "GHSA-xxxx-xxxx-xxxx"
//     - "CVE-2023-12345"

export interface DependencyAuditorConfig {
  failOn: string;
  includeDev: boolean;
  ignore: string[];
}

const DEFAULTS: DependencyAuditorConfig = {
  failOn: "high",
  includeDev: false,
  ignore: [],
};

function findConfigFile(startDir: string): string | null {
  const names = ["guardbee.yml", "guardbee.yaml", ".guardbee.yml"];
  let dir = resolve(startDir);

  for (let i = 0; i < 5; i++) {
    for (const name of names) {
      const p = join(dir, name);
      if (existsSync(p)) return p;
    }
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function parseYaml(content: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let currentSection: string | null = null;
  let currentKey: string | null = null;
  let currentList: string[] | null = null;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.replace(/#.*$/, "");
    if (!line.trim()) continue;
    const indent = line.match(/^(\s*)/)?.[1].length ?? 0;

    if (indent === 0 && line.trim().endsWith(":")) {
      if (currentKey && currentList && currentSection) {
        (root[currentSection] as Record<string, unknown>)[currentKey] = currentList;
        currentList = null; currentKey = null;
      }
      currentSection = line.trim().slice(0, -1);
      root[currentSection] = {};
      continue;
    }

    if (indent === 2 && currentSection) {
      if (currentKey && currentList) {
        (root[currentSection] as Record<string, unknown>)[currentKey] = currentList;
        currentList = null; currentKey = null;
      }
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;
      const key = line.slice(0, colonIdx).trim();
      const value = line.slice(colonIdx + 1).trim();
      if (value === "") { currentKey = key; currentList = []; }
      else (root[currentSection] as Record<string, unknown>)[key] = value;
      continue;
    }

    if (indent === 4 && currentList !== null) {
      currentList.push(line.trim().replace(/^-\s*/, "").replace(/^['"]|['"]$/g, ""));
      continue;
    }
  }

  if (currentKey && currentList && currentSection) {
    (root[currentSection] as Record<string, unknown>)[currentKey] = currentList;
  }
  return root;
}

export function loadConfig(searchDir: string, cliOverrides: Partial<DependencyAuditorConfig> = {}): DependencyAuditorConfig {
  const configPath = findConfigFile(searchDir);
  if (!configPath) return { ...DEFAULTS, ...cliOverrides };

  let fileConfig: Partial<DependencyAuditorConfig> = {};
  try {
    const raw = readFileSync(configPath, "utf8");
    const parsed = parseYaml(raw);
    const section = parsed["dependency-auditor"] as Record<string, unknown> | undefined;
    if (section) {
      if (typeof section["fail-on"] === "string") fileConfig.failOn = section["fail-on"];
      if (typeof section["include-dev"] === "string") fileConfig.includeDev = section["include-dev"] === "true";
      if (Array.isArray(section["ignore"])) fileConfig.ignore = section["ignore"] as string[];
    }
  } catch { /* ignore */ }

  return { ...DEFAULTS, ...fileConfig, ...cliOverrides };
}

export function configFilePath(searchDir: string): string | null {
  return findConfigFile(searchDir);
}
