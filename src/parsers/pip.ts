import { readFileSync, existsSync } from "fs";
import { join } from "path";
import type { Dependency } from "./npm.js";

function cleanPipVersion(v: string): string {
  return v.replace(/[^0-9.]/g, "").split(",")[0] ?? v;
}

export function parsePipRequirements(dir: string): Dependency[] {
  const candidates = [
    "requirements.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
    "requirements/production.txt",
  ];

  const deps: Dependency[] = [];

  for (const candidate of candidates) {
    const filePath = join(dir, candidate);
    if (!existsSync(filePath)) continue;

    try {
      const lines = readFileSync(filePath, "utf8").split("\n");
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith("#") || line.startsWith("-r") || line.startsWith("--")) continue;

        // package==1.2.3 or package>=1.2.3,<2.0
        const match = line.match(/^([A-Za-z0-9_\-\.]+)\s*([><=!]+.*)?$/);
        if (!match) continue;

        const name = match[1];
        const versionSpec = match[2] ?? "";
        // Extract pinned version from ==1.2.3
        const pinned = versionSpec.match(/==([0-9][0-9a-z.\-+]*)/i);
        const version = pinned ? pinned[1] : cleanPipVersion(versionSpec.replace(/^[><=!]+/, ""));

        if (name && version) {
          deps.push({ name, version, isDev: false, source: "direct" });
        }
      }
    } catch {
      continue;
    }
  }

  // Also check pyproject.toml [project.dependencies]
  const pyprojectPath = join(dir, "pyproject.toml");
  if (existsSync(pyprojectPath)) {
    try {
      const content = readFileSync(pyprojectPath, "utf8");
      const depsSection = content.match(/\[project\.dependencies\]([\s\S]*?)(?=\[|$)/);
      if (depsSection) {
        const lines = depsSection[1].split("\n");
        for (const line of lines) {
          const m = line.match(/"([A-Za-z0-9_\-\.]+)\s*([><=!]+[^"]*)?"/);
          if (!m) continue;
          const name = m[1];
          const pinned = (m[2] ?? "").match(/==([0-9][0-9a-z.\-+]*)/i);
          const version = pinned ? pinned[1] : "0";
          if (name) deps.push({ name, version, isDev: false, source: "direct" });
        }
      }
    } catch {
      // ignore
    }
  }

  return deps;
}
