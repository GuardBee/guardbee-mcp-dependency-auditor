import { readFileSync, existsSync } from "fs";
import { join } from "path";

export interface Dependency {
  name: string;
  version: string;
  isDev: boolean;
  source: "direct" | "lockfile";
}

function cleanVersion(v: string): string {
  // Strip semver range operators: ^1.2.3 → 1.2.3
  return v.replace(/^[\^~>=<]+/, "").split(" ")[0] ?? v;
}

export function parseNpmManifest(dir: string): Dependency[] {
  const manifestPath = join(dir, "package.json");
  if (!existsSync(manifestPath)) return [];

  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  } catch {
    return [];
  }

  const deps: Dependency[] = [];

  // Try package-lock.json first (locked versions are more accurate)
  const lockPath = join(dir, "package-lock.json");
  if (existsSync(lockPath)) {
    try {
      const lock = JSON.parse(readFileSync(lockPath, "utf8")) as {
        packages?: Record<string, { version: string; dev?: boolean }>;
        dependencies?: Record<string, { version: string; dev?: boolean }>;
      };

      // v2/v3 lock format
      if (lock.packages) {
        for (const [pkgPath, info] of Object.entries(lock.packages)) {
          if (!pkgPath || pkgPath === "") continue; // root
          const name = pkgPath.replace(/^node_modules\//, "").replace(/\/node_modules\//g, "/");
          if (info.version) {
            deps.push({ name, version: info.version, isDev: !!info.dev, source: "lockfile" });
          }
        }
        return deps;
      }

      // v1 lock format
      if (lock.dependencies) {
        for (const [name, info] of Object.entries(lock.dependencies)) {
          if (info.version) {
            deps.push({ name, version: info.version, isDev: !!info.dev, source: "lockfile" });
          }
        }
        return deps;
      }
    } catch {
      // fall through to manifest parsing
    }
  }

  // Fallback: parse package.json directly (versions may have ranges)
  const sections: Array<[keyof typeof manifest, boolean]> = [
    ["dependencies", false],
    ["devDependencies", true],
    ["peerDependencies", false],
    ["optionalDependencies", false],
  ];

  for (const [section, isDev] of sections) {
    const obj = manifest[section];
    if (obj && typeof obj === "object") {
      for (const [name, version] of Object.entries(obj as Record<string, string>)) {
        if (typeof version === "string") {
          deps.push({ name, version: cleanVersion(version), isDev, source: "direct" });
        }
      }
    }
  }

  return deps;
}
