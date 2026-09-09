import { describe, it, expect, beforeEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { parseNpmManifest } from "../parsers/npm.js";
import { parsePipRequirements } from "../parsers/pip.js";
import { getSeverity, getFixedVersion } from "../osv.js";
import type { OsvVuln } from "../osv.js";

// ── Test helpers ──────────────────────────────────────────────────────────────

function makeTmpDir(): string {
  const dir = join(tmpdir(), `auditor-test-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// ── npm parser ────────────────────────────────────────────────────────────────

describe("parseNpmManifest", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  it("returns empty array when no package.json", () => {
    expect(parseNpmManifest(dir)).toEqual([]);
  });

  it("parses package.json dependencies", () => {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({
        dependencies: { express: "^4.18.2" },
        devDependencies: { vitest: "^2.0.0" },
      })
    );
    const deps = parseNpmManifest(dir);
    const express = deps.find((d) => d.name === "express");
    expect(express).toBeDefined();
    expect(express!.version).toBe("4.18.2"); // range stripped
    expect(express!.isDev).toBe(false);
  });

  it("marks devDependencies as isDev=true", () => {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ devDependencies: { vitest: "2.0.0" } })
    );
    const deps = parseNpmManifest(dir);
    expect(deps[0]!.isDev).toBe(true);
  });

  it("prefers package-lock.json v2 locked versions", () => {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ dependencies: { lodash: "^4.0.0" } })
    );
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 2,
        packages: {
          "": {},
          "node_modules/lodash": { version: "4.17.21", dev: false },
        },
      })
    );
    const deps = parseNpmManifest(dir);
    const lodash = deps.find((d) => d.name === "lodash");
    expect(lodash!.version).toBe("4.17.21");
    expect(lodash!.source).toBe("lockfile");
  });

  it("handles package-lock.json v1 dependencies field", () => {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ dependencies: { moment: "*" } })
    );
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: { moment: { version: "2.29.4" } },
      })
    );
    const deps = parseNpmManifest(dir);
    const moment = deps.find((d) => d.name === "moment");
    expect(moment!.version).toBe("2.29.4");
  });

  it("strips semver range operators from package.json versions", () => {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ dependencies: { axios: "~1.6.0" } })
    );
    const deps = parseNpmManifest(dir);
    expect(deps[0]!.version).toBe("1.6.0");
  });
});

// ── pip parser ────────────────────────────────────────────────────────────────

describe("parsePipRequirements", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  it("returns empty array when no requirements file", () => {
    expect(parsePipRequirements(dir)).toEqual([]);
  });

  it("parses pinned packages from requirements.txt", () => {
    writeFileSync(join(dir, "requirements.txt"), "requests==2.31.0\nflask==3.0.0\n");
    const deps = parsePipRequirements(dir);
    expect(deps.find((d) => d.name === "requests")?.version).toBe("2.31.0");
    expect(deps.find((d) => d.name === "flask")?.version).toBe("3.0.0");
  });

  it("ignores comments and flags in requirements.txt", () => {
    writeFileSync(join(dir, "requirements.txt"), "# comment\n--index-url https://pypi.org\nrequests==2.31.0\n");
    const deps = parsePipRequirements(dir);
    expect(deps).toHaveLength(1);
    expect(deps[0]!.name).toBe("requests");
  });

  it("handles version ranges (>=) and extracts partial version", () => {
    writeFileSync(join(dir, "requirements.txt"), "django>=4.2,<5\n");
    const deps = parsePipRequirements(dir);
    expect(deps[0]!.name).toBe("django");
    expect(deps[0]!.version).toBeTruthy();
  });

  it("parses pyproject.toml [project.dependencies]", () => {
    // Parser uses regex capture until next "[", so list syntax with "[" inside breaks it.
    // Use bare quoted strings which the line regex can match.
    writeFileSync(
      join(dir, "pyproject.toml"),
      `[project.dependencies]\n"httpx==0.27.0"\n"requests>=2.28.0"\n`
    );
    const deps = parsePipRequirements(dir);
    expect(deps.find((d) => d.name === "httpx")?.version).toBe("0.27.0");
  });
});

// ── OSV helpers ───────────────────────────────────────────────────────────────

describe("getSeverity", () => {
  it("returns critical for CVSS >= 9.0", () => {
    const vuln: OsvVuln = { id: "OSV-1", severity: [{ type: "CVSS_V3", score: "9.8" }] };
    expect(getSeverity(vuln)).toBe("critical");
  });

  it("returns high for CVSS 7.0–8.9", () => {
    const vuln: OsvVuln = { id: "OSV-2", severity: [{ type: "CVSS_V3", score: "7.5" }] };
    expect(getSeverity(vuln)).toBe("high");
  });

  it("returns medium for CVSS 4.0–6.9", () => {
    const vuln: OsvVuln = { id: "OSV-3", severity: [{ type: "CVSS_V3", score: "5.3" }] };
    expect(getSeverity(vuln)).toBe("medium");
  });

  it("returns low for CVSS < 4.0", () => {
    const vuln: OsvVuln = { id: "OSV-4", severity: [{ type: "CVSS_V3", score: "2.0" }] };
    expect(getSeverity(vuln)).toBe("low");
  });

  it("falls back to text heuristics when no CVSS", () => {
    const vuln: OsvVuln = { id: "OSV-5", summary: "Remote code execution via crafted input" };
    expect(getSeverity(vuln)).toBe("critical");
  });

  it("returns unknown when no score and no matching text", () => {
    const vuln: OsvVuln = { id: "OSV-6", summary: "Cosmetic issue in UI rendering" };
    expect(getSeverity(vuln)).toBe("unknown");
  });
});

describe("getFixedVersion", () => {
  it("returns the fixed version for the given package", () => {
    const vuln: OsvVuln = {
      id: "OSV-7",
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
        },
      ],
    };
    expect(getFixedVersion(vuln, "lodash")).toBe("4.17.21");
  });

  it("returns null when package not in affected list", () => {
    const vuln: OsvVuln = {
      id: "OSV-8",
      affected: [
        {
          package: { name: "other-pkg", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ fixed: "1.0.0" }] }],
        },
      ],
    };
    expect(getFixedVersion(vuln, "lodash")).toBeNull();
  });

  it("returns null when no ranges", () => {
    const vuln: OsvVuln = {
      id: "OSV-9",
      affected: [{ package: { name: "lodash", ecosystem: "npm" } }],
    };
    expect(getFixedVersion(vuln, "lodash")).toBeNull();
  });
});
