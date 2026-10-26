#!/usr/bin/env node
/**
 * Sage 7 Standalone Reachability & Security Scanner (`npx @sage7/scan` / `gh sage7 scan`)
 *
 * Zero-external-dependency scanner CLI that:
 * 1. Reads local package lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `bun.lockb`, `bun.lock`, `yarn.lock`).
 * 2. Queries OSV.dev (and applies local static security rules across project files).
 * 3. Traces imports & call trees across project routes/handlers to classify each finding's reachability:
 *    - `T0`: Direct Public Handler (`src/routes/**`, `src/api/**`, `src/server/**`)
 *    - `T1`: Internal Helper (`src/**` reachable application modules)
 *    - `T2`: Unused Dependency (in production lockfile, no resolved source import)
 *    - `T3`: Dev Only (`devDependencies`, `tests/**`, build configs)
 * 4. Outputs:
 *    - Terminal summary table (default)
 *    - GitHub SARIF v2.1.0 report (`--sarif results.sarif`)
 *    - Direct upload to Sage 7 Cloud (`--token $SAGE7_PROJECT_TOKEN --api-url https://sage7.dev`)
 *
 * GitHub CLI Extension (`gh-sage7`) wrapper snippet:
 * ```sh
 * #!/usr/bin/env sh
 * set -e
 * exec npx --yes tsx "$(dirname "$0")/scripts/sage7-scan.ts" "$@"
 * ```
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";

export type ReachabilityTier = "T0" | "T1" | "T2" | "T3";
export type BlastRadius = "critical" | "high" | "medium" | "low";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export const REACHABILITY_TIER_LABELS: Record<ReachabilityTier, string> = {
  T0: "T0: Direct Public Handler",
  T1: "T1: Internal Helper",
  T2: "T2: Unused Dependency",
  T3: "T3: Dev Only",
};

export interface LockedDependency {
  name: string;
  version: string;
  dev: boolean;
  lockfile: string;
}

export interface ScanFinding {
  id: string;
  fingerprint: string;
  severity: FindingSeverity;
  title: string;
  detail: string;
  tier: ReachabilityTier;
  tierLabel: string;
  blastRadius: BlastRadius;
  packageName?: string | undefined;
  packageVersion?: string | undefined;
  fixedVersion?: string | null | undefined;
  entryPoint?: string | undefined;
  callPath?: string[] | undefined;
  line?: number | undefined;
  featureId?: string | undefined;
  url?: string | undefined;
  source: "osv" | "local-rule";
}

export interface CliOptions {
  cwd: string;
  sarifPath?: string | undefined;
  token?: string | undefined;
  apiUrl: string;
  target?: string | undefined;
  commit?: string | undefined;
  branch?: string | undefined;
  offline: boolean;
  json: boolean;
  help: boolean;
}

const EXACT_SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const IMPORT_SPECIFIER_RE =
  /(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)["']([^"'\r\n]+)["']/g;
const PUBLIC_HANDLER_FILE_RE =
  /(?:^|\/)(?:src\/(?:routes|server|api)\/|routes\/|api\/|pages\/api\/|app\/api\/|src\/(?:server|router|main|index)\.[cm]?[jt]sx?$)/i;
const DEV_ONLY_FILE_RE =
  /(?:^|\/)(?:tests?\/|__tests__\/|__mocks__\/|e2e\/|cypress\/|playwright\/|scripts\/|.*\.(?:test|spec|stories|config)\.[cm]?[jt]sx?$|(?:vite|vitest|jest|playwright|eslint|tailwind|postcss|tsup|rollup|webpack|babel)\.config\.[cm]?[jt]s$)/i;
const APP_HELPER_FILE_RE = /(?:^|\/)src\/.*\.[cm]?[jt]sx?$/i;

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".output",
  ".vinxi",
  ".tanstack",
  ".next",
  "coverage",
]);

export function parseCliArgs(argv: string[], cwd = process.cwd()): CliOptions {
  const args = [...argv];
  if (args[0] === "scan") args.shift();

  let sarifPath: string | undefined;
  let token = process.env["SAGE7_PROJECT_TOKEN"] || undefined;
  let apiUrl = process.env["SAGE7_API_URL"] || "https://sage7.dev";
  let target: string | undefined = process.env["GITHUB_REPOSITORY"] || undefined;
  let commit: string | undefined = process.env["GITHUB_SHA"] || undefined;
  let branch: string | undefined = process.env["GITHUB_REF_NAME"] || undefined;
  let dir = cwd;
  let offline = false;
  let json = false;
  let help = false;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === "--help" || arg === "-h") {
      help = true;
    } else if (arg === "--sarif" && args[i + 1]) {
      sarifPath = args[++i];
    } else if (arg.startsWith("--sarif=")) {
      sarifPath = arg.slice("--sarif=".length);
    } else if (arg === "--token" && args[i + 1]) {
      token = args[++i];
    } else if (arg.startsWith("--token=")) {
      token = arg.slice("--token=".length);
    } else if (arg === "--api-url" && args[i + 1]) {
      apiUrl = args[++i]!;
    } else if (arg.startsWith("--api-url=")) {
      apiUrl = arg.slice("--api-url=".length);
    } else if (arg === "--target" && args[i + 1]) {
      target = args[++i];
    } else if (arg.startsWith("--target=")) {
      target = arg.slice("--target=".length);
    } else if (arg === "--commit" && args[i + 1]) {
      commit = args[++i];
    } else if (arg.startsWith("--commit=")) {
      commit = arg.slice("--commit=".length);
    } else if (arg === "--branch" && args[i + 1]) {
      branch = args[++i];
    } else if (arg.startsWith("--branch=")) {
      branch = arg.slice("--branch=".length);
    } else if ((arg === "--cwd" || arg === "-C") && args[i + 1]) {
      dir = path.resolve(cwd, args[++i]!);
    } else if (arg === "--offline") {
      offline = true;
    } else if (arg === "--json") {
      json = true;
    }
  }

  return {
    cwd: dir,
    sarifPath,
    token,
    apiUrl: apiUrl.replace(/\/+$/, ""),
    target,
    commit,
    branch,
    offline,
    json,
    help,
  };
}

function packageNameFromNodeModulesPath(pkgPath: string): string | null {
  const segments = pkgPath.split("/").filter(Boolean);
  let lastNm = -1;
  for (let i = 0; i < segments.length; i += 1) {
    if (segments[i] === "node_modules") lastNm = i;
  }
  if (lastNm < 0 || !segments[lastNm + 1]) return null;
  const first = segments[lastNm + 1]!;
  if (first.startsWith("@")) {
    return segments[lastNm + 2] ? `${first}/${segments[lastNm + 2]}` : null;
  }
  return first;
}

export function parsePackageLockJson(content: string): LockedDependency[] {
  const results = new Map<string, LockedDependency>();
  try {
    const parsed = JSON.parse(content) as {
      packages?: Record<string, { name?: string; version?: string; dev?: boolean }>;
      dependencies?: Record<string, { version?: string; dev?: boolean }>;
    };
    if (parsed.packages && typeof parsed.packages === "object") {
      for (const [pkgPath, meta] of Object.entries(parsed.packages)) {
        if (!pkgPath || !meta) continue;
        const name = meta.name ?? packageNameFromNodeModulesPath(pkgPath);
        const version = meta.version;
        if (!name || !version || !EXACT_SEMVER_RE.test(version)) continue;
        results.set(`${name}@${version}`, {
          name,
          version,
          dev: Boolean(meta.dev),
          lockfile: "package-lock.json",
        });
      }
    }
    if (parsed.dependencies && typeof parsed.dependencies === "object") {
      for (const [name, meta] of Object.entries(parsed.dependencies)) {
        const version = meta?.version;
        if (!name || !version || !EXACT_SEMVER_RE.test(version)) continue;
        const key = `${name}@${version}`;
        if (!results.has(key)) {
          results.set(key, {
            name,
            version,
            dev: Boolean(meta.dev),
            lockfile: "package-lock.json",
          });
        }
      }
    }
  } catch {
    // Ignore malformed JSON
  }
  return [...results.values()];
}

export function parsePnpmLockYaml(content: string): LockedDependency[] {
  const results = new Map<string, LockedDependency>();
  const lines = content.split(/\r?\n/);
  let inPackages = false;
  let currentKey: string | null = null;
  let currentDev = false;

  const commitEntry = (spec: string | null, dev: boolean) => {
    if (!spec) return;
    const cleaned = spec.replace(/^['"]|['"]:?$/g, "").replace(/^\/+/, "");
    const core = cleaned.split("(")[0]!;
    const atIndex = core.startsWith("@") ? core.indexOf("@", 1) : core.indexOf("@");
    let name = "";
    let version = "";
    if (atIndex > 0) {
      name = core.slice(0, atIndex);
      version = core.slice(atIndex + 1);
    } else {
      const slashIdx = core.lastIndexOf("/");
      if (slashIdx > 0) {
        name = core.slice(0, slashIdx);
        version = core.slice(slashIdx + 1);
      }
    }
    if (name && EXACT_SEMVER_RE.test(version)) {
      results.set(`${name}@${version}`, {
        name,
        version,
        dev,
        lockfile: "pnpm-lock.yaml",
      });
    }
  };

  for (const line of lines) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line)) {
      commitEntry(currentKey, currentDev);
      currentKey = null;
      inPackages = false;
      continue;
    }
    if (!inPackages) continue;

    const entryMatch = /^ {2}(['"]?[@A-Za-z0-9._/-]+@[0-9][^:]*['"]?):\s*$/.exec(line);
    if (entryMatch?.[1]) {
      commitEntry(currentKey, currentDev);
      currentKey = entryMatch[1].replace(/^['"]|['"]$/g, "");
      currentDev = false;
      continue;
    }
    if (currentKey && /^\s+dev:\s*true\b/.test(line)) {
      currentDev = true;
    }
  }
  commitEntry(currentKey, currentDev);
  return [...results.values()];
}

export function parseBunLock(content: string | Buffer, lockfileName = "bun.lockb"): LockedDependency[] {
  const results = new Map<string, LockedDependency>();
  const text = typeof content === "string" ? content : content.toString("latin1");

  // 1. JSONC-style bun.lock or embedded strings in binary bun.lockb
  const pairRegex = /["']((?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)["']/g;
  for (const match of text.matchAll(pairRegex)) {
    const name = match[1];
    const version = match[2];
    if (name && version && EXACT_SEMVER_RE.test(version)) {
      results.set(`${name}@${version}`, {
        name,
        version,
        dev: false,
        lockfile: lockfileName,
      });
    }
  }
  return [...results.values()];
}

export function readProjectLockfiles(cwd: string): {
  dependencies: LockedDependency[];
  manifestDeps: Set<string>;
  manifestDevDeps: Set<string>;
} {
  const manifestDeps = new Set<string>();
  const manifestDevDeps = new Set<string>();
  const pkgJsonPath = path.join(cwd, "package.json");
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8")) as {
        dependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      for (const group of [pkg.dependencies, pkg.optionalDependencies, pkg.peerDependencies]) {
        if (group && typeof group === "object") {
          for (const name of Object.keys(group)) manifestDeps.add(name);
        }
      }
      if (pkg.devDependencies && typeof pkg.devDependencies === "object") {
        for (const name of Object.keys(pkg.devDependencies)) {
          if (!manifestDeps.has(name)) manifestDevDeps.add(name);
        }
      }
    } catch {
      // ignore
    }
  }

  const allDeps = new Map<string, LockedDependency>();
  const addAll = (items: LockedDependency[]) => {
    for (const item of items) {
      const isDev = item.dev || (manifestDevDeps.has(item.name) && !manifestDeps.has(item.name));
      allDeps.set(`${item.name}@${item.version}`, { ...item, dev: isDev });
    }
  };

  const npmLock = path.join(cwd, "package-lock.json");
  if (fs.existsSync(npmLock)) {
    addAll(parsePackageLockJson(fs.readFileSync(npmLock, "utf8")));
  }

  const pnpmLock = path.join(cwd, "pnpm-lock.yaml");
  if (fs.existsSync(pnpmLock)) {
    addAll(parsePnpmLockYaml(fs.readFileSync(pnpmLock, "utf8")));
  }

  const bunLockb = path.join(cwd, "bun.lockb");
  if (fs.existsSync(bunLockb)) {
    addAll(parseBunLock(fs.readFileSync(bunLockb), "bun.lockb"));
  }

  const bunLock = path.join(cwd, "bun.lock");
  if (fs.existsSync(bunLock)) {
    addAll(parseBunLock(fs.readFileSync(bunLock, "utf8"), "bun.lock"));
  }

  // Fallback to package.json exact/pinned versions if no lockfile entries were found
  if (allDeps.size === 0 && fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8")) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      for (const [name, rawVer] of Object.entries(pkg.dependencies ?? {})) {
        const cleanVer = String(rawVer).replace(/^[\^~>=<\s]+/, "");
        if (EXACT_SEMVER_RE.test(cleanVer)) {
          allDeps.set(`${name}@${cleanVer}`, {
            name,
            version: cleanVer,
            dev: false,
            lockfile: "package.json",
          });
        }
      }
      for (const [name, rawVer] of Object.entries(pkg.devDependencies ?? {})) {
        const cleanVer = String(rawVer).replace(/^[\^~>=<\s]+/, "");
        if (EXACT_SEMVER_RE.test(cleanVer) && !manifestDeps.has(name)) {
          allDeps.set(`${name}@${cleanVer}`, {
            name,
            version: cleanVer,
            dev: true,
            lockfile: "package.json",
          });
        }
      }
    } catch {
      // ignore
    }
  }

  return {
    dependencies: [...allDeps.values()],
    manifestDeps,
    manifestDevDeps,
  };
}

export function collectProjectSourceFiles(cwd: string): Record<string, string> {
  const files: Record<string, string> = {};
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".") && entry.name !== ".github") continue;
      if (IGNORED_DIRS.has(entry.name)) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && /\.[cm]?[jt]sx?$/i.test(entry.name)) {
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size <= 512 * 1024) {
            const rel = path.relative(cwd, fullPath).replace(/\\/g, "/");
            files[rel] = fs.readFileSync(fullPath, "utf8");
          }
        } catch {
          // ignore unreadable files
        }
      }
    }
  };
  walk(cwd);
  return files;
}

function extractSpecifierDetails(specifier: string): {
  pkg: string | null;
  relativeSpec: string | null;
} {
  const trimmed = specifier.trim();
  if (!trimmed) return { pkg: null, relativeSpec: null };
  if (trimmed.startsWith(".") || trimmed.startsWith("@/") || trimmed.startsWith("~/")) {
    return { pkg: null, relativeSpec: trimmed };
  }
  if (
    trimmed.startsWith("/") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("node:") ||
    trimmed.startsWith("bun:") ||
    trimmed.startsWith("http:") ||
    trimmed.startsWith("https:") ||
    trimmed.startsWith("virtual:")
  ) {
    return { pkg: null, relativeSpec: null };
  }
  const clean = trimmed.split("?")[0]!.split("#")[0]!;
  if (clean.startsWith("@")) {
    const parts = clean.split("/");
    return {
      pkg: parts.length >= 2 && parts[0] && parts[1] ? `${parts[0]}/${parts[1]}` : null,
      relativeSpec: null,
    };
  }
  const first = clean.split("/")[0];
  return { pkg: first || null, relativeSpec: null };
}

function resolveLocalImport(
  fromFile: string,
  specifier: string,
  knownFiles: Set<string>,
): string | null {
  let candidateBase: string;
  if (specifier.startsWith("@/") || specifier.startsWith("~/")) {
    candidateBase = `src/${specifier.slice(2)}`;
  } else {
    const dir = path.posix.dirname(fromFile);
    candidateBase = path.posix.normalize(path.posix.join(dir, specifier));
  }
  const cleanBase = candidateBase.replace(/\.[cm]?[jt]sx?$/i, "");
  const extensions = [
    "",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    "/index.ts",
    "/index.tsx",
    "/index.js",
  ];
  for (const ext of extensions) {
    const attempt = ext ? `${cleanBase}${ext}` : candidateBase;
    if (knownFiles.has(attempt)) return attempt;
  }
  return null;
}

export interface PackageCallTrace {
  tier: ReachabilityTier;
  tierLabel: string;
  blastRadius: BlastRadius;
  entryPoint?: string | undefined;
  callPath?: string[] | undefined;
}

export function buildImportCallGraph(sourceFiles: Record<string, string>) {
  const knownFiles = new Set(Object.keys(sourceFiles));
  const filePackages = new Map<string, Set<string>>();
  const localEdges = new Map<string, Set<string>>();

  for (const [filePath, content] of Object.entries(sourceFiles)) {
    const stripped = content
      .replace(/\/\*[\s\S]*?\*\//g, " ")
      .replace(/^\s*\/\/.*$/gm, " ");
    const pkgs = new Set<string>();
    const locals = new Set<string>();

    for (const match of stripped.matchAll(IMPORT_SPECIFIER_RE)) {
      const spec = match[1];
      if (!spec) continue;
      const { pkg, relativeSpec } = extractSpecifierDetails(spec);
      if (pkg) {
        pkgs.add(pkg);
      } else if (relativeSpec) {
        const resolved = resolveLocalImport(filePath, relativeSpec, knownFiles);
        if (resolved) locals.add(resolved);
      }
    }
    filePackages.set(filePath, pkgs);
    localEdges.set(filePath, locals);
  }

  return { filePackages, localEdges, knownFiles };
}

export function tracePackageReachability(params: {
  packageName: string;
  isDevDependency: boolean;
  severity: FindingSeverity;
  sourceFiles: Record<string, string>;
  graph?: ReturnType<typeof buildImportCallGraph> | undefined;
}): PackageCallTrace {
  const { packageName, isDevDependency, severity, sourceFiles } = params;
  const graph = params.graph ?? buildImportCallGraph(sourceFiles);
  const sortedFiles = [...graph.knownFiles].sort((a, b) => a.localeCompare(b));

  const publicRoutes = sortedFiles.filter(
    (f) => !DEV_ONLY_FILE_RE.test(f) && PUBLIC_HANDLER_FILE_RE.test(f),
  );
  const internalHelpers = sortedFiles.filter(
    (f) => !DEV_ONLY_FILE_RE.test(f) && !PUBLIC_HANDLER_FILE_RE.test(f) && APP_HELPER_FILE_RE.test(f),
  );
  const devFiles = sortedFiles.filter((f) => DEV_ONLY_FILE_RE.test(f));

  // 1. Direct or transitive call trace from Public Route Handlers -> T0: Direct Public Handler
  for (const routeFile of publicRoutes) {
    const queue: { file: string; chain: string[] }[] = [{ file: routeFile, chain: [routeFile] }];
    const visited = new Set<string>([routeFile]);
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (graph.filePackages.get(current.file)?.has(packageName)) {
        const callPath = [...current.chain, packageName];
        return {
          tier: "T0",
          tierLabel: REACHABILITY_TIER_LABELS.T0,
          blastRadius: severity === "critical" || severity === "high" ? "critical" : "high",
          entryPoint: routeFile,
          callPath,
        };
      }
      if (current.chain.length >= 5) continue;
      for (const nextFile of graph.localEdges.get(current.file) ?? []) {
        if (!visited.has(nextFile) && !DEV_ONLY_FILE_RE.test(nextFile)) {
          visited.add(nextFile);
          queue.push({ file: nextFile, chain: [...current.chain, nextFile] });
        }
      }
    }
  }

  // 2. Imported in Internal Application Helper -> T1: Internal Helper
  for (const helperFile of internalHelpers) {
    if (graph.filePackages.get(helperFile)?.has(packageName)) {
      return {
        tier: "T1",
        tierLabel: REACHABILITY_TIER_LABELS.T1,
        blastRadius:
          severity === "critical" ? "critical" : severity === "high" ? "high" : "medium",
        entryPoint: helperFile,
        callPath: [helperFile, packageName],
      };
    }
  }

  // 3. Dev-only dependency or imported only in tests/scripts/build configs -> T3: Dev Only
  for (const devFile of devFiles) {
    if (graph.filePackages.get(devFile)?.has(packageName)) {
      return {
        tier: "T3",
        tierLabel: REACHABILITY_TIER_LABELS.T3,
        blastRadius: "low",
        entryPoint: devFile,
        callPath: [devFile, packageName],
      };
    }
  }

  if (isDevDependency) {
    return {
      tier: "T3",
      tierLabel: REACHABILITY_TIER_LABELS.T3,
      blastRadius: "low",
    };
  }

  // 4. Present in production lockfile with no resolved source import -> T2: Unused Dependency
  return {
    tier: "T2",
    tierLabel: REACHABILITY_TIER_LABELS.T2,
    blastRadius: "low",
  };
}

interface LocalSecurityRule {
  id: string;
  title: string;
  detail: string;
  severity: FindingSeverity;
  pattern: RegExp;
}

const LOCAL_SECURITY_RULES: LocalSecurityRule[] = [
  {
    id: "SAGE7-RULE-001",
    title: "Dynamic code execution via eval() or new Function()",
    detail: "Untrusted input reaching dynamic code evaluation can lead to remote code execution.",
    severity: "high",
    pattern: /\b(?:eval\s*\(|new\s+Function\s*\()/,
  },
  {
    id: "SAGE7-RULE-002",
    title: "Shell command interpolation via child_process exec",
    detail: "Template literal interpolation inside exec/execSync risks OS command injection.",
    severity: "critical",
    pattern: /\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{/,
  },
  {
    id: "SAGE7-RULE-003",
    title: "Unfenced dangerouslySetInnerHTML usage",
    detail: "Rendering raw HTML without DOMPurify sanitization risks Cross-Site Scripting (XSS).",
    severity: "medium",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
  },
];

export function runLocalSecurityRules(sourceFiles: Record<string, string>): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const sortedPaths = Object.keys(sourceFiles).sort((a, b) => a.localeCompare(b));

  for (const filePath of sortedPaths) {
    if (DEV_ONLY_FILE_RE.test(filePath)) continue;
    const content = sourceFiles[filePath]!;
    const lines = content.split(/\r?\n/);

    for (const rule of LOCAL_SECURITY_RULES) {
      for (let idx = 0; idx < lines.length; idx += 1) {
        const lineText = lines[idx]!;
        if (/^\s*\/\//.test(lineText)) continue;
        if (rule.pattern.test(lineText)) {
          const isPublicHandler = PUBLIC_HANDLER_FILE_RE.test(filePath);
          const tier: ReachabilityTier = isPublicHandler ? "T0" : "T1";
          const blastRadius: BlastRadius =
            tier === "T0"
              ? rule.severity === "critical" || rule.severity === "high"
                ? "critical"
                : "high"
              : rule.severity === "critical"
                ? "critical"
                : rule.severity === "high"
                  ? "high"
                  : "medium";
          const fp = `${rule.severity}:${tier}:${rule.id.toLowerCase()}:${filePath}:${idx + 1}`;
          findings.push({
            id: rule.id,
            fingerprint: fp,
            severity: rule.severity,
            title: `${rule.title} (${filePath}:${idx + 1})`,
            detail: rule.detail,
            tier,
            tierLabel: REACHABILITY_TIER_LABELS[tier],
            blastRadius,
            entryPoint: filePath,
            callPath: [filePath],
            line: idx + 1,
            source: "local-rule",
          });
          break;
        }
      }
    }
  }
  return findings;
}

interface OsvVuln {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: { ranges?: { events?: { fixed?: string }[] }[] }[];
}

function normalizeOsvSeverity(vuln: OsvVuln): FindingSeverity {
  const raw = vuln.database_specific?.severity?.toLowerCase();
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") return raw;
  return "medium";
}

export async function queryOsvAdvisories(
  deps: LockedDependency[],
  fetchImpl: typeof fetch = fetch,
): Promise<{ dep: LockedDependency; vuln: OsvVuln }[]> {
  if (deps.length === 0) return [];
  const capped = deps.slice(0, 1000);
  const batchSize = 100;
  const matches: { dep: LockedDependency; vuln: OsvVuln }[] = [];

  for (let i = 0; i < capped.length; i += batchSize) {
    const slice = capped.slice(i, i + batchSize);
    try {
      const response = await fetchImpl("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: slice.map((d) => ({
            package: { name: d.name, ecosystem: "npm" },
            version: d.version,
          })),
        }),
      });
      if (!response.ok) continue;
      const data = (await response.json()) as { results?: { vulns?: OsvVuln[] }[] };
      const results = data.results ?? [];
      for (let j = 0; j < slice.length; j += 1) {
        const dep = slice[j]!;
        for (const vuln of results[j]?.vulns ?? []) {
          if (vuln.id) matches.push({ dep, vuln });
        }
      }
    } catch {
      // Offline or OSV unreachable; degrade gracefully
    }
  }
  return matches;
}

export async function runStandaloneSecurityScan(
  options: CliOptions,
  fetchImpl: typeof fetch = fetch,
): Promise<{
  target: string;
  commit: string | null;
  branch: string | null;
  totalFiles: number;
  filesScanned: string[];
  findings: ScanFinding[];
}> {
  const { dependencies } = readProjectLockfiles(options.cwd);
  const sourceFiles = collectProjectSourceFiles(options.cwd);
  const graph = buildImportCallGraph(sourceFiles);
  const findings: ScanFinding[] = [];

  if (!options.offline && dependencies.length > 0) {
    const osvHits = await queryOsvAdvisories(dependencies, fetchImpl);
    for (const { dep, vuln } of osvHits) {
      const id = vuln.aliases?.find((a) => a.startsWith("CVE-")) ?? vuln.id ?? "OSV-UNKNOWN";
      const severity = normalizeOsvSeverity(vuln);
      const trace = tracePackageReachability({
        packageName: dep.name,
        isDevDependency: dep.dev,
        severity,
        sourceFiles,
        graph,
      });
      const fixedVersion =
        vuln.affected
          ?.flatMap((a) => a.ranges ?? [])
          .flatMap((r) => r.events ?? [])
          .map((e) => e.fixed)
          .find((v): v is string => typeof v === "string" && v.length > 0) ?? null;
      const summary =
        vuln.summary?.trim() ||
        vuln.details?.split(/\r?\n/)[0]?.slice(0, 200) ||
        `Known vulnerability in ${dep.name}@${dep.version}`;
      const title = `${dep.name}@${dep.version} — ${id}`;
      const detail = `${summary}${fixedVersion ? ` (Fix available: ${fixedVersion})` : ""}`;
      const fp = `${severity}:${trace.tier}:${title.toLowerCase()}:${detail.toLowerCase()}`.slice(
        0,
        500,
      );

      findings.push({
        id,
        fingerprint: fp,
        severity,
        title,
        detail,
        tier: trace.tier,
        tierLabel: trace.tierLabel,
        blastRadius: trace.blastRadius,
        packageName: dep.name,
        packageVersion: dep.version,
        fixedVersion,
        entryPoint: trace.entryPoint,
        callPath: trace.callPath,
        url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id ?? id)}`,
        source: "osv",
      });
    }
  }

  findings.push(...runLocalSecurityRules(sourceFiles));

  const tierRank: Record<ReachabilityTier, number> = { T0: 0, T1: 1, T2: 2, T3: 3 };
  const sevRank: Record<FindingSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  findings.sort(
    (a, b) => tierRank[a.tier] - tierRank[b.tier] || sevRank[a.severity] - sevRank[b.severity],
  );

  const detectedTarget = options.target || detectGitTarget(options.cwd);
  const detectedCommit = options.commit || detectGitValue(options.cwd, "git rev-parse HEAD");
  const detectedBranch =
    options.branch || detectGitValue(options.cwd, "git rev-parse --abbrev-ref HEAD");
  const fileList = Object.keys(sourceFiles).sort((a, b) => a.localeCompare(b));

  return {
    target: detectedTarget,
    commit: detectedCommit,
    branch: detectedBranch,
    totalFiles: fileList.length,
    filesScanned: fileList,
    findings,
  };
}

function detectGitValue(cwd: string, cmd: string): string | null {
  try {
    return execSync(cmd, { cwd, stdio: ["ignore", "pipe", "ignore"] })
      .toString("utf8")
      .trim();
  } catch {
    return null;
  }
}

function detectGitTarget(cwd: string): string {
  const remote = detectGitValue(cwd, "git config --get remote.origin.url");
  if (remote) {
    const match = /github\.com[:/]([^/]+\/[^/.]+?)(?:\.git)?$/i.exec(remote);
    if (match?.[1]) return match[1];
  }
  return path.basename(cwd);
}

export function buildSarifReport(findings: ScanFinding[]) {
  const rulesMap = new Map<string, ScanFinding>();
  for (const f of findings) {
    if (!rulesMap.has(f.id)) rulesMap.set(f.id, f);
  }

  const toSarifLevel = (sev: FindingSeverity): "error" | "warning" | "note" => {
    if (sev === "critical" || sev === "high") return "error";
    if (sev === "medium") return "warning";
    return "note";
  };

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Sage 7 Reachability Scanner",
            informationUri: "https://sage7.dev",
            version: "1.0.0",
            rules: [...rulesMap.values()].map((f) => ({
              id: f.id,
              name: f.title,
              shortDescription: { text: f.title },
              fullDescription: { text: f.detail },
              helpUri: f.url ?? "https://sage7.dev",
              properties: {
                tags: ["security", f.tier, f.blastRadius],
              },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.id,
          level: toSarifLevel(f.severity),
          message: {
            text: `[${f.tierLabel}] ${f.title}: ${f.detail}${
              f.callPath?.length ? ` (Call path: ${f.callPath.join(" -> ")})` : ""
            }`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.entryPoint ?? "package-lock.json",
                },
                region: {
                  startLine: f.line ?? 1,
                },
              },
            },
          ],
          properties: {
            fingerprint: f.fingerprint,
            reachabilityTier: f.tier,
            reachabilityLabel: f.tierLabel,
            blastRadius: f.blastRadius,
            callPath: f.callPath ?? [],
          },
        })),
      },
    ],
  };
}

export function formatTerminalTable(findings: ScanFinding[], target: string): string {
  const lines: string[] = [];
  const t0Count = findings.filter((f) => f.tier === "T0").length;
  const t1Count = findings.filter((f) => f.tier === "T1").length;
  const dormantCount = findings.length - t0Count - t1Count;

  lines.push(`\nSage 7 Security & Reachability Scan — ${target}`);
  lines.push(
    `Total: ${findings.length} | Actionable (T0/T1): ${t0Count + t1Count} (T0: ${t0Count}, T1: ${t1Count}) | Noise/Dormant (T2/T3): ${dormantCount}\n`,
  );

  if (findings.length === 0) {
    lines.push("No security findings detected.");
    return lines.join("\n");
  }

  const headers = ["TIER", "SEVERITY", "BLAST", "FINDING", "ENTRY POINT / CALL PATH"];
  const rows = findings.map((f) => [
    f.tierLabel,
    f.severity.toUpperCase(),
    f.blastRadius.toUpperCase(),
    f.title.slice(0, 44),
    f.callPath?.length ? f.callPath.join(" -> ") : (f.entryPoint ?? "lockfile"),
  ]);

  const widths = headers.map((h, col) =>
    Math.max(h.length, ...rows.map((r) => (r[col] ?? "").length)),
  );
  const formatRow = (cols: string[]) =>
    cols.map((c, idx) => c.padEnd(widths[idx]!)).join("  ");

  lines.push(formatRow(headers));
  lines.push(widths.map((w) => "-".repeat(w)).join("  "));
  for (const row of rows) {
    lines.push(formatRow(row));
  }
  return lines.join("\n");
}

export async function uploadScanToSage7Cloud(params: {
  apiUrl: string;
  token: string;
  target: string;
  commit: string | null;
  branch: string | null;
  totalFiles: number;
  filesScanned: string[];
  findings: ScanFinding[];
  fetchImpl?: typeof fetch | undefined;
}): Promise<{ ok: boolean; scanId?: string; findingsCount?: number; reachableCount?: number }> {
  const fetchFn = params.fetchImpl ?? fetch;
  const endpoint = `${params.apiUrl.replace(/\/+$/, "")}/api/public/security/ingest`;
  const response = await fetchFn(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${params.token}`,
    },
    body: JSON.stringify({
      target: params.target,
      commit: params.commit,
      branch: params.branch,
      totalFiles: params.totalFiles,
      filesScanned: params.filesScanned,
      findings: params.findings.map((f) => ({
        fingerprint: f.fingerprint,
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        tier: f.tier,
        blastRadius: f.blastRadius,
        ...(f.featureId ? { featureId: f.featureId } : {}),
        evidence: {
          source: "cli",
          reachability: {
            tier: f.tier,
            label: f.tierLabel,
            ...(f.entryPoint ? { entry_point: f.entryPoint } : {}),
            ...(f.callPath ? { call_path: f.callPath } : {}),
          },
          blast_radius: f.blastRadius,
          ...(f.packageName ? { package: f.packageName, version: f.packageVersion } : {}),
          ...(f.fixedVersion ? { fixed_version: f.fixedVersion } : {}),
        },
      })),
    }),
  });

  if (!response.ok) {
    const errText = await response.text().catch(() => response.statusText);
    throw new Error(`Sage 7 Cloud upload failed (${response.status}): ${errText}`);
  }
  return (await response.json()) as {
    ok: boolean;
    scanId?: string;
    findingsCount?: number;
    reachableCount?: number;
  };
}

export async function runCli(argv = process.argv.slice(2)): Promise<number> {
  const options = parseCliArgs(argv);
  if (options.help) {
    console.log(
      [
        "Usage: sage7-scan [scan] [options]",
        "       gh sage7 scan [options]",
        "",
        "Options:",
        "  --sarif <path>       Write SARIF v2.1.0 report for GitHub Code Scanning",
        "  --token <token>      Upload findings to Sage 7 Cloud ($SAGE7_PROJECT_TOKEN)",
        "  --api-url <url>      Sage 7 Cloud base URL (default: https://sage7.dev)",
        "  --target <repo>      Repository target identifier (owner/repo)",
        "  --offline            Skip remote OSV queries and run local reachability rules only",
        "  --json               Print JSON output to stdout",
      ].join("\n"),
    );
    return 0;
  }

  const result = await runStandaloneSecurityScan(options);

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(formatTerminalTable(result.findings, result.target));
  }

  if (options.sarifPath) {
    const sarif = buildSarifReport(result.findings);
    const outPath = path.resolve(options.cwd, options.sarifPath);
    fs.writeFileSync(outPath, JSON.stringify(sarif, null, 2), "utf8");
    if (!options.json) {
      console.log(`\nSARIF report written to ${outPath}`);
    }
  }

  if (options.token) {
    const uploaded = await uploadScanToSage7Cloud({
      apiUrl: options.apiUrl,
      token: options.token,
      target: result.target,
      commit: result.commit,
      branch: result.branch,
      totalFiles: result.totalFiles,
      filesScanned: result.filesScanned,
      findings: result.findings,
    });
    if (!options.json) {
      console.log(
        `Uploaded scan ${uploaded.scanId ?? ""} to Sage 7 Cloud (${uploaded.findingsCount ?? 0} findings, ${uploaded.reachableCount ?? 0} reachable).`,
      );
    }
  }

  return 0;
}

const isDirectExecution =
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  path.basename(process.argv[1]).startsWith("sage7-scan");

if (isDirectExecution) {
  runCli().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    },
  );
}
