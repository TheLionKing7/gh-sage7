# gh-sage7 — Sage 7 reachability scanner as a GitHub CLI extension

Wraps the zero-dependency Sage 7 scanner so any repository can run a reachability-aware
security scan straight from the terminal or from CI:

```bash
gh extension install TheLionKing7/gh-sage7
gh sage7 scan
```

The wrapper delegates to `scripts/sage7-scan.ts` when the scanner is vendored next to the
extension, and otherwise falls back to `npx --yes @sage7/scan`. It requires Node.js 22.6 or
newer (native TypeScript type stripping).

## Usage

```bash
gh sage7 scan                          # terminal summary table
gh sage7 scan --json                   # machine-readable JSON on stdout
gh sage7 scan --offline                # local rules only, no OSV network calls
gh sage7 scan --sarif results.sarif    # SARIF 2.1.0 for GitHub Code Scanning
gh sage7 scan --token "$SAGE7_PROJECT_TOKEN" --api-url https://sage7.dev
```

`scan` is optional: `gh sage7 --sarif results.sarif` behaves the same.

### Options

| Flag | Description |
| --- | --- |
| `--sarif <path>` | Write a SARIF 2.1.0 report (GitHub Code Scanning compatible). |
| `--token <token>` | Upload findings to Sage 7 Cloud (`SAGE7_PROJECT_TOKEN`). |
| `--api-url <url>` | Sage 7 Cloud base URL (default `https://sage7.dev`). |
| `--target <repo>` | Repository identifier (`owner/repo`). |
| `--commit <sha>` | Commit SHA recorded with the findings. |
| `--branch <name>` | Branch name recorded with the findings. |
| `--cwd <path>` / `-C` | Directory to scan (default: the current directory). |
| `--offline` | Skip remote OSV queries and run local reachability rules only. |
| `--json` | Print JSON output instead of the terminal table. |
| `--help` / `-h` | Show usage. |

Environment fallbacks: `SAGE7_PROJECT_TOKEN`, `SAGE7_API_URL`, `GITHUB_REPOSITORY`,
`GITHUB_SHA`, `GITHUB_REF_NAME`.

## Reachability tiers

Every finding is classified by tracing the lockfile advisory back into the project's
import graph, so the report separates real risk from noise:

| Tier | Meaning | Blast radius |
| --- | --- | --- |
| `T0` | Imported by an HTTP route or public entry point (directly exposed). | `critical` / `high` |
| `T1` | Reachable through application source imports (`src/**`). | `critical` → `medium` |
| `T2` | Declared but never imported (unused dependency). | `low` |
| `T3` | Dev/test only, or dormant transitive dependency. | `low` |

The terminal summary leads with `Actionable (T0/T1)` and pushes `Noise/Dormant (T2/T3)` to
the end, and `--json` output carries `tier`, `tierLabel`, `blastRadius`, `entryPoint` and
`callPath` for each finding.

## GitHub Action

```yaml
name: Sage 7 Reachability & Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  sage7-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Run Sage 7 Scanner
        env:
          SAGE7_PROJECT_TOKEN: ${{ secrets.SAGE7_PROJECT_TOKEN }}
          SAGE7_API_URL: ${{ vars.SAGE7_API_URL || 'https://sage7.dev' }}
        run: |
          gh extension install TheLionKing7/gh-sage7
          gh sage7 scan \
            --sarif results.sarif \
            --target "${{ github.repository }}" \
            --commit "${{ github.sha }}" \
            --branch "${{ github.ref_name }}"

      - name: Upload SARIF to GitHub Code Scanning
        if: always() && hashFiles('results.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: sage7-reachability
```

Add `--token "$SAGE7_PROJECT_TOKEN" --api-url "$SAGE7_API_URL"` to the scan command to push
results into a project's Security Workbench instead of (or in addition to) Code Scanning.

## Exit codes

`0` — scan completed (findings do not fail the build; triage happens in Code Scanning or the
Security Workbench). `1` — the scanner failed to run (missing lockfile, network error on an
upload, invalid arguments).
