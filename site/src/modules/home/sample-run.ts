/**
 * One real `pkguard scan` run, captured from the binary against a folder holding
 * a bun app beside a uv service. Every name, code, count and message below is
 * verbatim, and the summary line is the one that run printed. Advisory rows are
 * a subset: `omitted` says how many were cut from each section.
 *
 * uv publishes no severity for an advisory, which is why the uv rows all read
 * `info` while the bun rows span critical to low.
 */

export type Severity = "critical" | "high" | "moderate" | "low" | "info";

export interface Finding {
  severity: Severity;
  code: string;
  /** Package the advisory belongs to. Settings findings have none. */
  pkg?: string;
  detail: string;
}

export interface Section {
  /** Heading the CLI prints, e.g. "bun · settings". */
  title: string;
  /** Total the CLI counted, which may exceed the rows kept below. */
  count: number;
  findings: Finding[];
  /** Rows dropped from `findings` to keep the block readable. */
  omitted?: number;
  /** Stand-in the CLI prints when a section has nothing to list. */
  empty?: string;
}

export interface SampleProject {
  name: string;
  headline: string;
  preset: string;
  sections: Section[];
}

export const SAMPLE_COMMAND = "pkguard scan ~/code";

export const SAMPLE_PROJECTS: SampleProject[] = [
  {
    name: "react-project",
    headline: "37 findings",
    preset: "standard",
    sections: [
      {
        title: "bun · settings",
        count: 3,
        findings: [
          {
            severity: "high",
            code: "min-age.disabled",
            detail: "install.minimumReleaseAge must be at least 86400 seconds",
          },
          {
            severity: "high",
            code: "scripts.unrestricted",
            detail: "bun scripts must be restricted",
          },
          {
            severity: "info",
            code: "registry.unpinned",
            detail: "install.registry must be set",
          },
        ],
      },
      {
        title: "bun · advisories",
        count: 34,
        omitted: 30,
        findings: [
          {
            severity: "critical",
            code: "GHSA-w7jw-789q-3m8p",
            pkg: "shell-quote",
            detail:
              "shell-quote quote() does not escape newlines in object .op values",
          },
          {
            severity: "high",
            code: "GHSA-4cwx-7wf7-3272",
            pkg: "undici",
            detail:
              "cross-user information disclosure and parse-time crash via degenerate private cache directives",
          },
          {
            severity: "high",
            code: "GHSA-fx2h-pf6j-xcff",
            pkg: "vite",
            detail: "server.fs.deny bypass on Windows alternate paths",
          },
          {
            severity: "moderate",
            code: "GHSA-58qx-3vcg-4xpx",
            pkg: "ws",
            detail: "uninitialized memory disclosure",
          },
        ],
      },
    ],
  },
  {
    name: "python-project",
    headline: "91 findings",
    preset: "standard",
    sections: [
      {
        title: "uv · settings",
        count: 2,
        findings: [
          {
            severity: "high",
            code: "audit.malware-disabled",
            detail: "uv audit malware-check must be true",
          },
          {
            severity: "high",
            code: "min-age.disabled",
            detail: "exclude-newer must meet 1 days",
          },
        ],
      },
      {
        title: "uv · advisories",
        count: 89,
        omitted: 85,
        findings: [
          {
            severity: "info",
            code: "GHSA-34jh-p97f-mpxf",
            pkg: "urllib3@1.26.5 -> 1.26.19",
            detail:
              "urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects",
          },
          {
            severity: "info",
            code: "GHSA-3f63-hfp8-52jq",
            pkg: "pillow@10.0.0 -> 10.2.0",
            detail: "Arbitrary Code Execution in Pillow",
          },
          {
            severity: "info",
            code: "GHSA-3ww4-gg4f-jr7f",
            pkg: "cryptography@41.0.0 -> 42.0.0",
            detail:
              "Python Cryptography package vulnerable to Bleichenbacher timing oracle attack",
          },
          {
            severity: "info",
            code: "GHSA-44wm-f244-xhp3",
            pkg: "pillow@10.0.0 -> 10.3.0",
            detail: "Pillow buffer overflow vulnerability",
          },
        ],
      },
    ],
  },
];

export const SAMPLE_SUMMARY =
  "2 projects · 1 critical, 21 high, 13 moderate, 3 low, 90 info · policy failed · exit 1";

/** Severity drives colour only; the CLI prints the word either way. */
export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "text-accent-sunset",
  high: "text-accent-sunset",
  moderate: "text-ink",
  low: "text-body",
  info: "text-body-mid",
};
