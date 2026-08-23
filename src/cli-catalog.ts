export interface HelpArg {
  name: string;
  required: boolean;
  description: string;
}

export interface HelpFlag {
  names: readonly string[];
  value?: string;
  description: string;
}

export interface CommandHelp {
  name: string;
  summary: string;
  arguments: readonly HelpArg[];
  flags: readonly HelpFlag[];
}

export const HELP_FLAG: HelpFlag = {
  description: "Show this help",
  names: ["-h", "--help"],
};

export const COMMANDS: readonly CommandHelp[] = [
  {
    arguments: [
      {
        description: "Directory to scan (default: current directory)",
        name: "path",
        required: false,
      },
    ],
    flags: [
      {
        description: "Policy preset: relaxed, standard, or strict",
        names: ["--preset"],
        value: "name",
      },
      {
        description: "Max concurrent advisory audits (default: 4)",
        names: ["--concurrency"],
        value: "n",
      },
      {
        description: "Write a markdown report to path",
        names: ["--report"],
        value: "path",
      },
      {
        description: "Write settings fixes (clean git tree required)",
        names: ["--apply", "--fix"],
      },
      {
        description: "Upgrade packages with known fixes (no major bumps)",
        names: ["--apply-advisories"],
      },
      {
        description:
          "Write safe agentic edits only. Never writes a home-dir store or deletes overrides",
        names: ["--apply-agentic"],
      },
      {
        description: "Allow major version bumps when applying advisories",
        names: ["--allow-majors"],
      },
      {
        description: "Prompt for consent per repo",
        names: ["--interactive", "-i"],
      },
      {
        description: "Apply even when the git tree is dirty",
        names: ["--force"],
      },
      {
        description: "Commit applied changes (one commit per repo)",
        names: ["--commit"],
      },
      {
        description: "Print the full result as JSON",
        names: ["--json"],
      },
      {
        description: "Print the result as SARIF",
        names: ["--sarif"],
      },
      {
        description: "Bypass the lockfile digest cache and re-run audits",
        names: ["--refresh"],
      },
      {
        description: "Bypass the cache and do not write new entries",
        names: ["--no-cache"],
      },
      HELP_FLAG,
    ],
    name: "audit",
    summary: "Audit settings and advisories (never writes unless apply flags)",
  },
  {
    arguments: [],
    flags: [
      {
        description: "Write .mailclad.toml in the current directory",
        names: ["--local"],
      },
      {
        description: "Overwrite an existing file",
        names: ["--force"],
      },
      HELP_FLAG,
    ],
    name: "init",
    summary: "Write a starter user config (or --local for this directory)",
  },
  {
    arguments: [
      {
        description: "Command to describe",
        name: "command",
        required: false,
      },
    ],
    flags: [HELP_FLAG],
    name: "help",
    summary: "Show this help or help for a command",
  },
];

export const argToken = (arg: HelpArg): string =>
  arg.required ? `<${arg.name}>` : `[${arg.name}]`;

export const commandSynopsis = (command: CommandHelp): string => {
  if (command.arguments.length === 0) {
    return command.name;
  }
  return `${command.name} ${command.arguments.map(argToken).join(" ")}`;
};

export const flagLabel = (flag: HelpFlag): string => {
  const names = flag.names.join(", ");
  return flag.value === undefined ? names : `${names} <${flag.value}>`;
};

export const commandByName = (name: string): CommandHelp | undefined =>
  COMMANDS.find((command) => command.name === name);
