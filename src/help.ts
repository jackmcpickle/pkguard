import { APP_NAME } from "./app-name";

const ANSI = {
  bold: "\u001B[1m",
  cyan: "\u001B[36m",
  dim: "\u001B[2m",
  reset: "\u001B[0m",
};

const paint = (text: string, code: string, on: boolean): string =>
  on ? `${code}${text}${ANSI.reset}` : text;

interface HelpArg {
  name: string;
  required: boolean;
  description: string;
}

interface HelpFlag {
  names: readonly string[];
  value?: string;
  description: string;
}

interface CommandHelp {
  name: string;
  summary: string;
  arguments: readonly HelpArg[];
  flags: readonly HelpFlag[];
}

const HELP_FLAG: HelpFlag = {
  description: "Show this help",
  names: ["-h", "--help"],
};

const COMMANDS: readonly CommandHelp[] = [
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
        names: ["--apply"],
      },
      {
        description: "Upgrade packages with known fixes (no major bumps)",
        names: ["--apply-advisories"],
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

export const isHelpFlag = (arg: string): boolean =>
  arg === "--help" || arg === "-h";

export const commandByName = (name: string): CommandHelp | undefined =>
  COMMANDS.find((command) => command.name === name);

const argToken = (arg: HelpArg): string =>
  arg.required ? `<${arg.name}>` : `[${arg.name}]`;

const synopsis = (command: CommandHelp): string => {
  if (command.arguments.length === 0) {
    return command.name;
  }
  return `${command.name} ${command.arguments.map(argToken).join(" ")}`;
};

const flagLabel = (flag: HelpFlag): string => {
  const names = flag.names.join(", ");
  return flag.value === undefined ? names : `${names} <${flag.value}>`;
};

const colWidth = (labels: readonly string[]): number => {
  let width = 0;
  for (const label of labels) {
    if (label.length > width) {
      width = label.length;
    }
  }
  return width;
};

const padEnd = (text: string, width: number): string =>
  text.length >= width ? text : `${text}${" ".repeat(width - text.length)}`;

const row = (
  label: string,
  description: string,
  width: number,
  color: boolean
): string =>
  `  ${paint(padEnd(label, width), ANSI.cyan, color)}  ${paint(description, ANSI.dim, color)}`;

const heading = (text: string, color: boolean): string =>
  paint(text, ANSI.bold, color);

export const formatRootHelp = (color: boolean): string => {
  const labels = COMMANDS.map((command) => synopsis(command));
  const width = colWidth(labels);
  const rows = COMMANDS.map((command, index) =>
    row(labels[index] ?? command.name, command.summary, width, color)
  );
  return [
    heading(`Usage: ${APP_NAME} <command>`, color),
    "",
    paint(
      "Audit package-manager security settings and advisories.",
      ANSI.dim,
      color
    ),
    "",
    heading("Commands:", color),
    ...rows,
    "",
    paint(
      `Run \`${APP_NAME} <command> --help\` for flag details.`,
      ANSI.dim,
      color
    ),
    "",
  ].join("\n");
};

export const formatCommandHelp = (
  command: CommandHelp,
  color: boolean
): string => {
  const lines = [
    heading(`Usage: ${APP_NAME} ${synopsis(command)}`, color),
    "",
    paint(command.summary, ANSI.dim, color),
  ];
  if (command.arguments.length > 0) {
    const labels = command.arguments.map((arg) => arg.name);
    lines.push("", heading("Arguments:", color));
    for (const arg of command.arguments) {
      lines.push(row(arg.name, arg.description, colWidth(labels), color));
    }
  }
  if (command.flags.length > 0) {
    const labels = command.flags.map((flag) => flagLabel(flag));
    lines.push("", heading("Options:", color));
    for (const flag of command.flags) {
      lines.push(
        row(flagLabel(flag), flag.description, colWidth(labels), color)
      );
    }
  }
  lines.push("");
  return lines.join("\n");
};

export const formatUnknownCommand = (name: string, color: boolean): string =>
  `${heading(`Unknown command: ${name}`, color)}\n\n${formatRootHelp(color)}`;
