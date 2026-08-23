import { AGENTIC_CATALOG } from "./agentic-catalog";
import { APP_NAME } from "./app-name";
import type { CommandHelp } from "./cli-catalog";
import { COMMANDS, commandSynopsis, flagLabel } from "./cli-catalog";

export { commandByName } from "./cli-catalog";

const ANSI = {
  bold: "\u001B[1m",
  cyan: "\u001B[36m",
  dim: "\u001B[2m",
  reset: "\u001B[0m",
};

const paint = (text: string, code: string, on: boolean): string =>
  on ? `${code}${text}${ANSI.reset}` : text;

export const isHelpFlag = (arg: string): boolean =>
  arg === "--help" || arg === "-h";

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
  const labels = COMMANDS.map((command) => commandSynopsis(command));
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
    heading(`Usage: ${APP_NAME} ${commandSynopsis(command)}`, color),
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
  if (command.name === "audit") {
    lines.push(
      "",
      heading("Agentic checks:", color),
      paint(
        "Warned by default (agentic = true). Apply is off (applyAgentic = false) unless --apply-agentic.",
        ANSI.dim,
        color
      )
    );
    const codeWidth = colWidth(AGENTIC_CATALOG.map((check) => check.code));
    for (const check of AGENTIC_CATALOG) {
      lines.push(
        row(check.code, check.description, codeWidth, color),
        paint(`    ${check.caveat}`, ANSI.dim, color)
      );
    }
  }
  lines.push("");
  return lines.join("\n");
};

export const formatUnknownCommand = (name: string, color: boolean): string =>
  `${heading(`Unknown command: ${name}`, color)}\n\n${formatRootHelp(color)}`;
