import { CONFIG_FILE_NAME } from "./app-name";

export type ConfigSourceKind = "user" | "scan" | "repo";

export interface ConfigSource {
  kind: ConfigSourceKind;
  path: string;
}

export const CONFIG_SEARCH_ORDER = `Looks for a user/tool config, then ${CONFIG_FILE_NAME} in the scan directory and each project. Closer wins; flags win over files.`;

const SEARCH_ORDER = CONFIG_SEARCH_ORDER;

const ANSI = {
  dim: "\u001B[2m",
  reset: "\u001B[0m",
};

const paint = (text: string, code: string, on: boolean): string =>
  on ? `${code}${text}${ANSI.reset}` : text;

const padEnd = (text: string, width: number): string =>
  text.length >= width ? text : `${text}${" ".repeat(width - text.length)}`;

const colWidth = (cells: readonly string[]): number => {
  let width = 0;
  for (const cell of cells) {
    if (cell.length > width) {
      width = cell.length;
    }
  }
  return width;
};

export const formatConfigSources = (
  sources: readonly ConfigSource[],
  readFile: (filePath: string) => string | null,
  opts?: { color?: boolean }
): string => {
  const color = opts?.color ?? false;
  const headers = ["Kind", "Path", "Status"] as const;
  const rows = sources.map((source) => {
    const status = readFile(source.path) === null ? "missing" : "found";
    return [source.kind, source.path, status] as const;
  });
  const widths = headers.map((header, index) =>
    colWidth([header, ...rows.map((row) => row[index] ?? "")])
  );
  const line = (cells: readonly string[]): string =>
    `  ${cells.map((cell, index) => padEnd(cell, widths[index] ?? 0)).join("  ")}`;
  const body = [
    paint("Configuration:", ANSI.dim, color),
    paint(`  ${SEARCH_ORDER}`, ANSI.dim, color),
    "",
    paint(line(headers), ANSI.dim, color),
    ...rows.map((row) => paint(line(row), ANSI.dim, color)),
    "",
  ].join("\n");
  return body;
};
