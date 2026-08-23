import { COMMANDS, commandSynopsis } from "@cli/cli-catalog";

export interface DocsLink {
  href: string;
  label: string;
}

export const DOCS_LINKS: readonly DocsLink[] = [
  { href: "/docs", label: "Overview" },
  { href: "/docs/install", label: "Install" },
  { href: "/docs/commands", label: "Commands" },
  ...COMMANDS.map((command) => ({
    href: `/docs/commands/${command.name}`,
    label: commandSynopsis(command),
  })),
  { href: "/docs/config", label: "Config" },
  { href: "/docs/presets", label: "Presets" },
  { href: "/docs/managers", label: "Managers" },
  { href: "/docs/agentic", label: "Agentic checks" },
];
