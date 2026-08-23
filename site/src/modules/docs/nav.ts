export interface DocsLink {
  href: string;
  label: string;
}

export interface DocsNavGroup {
  title: string;
  items: readonly DocsLink[];
}

export interface DocsTocItem {
  id: string;
  label: string;
}

export const DOCS_NAV: readonly DocsNavGroup[] = [
  {
    title: "Getting started",
    items: [
      { href: "/docs", label: "Overview" },
      { href: "/docs/install", label: "Install" },
      { href: "/docs/commands/scan", label: "Quick start" },
    ],
  },
  {
    title: "Guides",
    items: [
      { href: "/docs/config", label: "Config" },
      { href: "/docs/presets", label: "Presets" },
      { href: "/docs/managers", label: "Managers" },
      { href: "/docs/agentic", label: "Agentic checks" },
    ],
  },
];

export const DOCS_LINKS: readonly DocsLink[] = DOCS_NAV.flatMap(
  (group) => group.items
);
