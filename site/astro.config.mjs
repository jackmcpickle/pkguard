import path from "node:path";
import { fileURLToPath } from "node:url";

import sitemap from "@astrojs/sitemap";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  // Astro's HTML compressor eats the whitespace between a text node and an
  // inline tag on the next line, gluing prose to links ("Read the<a>notes").
  compressHTML: false,
  integrations: [sitemap()],
  output: "static",
  site: "https://pkguard.dev",
  redirects: {
    "/docs/commands": "/docs/commands/scan",
    "/docs/commands/audit": "/docs/commands/scan",
    "/docs/commands/init": "/docs/commands/scan",
    "/docs/commands/help": "/docs/commands/scan",
  },
  vite: {
    plugins: [tailwindcss()],
    resolve: {
      alias: {
        "@": path.join(root, "src"),
      },
    },
  },
});
