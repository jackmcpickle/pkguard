import path from "node:path";
import { fileURLToPath } from "node:url";

import sitemap from "@astrojs/sitemap";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  integrations: [sitemap()],
  output: "static",
  site: "https://pkguard.dev",
  redirects: {
    "/docs/commands/audit": "/docs/commands/scan",
    "/docs/commands/init": "/docs/commands",
    "/docs/commands/help": "/docs/commands",
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
