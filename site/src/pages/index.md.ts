import type { APIRoute } from "astro";

import { APP_NAME, APP_VERSION, MANAGER_DOCS } from "@/lib/catalog";
import {
  AUTHOR_NAME,
  AUTHOR_URL,
  BREW_INSTALL,
  CHANGELOG_URL,
  GITHUB_URL,
  ISSUES_URL,
  LICENSE_NAME,
  LICENSE_URL,
  RELEASES_URL,
  SITE_UPDATED,
  SITE_URL,
} from "@/lib/site";
import { FAQ_ITEMS } from "@/modules/home/faq";

const ported = MANAGER_DOCS.filter((manager) => manager.ported).map(
  (manager) => manager.name,
);
const detectOnly = MANAGER_DOCS.filter((manager) => !manager.ported).map(
  (manager) => manager.name,
);

const body = `# ${APP_NAME}

> ${APP_NAME} is a free command-line tool. It scans a folder full of repos, finds
> every package manager, reads the settings you keep in git, and runs each
> manager's own audit. One command instead of one per project.

- Version: ${APP_VERSION}
- License: ${LICENSE_NAME} (${LICENSE_URL})
- Price: free. No paid tier, no account, no telemetry.
- Maintainer: ${AUTHOR_NAME} (${AUTHOR_URL})
- Source: ${GITHUB_URL}
- Release notes: ${RELEASES_URL} and ${CHANGELOG_URL}
- Support: ${ISSUES_URL}
- Last updated: ${SITE_UPDATED}

## Install

\`\`\`
${BREW_INSTALL}
\`\`\`

## How it works

1. Find each root. ${APP_NAME} walks the path you pass and stops at every
   package-manager root.
2. Read committed settings. It parses the config files in git. A missing binary
   does not skip this step.
3. Run the native audit. If the manager binary is on PATH, ${APP_NAME} shells out
   to that manager's own audit command.

A scan never writes files. Pass \`--fix\` when you want ${APP_NAME} to repair the
unsafe settings it finds.

## Supported package managers

- Full settings checks and native audit: ${ported.join(", ")}
- Detected only: ${detectOnly.join(", ")}

## Questions and answers

${FAQ_ITEMS.map((item) => `### ${item.question}\n\n${item.answer}`).join("\n\n")}

## More

- Docs: ${SITE_URL}/docs
- About and contact: ${SITE_URL}/about
- Full text for AI: ${SITE_URL}/llms-full.txt
`;

export const GET: APIRoute = () =>
  new Response(body, {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
    },
  });
