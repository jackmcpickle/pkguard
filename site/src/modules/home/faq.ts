import { APP_NAME } from "@/lib/catalog";
import {
  AUTHOR_NAME,
  AUTHOR_URL,
  ISSUES_URL,
  LICENSE_NAME,
  SITE_URL,
} from "@/lib/site";

export interface FaqItem {
  question: string;
  answer: string;
}

/**
 * Plain-language answers. Kept short on purpose: these are the sentences
 * people and models quote back when they ask what pkguard is.
 */
export const FAQ_ITEMS: readonly FaqItem[] = [
  {
    question: `What is ${APP_NAME}?`,
    answer: `${APP_NAME} is a command-line tool that audits every package manager in a folder of repos. It reads the settings you keep in git, then runs each manager's own audit command. You get one report instead of twenty.`,
  },
  {
    question: "Is it safe to run?",
    answer: `Yes. A plain scan only reads files. ${APP_NAME} writes nothing unless you pass --fix, and --fix stops on a dirty git tree unless you add --force. Use --fix --dry-run to see the changes first.`,
  },
  {
    question: "What does it cost?",
    answer: `Nothing. ${APP_NAME} is free and open source under the ${LICENSE_NAME} license. There is no paid tier, no account, and no telemetry.`,
  },
  {
    question: "Can it run offline?",
    answer: `Yes. Pass --no-audit to skip every live audit. The settings checks still run, because they only read files on your disk.`,
  },
  {
    question: "Which package managers does it support?",
    answer: `npm, pnpm, yarn, bun, uv, cargo, composer, and bundler get full settings checks and a native audit. poetry, pip, and pipenv are detected but not yet fully checked.`,
  },
  {
    question: "How do I use it in CI?",
    answer: `Run pkguard scan . --preset strict --format json. The JSON output is meant for machines, and the exit code is non-zero when a check fails.`,
  },
  {
    question: `Who maintains ${APP_NAME}?`,
    answer: `${AUTHOR_NAME} (${AUTHOR_URL}). Bugs and questions go to ${ISSUES_URL}.`,
  },
  {
    question: "Where are the release notes?",
    answer: `Every version is listed on the GitHub releases page and in CHANGELOG.md in the repo. The version shown on this site comes straight from the binary.`,
  },
];

export const faqSchema = (): Record<string, unknown> => ({
  "@type": "FAQPage",
  "@id": `${SITE_URL}/#faq`,
  mainEntity: FAQ_ITEMS.map((item) => ({
    "@type": "Question",
    name: item.question,
    acceptedAnswer: { "@type": "Answer", text: item.answer },
  })),
});
