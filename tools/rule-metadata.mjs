// Prints metadata for the Node-based rules codewatch enables, for the rule catalogue.
// Usage: node rule-metadata.mjs html-validate-config.json
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { ESLint } from "eslint";
import { builtinRules } from "eslint/use-at-your-own-risk";
import { HtmlValidate } from "html-validate";

const require = createRequire(import.meta.url);
const here = new URL(".", import.meta.url).pathname;

async function enabledEslintRules(configFile, sample) {
  const eslint = new ESLint({ overrideConfigFile: here + configFile, cwd: here });
  const config = await eslint.calculateConfigForFile(here + sample);
  return Object.entries(config.rules)
    .filter(([, setting]) => (Array.isArray(setting) ? setting[0] : setting) !== 0 && setting !== "off")
    .map(([id]) => id);
}

const PLUGINS = new Map([
  ["security", new Map(Object.entries(require("eslint-plugin-security").rules))],
  ["jsx-a11y", new Map(Object.entries(require("eslint-plugin-jsx-a11y").rules))],
]);

function eslintMeta(id) {
  const [plugin, name] = id.includes("/") ? id.split("/") : [null, id];
  const rule = plugin ? PLUGINS.get(plugin)?.get(name) : builtinRules.get(id);
  const docs = rule?.meta?.docs ?? {};
  return { id, description: docs.description ?? "", url: docs.url ?? "", category: docs.category ?? "" };
}

const eslintRules = (await enabledEslintRules("eslint-quality.config.js", "sample.js")).map(eslintMeta);
const a11yRules = (await enabledEslintRules("eslint-a11y.config.js", "sample.tsx")).map(eslintMeta);

// eslint-disable-next-line security/detect-non-literal-fs-filename -- path chosen by codewatch, not by scanned code
const hvConfig = JSON.parse(readFileSync(process.argv[2], "utf8"));
const resolved = await new HtmlValidate(hvConfig).getConfigFor("sample.html");
const htmlRules = [];
for (const [id, [severity]] of resolved.getRules()) {
  if (severity === 0) continue;
  htmlRules.push({ id, url: `https://html-validate.org/rules/${id}.html` });
}

const stylelint = require("stylelint");
const styleConfig = await stylelint.resolveConfig(here + "sample.css", { configFile: here + "stylelint.config.json" });
const styleRules = Object.entries(styleConfig.rules ?? {})
  .filter(([, v]) => v !== null && v !== false)
  .map(([id, v]) => ({ id, url: `https://stylelint.io/user-guide/rules/${id}`,
                       warning: Array.isArray(v) && v[1]?.severity === "warning" }));

const axe = require("axe-core");
const axeRules = axe.getRules().map((r) => ({
  id: r.ruleId, description: r.description, help: r.help, url: r.helpUrl.split("?")[0], tags: r.tags,
}));

process.stdout.write(JSON.stringify({ eslint: eslintRules, "jsx-a11y": a11yRules, "html-a11y": htmlRules, axe: axeRules, stylelint: styleRules }));
