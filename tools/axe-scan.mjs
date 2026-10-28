// Usage: node axe-scan.mjs urls.json  ->  JSON on stdout: [{url, error?, violations: [...]}]
// urls.json: {"urls": ["https://..."], "timeoutMs": 30000, "colorScheme": "light" | "dark"}
import { readFileSync } from "node:fs";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";

const { urls, timeoutMs = 30000, colorScheme = "light" } = JSON.parse(readFileSync(process.argv[2], "utf8"));
const MAX_NODES = 20;

const browser = await chromium.launch();
const results = [];
try {
  for (const url of urls) {
    const context = await browser.newContext({ colorScheme });
    const page = await context.newPage();
    try {
      await page.goto(url, { waitUntil: "networkidle", timeout: timeoutMs });
      const report = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"])
        .analyze();
      results.push({
        url,
        violations: report.violations.map((v) => ({
          id: v.id,
          impact: v.impact,
          help: v.help,
          helpUrl: v.helpUrl,
          tags: v.tags,
          nodes: v.nodes.slice(0, MAX_NODES).map((n) => ({
            target: n.target.join(" "),
            summary: n.failureSummary,
          })),
        })),
      });
    } catch (err) {
      results.push({ url, error: String(err.message || err).split("\n")[0], violations: [] });
    } finally {
      await context.close();
    }
  }
} finally {
  await browser.close();
}
process.stdout.write(JSON.stringify(results));
