// codewatch's own checks that need a parser: repeated string literals in JS/TS, and ReDoS-prone regexes.
// Usage: node codewatch-checks.mjs spec.json out.json
// spec: {"jsFiles": [abs paths], "minLength": 5, "maxRepeats": 3, "pythonRegexes": [{path, line, pattern, flags}]}
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ts = require("typescript");
const { checkSync } = require("recheck");

const spec = JSON.parse(readFileSync(process.argv[2], "utf8"));
const literals = [];
const regexes = [];

function scriptKind(path) {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return path.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
}

// Strings that are names rather than repeated data: module specifiers, property keys and literal types.
function isStructural(node) {
  const p = node.parent;
  if (!p) return false;
  if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isExternalModuleReference(p)) return true;
  if (ts.isCallExpression(p) && p.expression.getText() === "require") return true;
  if ((ts.isPropertyAssignment(p) || ts.isPropertySignature(p) || ts.isPropertyDeclaration(p)) && p.name === node) return true;
  return ts.isLiteralTypeNode(p) || ts.isElementAccessExpression(p);
}

function scanJs(path) {
  const text = readFileSync(path, "utf8");
  const sf = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, scriptKind(path));
  const seen = new Map();
  const lineOf = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const visit = (node) => {
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && !isStructural(node)
        && node.text.trim().length >= spec.minLength) {
      if (!seen.has(node.text)) seen.set(node.text, []);
      seen.get(node.text).push(lineOf(node));
    }
    if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
      const raw = node.getText(sf);
      const end = raw.lastIndexOf("/");
      regexes.push({ path, line: lineOf(node), pattern: raw.slice(1, end), flags: raw.slice(end + 1) });
    }
    if ((ts.isNewExpression(node) || ts.isCallExpression(node)) && node.expression.getText(sf) === "RegExp"
        && node.arguments?.length && ts.isStringLiteral(node.arguments[0])) {
      const flags = node.arguments[1] && ts.isStringLiteral(node.arguments[1]) ? node.arguments[1].text : "";
      regexes.push({ path, line: lineOf(node), pattern: node.arguments[0].text, flags });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  for (const [value, lines] of seen) {
    if (lines.length > spec.maxRepeats) literals.push({ path, value, lines });
  }
}

for (const path of spec.jsFiles) {
  try {
    scanJs(path);
  } catch (err) {
    process.stderr.write(`${path}: ${err.message}\n`);
  }
}

const checked = [];
for (const r of [...regexes, ...spec.pythonRegexes]) {
  try {
    const result = checkSync(r.pattern, r.flags.replace(/[^dgimsuyv]/g, ""), { timeout: 3000 });
    if (result.status === "vulnerable") {
      checked.push({ ...r, complexity: result.complexity?.type, summary: result.complexity?.summary,
                     attack: result.attack?.pattern });
    }
  } catch (err) {
    // Patterns JavaScript can't parse (some Python-only syntax) are skipped rather than guessed at.
  }
}

writeFileSync(process.argv[3], JSON.stringify({ literals, regexes: checked }));
