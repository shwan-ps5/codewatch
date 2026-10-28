// codewatch's own checks that need a parser: repeated string literals in JS/TS, and ReDoS-prone regexes.
// Usage: node codewatch-checks.mjs spec.json out.json
// spec: {"jsFiles": [abs paths], "minLength": 5, "maxRepeats": 3, "pythonRegexes": [{path, line, pattern, flags}]}
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ts = require("typescript");
const { checkSync } = require("recheck");

// eslint-disable-next-line security/detect-non-literal-fs-filename -- path chosen by codewatch, not by scanned code
const spec = JSON.parse(readFileSync(process.argv[2], "utf8"));
const literals = [];
const regexes = [];

function scriptKind(path) {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return path.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
}

// Strings that are names rather than repeated data: module specifiers, property keys and literal types.
const STRUCTURAL_PARENTS = [
  (p) => ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isExternalModuleReference(p),
  (p) => ts.isCallExpression(p) && p.expression.getText() === "require",
  (p, node) => p.name === node
    && (ts.isPropertyAssignment(p) || ts.isPropertySignature(p) || ts.isPropertyDeclaration(p)),
  (p) => ts.isLiteralTypeNode(p) || ts.isElementAccessExpression(p),
];

function isStructural(node) {
  return Boolean(node.parent) && STRUCTURAL_PARENTS.some((test) => test(node.parent, node));
}

function isRepeatableString(node) {
  return (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && !isStructural(node)
    && node.text.trim().length >= spec.minLength;
}

function regexLiteral(node, sf) {
  if (node.kind !== ts.SyntaxKind.RegularExpressionLiteral) return null;
  const raw = node.getText(sf);
  const end = raw.lastIndexOf("/");
  return { pattern: raw.slice(1, end), flags: raw.slice(end + 1) };
}

// new RegExp("...", "flags") / RegExp("...") with literal arguments.
function regexConstructor(node, sf) {
  const isCall = ts.isNewExpression(node) || ts.isCallExpression(node);
  if (!isCall || node.expression.getText(sf) !== "RegExp") return null;
  const [source, flags] = node.arguments ?? [];
  if (!source || !ts.isStringLiteral(source)) return null;
  return { pattern: source.text, flags: flags && ts.isStringLiteral(flags) ? flags.text : "" };
}

function scanJs(path) {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- path chosen by codewatch, not by scanned code
  const text = readFileSync(path, "utf8");
  const sf = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, scriptKind(path));
  const seen = new Map();
  const lineOf = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const visit = (node) => {
    if (isRepeatableString(node)) {
      if (!seen.has(node.text)) seen.set(node.text, []);
      seen.get(node.text).push(lineOf(node));
    }
    const regex = regexLiteral(node, sf) ?? regexConstructor(node, sf);
    if (regex) regexes.push({ path, line: lineOf(node), ...regex });
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
