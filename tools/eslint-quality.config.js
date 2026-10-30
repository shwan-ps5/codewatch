import js from "@eslint/js";
import security from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

const ERROR = "error";
const WARN = "warn";

const quality = {
  "no-undef": WARN,
  eqeqeq: [ERROR, "smart"],
  "no-var": ERROR,
  "prefer-const": WARN,
  "no-eval": ERROR,
  "no-implied-eval": ERROR,
  "no-new-func": ERROR,
  "no-throw-literal": ERROR,
  "no-unused-expressions": ERROR,
  "consistent-return": WARN,
  "default-case-last": ERROR,
  "no-shadow": WARN,
  "no-return-assign": ERROR,
  "no-self-compare": ERROR,
  "no-unmodified-loop-condition": ERROR,
  "no-unreachable-loop": ERROR,
  "no-template-curly-in-string": WARN,
  "require-atomic-updates": WARN,
  "max-depth": [WARN, 4],
  "max-params": [WARN, 6],
  "max-nested-callbacks": [WARN, 4],
  // `a ?? 32 - 32` reads as `(a ?? 32) - 32` but parses as `a ?? 0`.
  // Each group pairs ?? with one operator, so ordinary arithmetic like a + b * c is not flagged.
  "no-mixed-operators": [ERROR, { groups: ["+", "-", "*", "/", "%", "**"].map((op) => ["??", op]) }],
  "no-restricted-syntax": [
    WARN,
    {
      selector: "CallExpression[callee.property.name=/^reduce(Right)?$/][arguments.length=1]",
      message: "reduce() without an initial value throws on an empty array",
    },
  ],
};

// Flags every obj[variable] access; in practice nearly all of its findings are false positives.
const securityRules = { ...security.configs.recommended.rules, "security/detect-object-injection": "off" };

export default [
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.jsx", "**/*.ts", "**/*.tsx"],
    plugins: { security },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parser: tseslint.parser,
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser, ...globals.node, ...globals.es2021 },
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    rules: { ...js.configs.recommended.rules, ...securityRules, ...quality },
  },
  { files: ["**/*.cjs"], languageOptions: { sourceType: "commonjs" } },
  // The TypeScript compiler already resolves names; no-undef misfires on types.
  { files: ["**/*.ts", "**/*.tsx"], rules: { "no-undef": "off", "no-unused-vars": "off" } },
];
