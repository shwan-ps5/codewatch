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
};

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
    rules: { ...js.configs.recommended.rules, ...security.configs.recommended.rules, ...quality },
  },
  { files: ["**/*.cjs"], languageOptions: { sourceType: "commonjs" } },
  // The TypeScript compiler already resolves names; no-undef misfires on types.
  { files: ["**/*.ts", "**/*.tsx"], rules: { "no-undef": "off", "no-unused-vars": "off" } },
];
