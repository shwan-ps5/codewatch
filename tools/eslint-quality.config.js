import js from "@eslint/js";
import security from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

const quality = {
  "no-undef": "warn",
  eqeqeq: ["error", "smart"],
  "no-var": "error",
  "prefer-const": "warn",
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
  "no-throw-literal": "error",
  "no-unused-expressions": "error",
  "consistent-return": "warn",
  "default-case-last": "error",
  "no-shadow": "warn",
  "no-return-assign": "error",
  "no-self-compare": "error",
  "no-unmodified-loop-condition": "error",
  "no-unreachable-loop": "error",
  "no-template-curly-in-string": "warn",
  "require-atomic-updates": "warn",
  "max-depth": ["warn", 4],
  "max-params": ["warn", 6],
  "max-nested-callbacks": ["warn", 4],
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
