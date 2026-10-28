import jsxA11y from "eslint-plugin-jsx-a11y";
import tseslint from "typescript-eslint";

const recommended = jsxA11y.flatConfigs.recommended;

export default [
  {
    ...recommended,
    files: ["**/*.jsx", "**/*.tsx"],
    languageOptions: {
      ...recommended.languageOptions,
      parser: tseslint.parser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
  },
];
