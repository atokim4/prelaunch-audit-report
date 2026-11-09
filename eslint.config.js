import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["node_modules", "vendor", "test/fixtures", "examples", "out"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  { languageOptions: { globals: globals.node } },
  // Tests index into known fixtures; a wrong index fails the test anyway.
  { files: ["test/**/*.ts"], rules: { "@typescript-eslint/no-non-null-assertion": "off" } },
);
