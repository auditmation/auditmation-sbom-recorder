import auditmationConfig from '@auditmation/eslint-config';
import typescriptEslint from '@typescript-eslint/eslint-plugin';
import typescriptParser from '@typescript-eslint/parser';

export default [
  {
    ignores: ['dist/**', 'package/**', 'node_modules/**', '*.js.map'],
  },
  ...auditmationConfig,
  {
    files: ['**/src/**/*.ts', '**/test/**/*.ts'],
    languageOptions: {
      parser: typescriptParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
      globals: {
        // Node.js globals
        __dirname: 'readonly',
        __filename: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        exports: 'readonly',
        global: 'readonly',
        module: 'readonly',
        process: 'readonly',
        require: 'readonly',
        // Mocha globals
        after: 'readonly',
        afterEach: 'readonly',
        before: 'readonly',
        beforeEach: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        xit: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': typescriptEslint,
    },
    rules: {
      // Disable import rules (these would need eslint-plugin-import which may not be compatible with flat config)
      'import/no-cycle': 'off',

      // TypeScript rules
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-empty-function': 'off',

      // General rules from old config
      'class-methods-use-this': 'off',
      'no-await-in-loop': 'off',
      'no-template-curly-in-string': 'off',
      'object-curly-newline': 'off',
      'no-return-await': 'off',
      'function-paren-newline': 'off',
      'function-call-argument-newline': 'off',
      'no-restricted-syntax': ['error', 'ForInStatement', 'LabeledStatement', 'WithStatement'],
      'max-len': ['error', { code: 150 }],

      // Unicorn overrides
      'unicorn/better-regex': 'warn',
      'unicorn/prevent-abbreviations': 'off',
      'unicorn/no-null': 'off',
      'unicorn/prefer-module': 'off',
      'unicorn/prefer-top-level-await': 'off',
      'unicorn/no-keyword-prefix': 'off',
      'unicorn/no-abusive-eslint-disable': 'off',
      'unicorn/no-empty-file': 'off',
      'unicorn/no-process-exit': 'off',
      'unicorn/filename-case': 'off',
      'unicorn/consistent-destructuring': 'off',
      'unicorn/prefer-array-some': 'off',
      'unicorn/no-useless-undefined': 'off',
    },
  },
];
