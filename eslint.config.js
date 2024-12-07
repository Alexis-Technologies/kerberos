const neostandard = require('neostandard');
const { resolveIgnoresFromGitignore } = require('neostandard');

const config = neostandard({
  env: ['builtin', 'nodeBuiltin', 'node'],
  globals: ['process', 'require', 'module', 'exports'],
  files: ['src/**/*.js'],
  ignores: ['!**/*', 'node_modules', 'dist', '.nx', ...resolveIgnoresFromGitignore()],
  semi: true,
});

config[config.length - 1].rules = {
  ...config[config.length - 1].rules,
  '@stylistic/space-before-function-paren': 'off',
  '@stylistic/quotes': ['error', 'single', { allowTemplateLiterals: true }],
};

module.exports = config;
