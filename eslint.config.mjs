import globals from 'globals'
import pluginJs from '@eslint/js'
import tseslint from 'typescript-eslint'

/**
 * Initial file generated with `npm lint -- --init`
 * 
 * @type {import('eslint').Linter.Config[]}
 */
// @ts-expect-error `languageOptions` property in `tseslint.configs.recommended` result incompatible with `eslint` config types.
const tseslintReccommended = tseslint.configs.recommended

/** @type {import('eslint').Linter.Config[]} */
const config = [
	{ languageOptions: { globals: { ...globals.browser, ...globals.node } } },
	pluginJs.configs.recommended,
	...tseslintReccommended,
	{ files: [ 'src/**/*.{js,mjs,cjs,ts}' ] },
	{ ignores: [ 'dist', 'scripts', 'coverage' ] },
	{ rules: {
		'@typescript-eslint/no-namespace': 'off',
	} },
]

export default config