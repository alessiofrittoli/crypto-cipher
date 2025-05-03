import { defineConfig } from 'tsup'

const enableSourcemap = process.env.NODE_ENV !== 'production'

export default defineConfig( {
	entry		: [ 'src/**/*.ts' ],
	format		: [ 'cjs', 'esm' ],
	dts			: true,
	splitting	: true,
	shims		: false,
	skipNodeModulesBundle: true,
	clean		: true,
	minify		: true,
	sourcemap	: enableSourcemap,
} )