import { tsdownConfig } from '@alessiofrittoli/package-configs/tsdown'
import { resolve } from 'path'

export default tsdownConfig(() => ({
	tsconfig: resolve(process.cwd(), 'tsconfig.build.json'),
}))
