import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { bufferEquals } from '@alessiofrittoli/crypto-buffer'
import { getPaths } from './hybrid.test'
import { Cipher } from '@/index'
import fs from 'fs'

describe('Cipher - File Stream Encryption/Decryption', () => {
	const dataToEncrypt = 'my TOP-SECRET message'
	const password = 'verystrong-password'

	let basepath: string, inputpath: string, encryptedPath: string, decryptedPath: string

	beforeAll(() => {
		const tempPath = fs.mkdtempSync('file-stream-hybrid')
		const paths = getPaths('file.txt', tempPath)
		basepath = paths.basepath
		inputpath = paths.inputpath
		encryptedPath = paths.encryptedPath
		decryptedPath = paths.decryptedPath

		fs.writeFileSync(inputpath, dataToEncrypt)
	})

	afterAll(() => {
		fs.rmSync(basepath, { recursive: true })
	})

	describe('Cipher.stream.Encrypt()', () => {
		it('encrypts a file based stream', async () => {
			// input where raw data to encrypt is read
			const input = fs.createReadStream(inputpath)
			// output where encrypted data is written
			const output = fs.createWriteStream(encryptedPath)

			await Cipher.stream.Encrypt(password, { input, output })

			const encrypted = fs.readFileSync(encryptedPath)

			expect(bufferEquals(encrypted, Buffer.from(dataToEncrypt))).not.toBe(true)
		})
	})

	describe('Cipher.stream.Decrypt()', () => {
		it('decrypts a file based stream', async () => {
			// --- encrypt (required so the test can run standalone) ---
			// input where raw data to encrypt is read
			const rawDataInput = fs.createReadStream(inputpath)
			// output where encrypted data is written
			const encryptedOutput = fs.createWriteStream(encryptedPath)

			await Cipher.stream.Encrypt(password, { input: rawDataInput, output: encryptedOutput })
			// --- end encrypt ---

			// input where encrypted data is read
			const input = fs.createReadStream(encryptedPath)
			// output where decrypted data is written
			const output = fs.createWriteStream(decryptedPath)

			await Cipher.stream.Decrypt(password, { input, output })

			const decrypted = fs.readFileSync(decryptedPath)

			expect(bufferEquals(decrypted, Buffer.from(dataToEncrypt))).toBe(true)
		})
	})
})
