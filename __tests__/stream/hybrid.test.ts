import { describe, expect, it } from 'vitest'
import { Readable, Writable } from 'stream'
import { Cipher } from '@/index'
import crypto from 'crypto'

describe('Cipher - In-Memory Stream Hybrid Encryption/Decryption', () => {
	const dataToEncrypt = 'my TOP-SECRET message'
	const password = 'verystrong-password'

	const rsaBytes = 512
	const keyPair = crypto.generateKeyPairSync('rsa', {
		modulusLength: rsaBytes * 8, // 4096 bits
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: {
			type: 'pkcs1',
			format: 'pem',
			passphrase: password,
			cipher: Cipher.ALGORITHM.CHACHA_20_POLY,
		},
	})

	describe('Cipher.stream.HybridEncrypt()', () => {
		it('encrypts an in-memory buffer stream', async () => {
			const encryptedChunks: Buffer[] = []

			// Create a `Readable` Stream with raw data.
			const input = new Readable({
				read(): void {
					this.push(dataToEncrypt) // Push data to encrypt
					this.push(null) // Signal end of stream
				},
			})

			// `Writable` Stream where encrypted data is written
			const output = new Writable({
				write(chunk, encoding, callback): void {
					encryptedChunks.push(chunk)
					callback()
				},
			})

			await Cipher.stream.HybridEncrypt(keyPair.publicKey, { input, output })

			const encryptedResult = Buffer.concat(encryptedChunks)

			expect(encryptedResult.toString()).not.toBe(dataToEncrypt)
		})
	})

	describe('Cipher.stream.HybridDecrypt()', () => {
		it('decrypts an in-memory buffer stream', async () => {
			// --- encrypt (required so the test can run standalone) ---
			const encryptedChunks: Buffer[] = []

			// Create a `Readable` Stream with raw data.
			const rawDataInput = new Readable({
				read(): void {
					this.push(dataToEncrypt) // Push data to encrypt
					this.push(null) // Signal end of stream
				},
			})

			// `Writable` Stream where encrypted data is written
			const encryptedOutput = new Writable({
				write(chunk, encoding, callback): void {
					encryptedChunks.push(chunk)
					callback()
				},
			})

			await Cipher.stream.HybridEncrypt(keyPair.publicKey, {
				input: rawDataInput,
				output: encryptedOutput,
			})

			// --- end encrypt ---

			// Create a `Readable` Stream with encrypted data.
			const input = Readable.from(encryptedChunks)

			const chunks: Buffer[] = []

			// `Writable` Stream where decrypted data is written
			const output = new Writable({
				write(chunk, encoding, callback): void {
					chunks.push(chunk)
					callback()
				},
			})

			await Cipher.stream.HybridDecrypt(
				{
					key: keyPair.privateKey,
					passphrase: password,
				},
				{ input, output },
			)

			const decrypted = Buffer.concat(chunks)

			expect(decrypted.toString()).toBe(dataToEncrypt)
		})

		it('handles stream errors correctly', async () => {
			const encryptedChunks: Buffer[] = []

			const input = Readable.from([
				Buffer.from('Chunk n.1'),
				Buffer.from('Chunk n.2'),
				Buffer.from('Chunk n.3'),
				Buffer.from('Chunk n.4'),
			])

			// `Writable` Stream where encrypted data is written
			const output = new Writable({
				write(chunk, encoding, callback): void {
					encryptedChunks.push(chunk)
					callback()
				},
			})

			await Cipher.stream.HybridEncrypt(keyPair.publicKey, { input, output })

			const decryptInput = Readable.from(encryptedChunks)

			let chunkN = -1
			// `Writable` Stream where decrypted data is written
			const decryptOutput = new Writable({
				write(chunk, encoding, callback): void {
					chunkN++
					if (chunkN === 2) {
						return callback(new Error('Error returned.'))
					}
					callback()
				},
			})

			await expect(() =>
				Cipher.stream.HybridDecrypt(
					{
						key: keyPair.privateKey,
						passphrase: password,
					},
					{ input: decryptInput, output: decryptOutput },
				),
			).rejects.toThrow('Error returned.')
		})
	})
})
