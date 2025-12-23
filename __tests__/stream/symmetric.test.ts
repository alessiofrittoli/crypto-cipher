import { Readable, Writable } from 'stream'
import { Cipher } from '@/index'


describe( 'Cipher - In-Memory Stream Encryption/Decryption', () => {
	
	const dataToEncrypt	= 'my TOP-SECRET message'
	const password		= 'verystrong-password'

	const encryptedChunks: Buffer[] = []


	describe( 'Cipher.stream.Encrypt()', () => {

		it( 'encrypts an in-memory buffer stream', async () => {
	
			// Create a `Readable` Stream with raw data.
			const input = new Readable( {
				read()
				{
					this.push( dataToEncrypt ) // Push data to encrypt
					this.push( null ) // Signal end of stream
				},
			} )
	
			// `Writable` Stream where encrypted data is written
			const output = new Writable( {
				write( chunk, encoding, callback )
				{
					encryptedChunks.push( chunk )
					callback()
				}
			} )

			await Cipher.stream.Encrypt( password, { input, output } )
			
			const encryptedResult = Buffer.concat( encryptedChunks )
			
			expect( encryptedResult.toString() )
				.not.toBe( dataToEncrypt )

		} )

	} )


	describe( 'Cipher.stream.Decrypt()', () => {

		it( 'decrypts an in-memory buffer stream', async () => {

			const encryptedResult = Buffer.concat( encryptedChunks )
		
			// Create a `Readable` Stream with encrypted data.
			const input = new Readable( {
				read()
				{
					this.push( encryptedResult ) // Push data to decrypt
					this.push( null ) // Signal end of stream
				},
			} )
		
			const chunks: Buffer[] = []
		
			// `Writable` Stream where decrypted data is written
			const output = new Writable( {
				write( chunk, encoding, callback )
				{
					chunks.push( chunk )
					callback()
				},
			} )

			await Cipher.stream.Decrypt( password, { input, output } )

			const decrypted = Buffer.concat( chunks )

			expect( decrypted.toString() )
				.toBe( dataToEncrypt )
			
		} )

	} )

} )