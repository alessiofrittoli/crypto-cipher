import { Readable, Writable } from 'stream'
import { Cipher } from '@/index'

describe( 'Cipher - In-Memory Stream Symmetric Encryption/Decryption', () => {

	const dataToEncrypt	= 'my TOP-SECRET message'
	const password		= 'verystrong-password'

	const encryptedChunks: Buffer[] = []

	it( 'encrypts an in-memory buffer stream with Cipher Symmetric Key', async () => {

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
	
		const { encrypt } = Cipher.streamEncrypt( password, { input, output } )

		await encrypt()
	
		const encryptedResult = Buffer.concat( encryptedChunks )
		
		expect( encryptedResult.toString() )
			.not.toBe( dataToEncrypt )
		
	} )


	it( 'decrypts an in-memory buffer stream with Cipher Symmetric Key', async () => {

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
	
		const { decrypt } = await Cipher.streamDecrypt(
			password, { input, output }
		)

		await decrypt()
	
		const decrypted = Buffer.concat( chunks )

		expect( decrypted.toString() )
			.toBe( dataToEncrypt )

	} )

} )