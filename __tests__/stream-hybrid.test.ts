import crypto from 'crypto'
import { Readable, Writable } from 'stream'
import { Cipher } from '@/index'

describe( 'Cipher - In-Memory Stream Hybrid Encryption/Decryption', () => {

	const dataToEncrypt	= 'my TOP-SECRET message'
	const password		= 'verystrong-password'

	const rsaBytes	= 512
	const keyPair	= crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: rsaBytes * 8, // 4096 bits
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase: password, cipher: 'aes-256-cbc' }
	} )

	const encryptedChunks: Buffer[] = []


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
	
		await Cipher.hybridEncrypt( password, {
			key			: keyPair.publicKey,
			padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash	: 'SHA-256',
		}, { input, output } )
	
		const encryptedResult = Buffer.concat( encryptedChunks )
		
		expect( encryptedResult.toString() )
			.not.toBe( dataToEncrypt )
		
	} )


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
	
		await Cipher.hybridDecrypt(
			{
				key			: keyPair.privateKey,
				passphrase	: password,
				padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash	: 'SHA-256',
			}, { input, output, rsaKeyLength: rsaBytes }
		)
	
		const decrypted = Buffer.concat( chunks )

		expect( decrypted.toString() )
			.toBe( dataToEncrypt )

	} )

} )