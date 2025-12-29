import crypto from 'crypto'
import { Cipher } from '@/index'

const dataToEncrypt	= 'my TOP-SECRET message'


describe( 'Cipher - In-Memory Hybrid Encryption/Decryption', () => {

	const keypair = crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: 256 * 8,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
	} )


	describe( 'Cipher.HybridEncrypt()', () => {

		it( 'encrpyts the given data', () => {
			
			const encrypted = Cipher.HybridEncrypt( dataToEncrypt, keypair.publicKey )
			
			expect( encrypted.toString() ).not.toBe( dataToEncrypt )
			
		} )
	
	} )
	
	
	describe( 'Cipher.HybridDecrypt()', () => {
	
		it( 'decrypts data', () => {

			const encrypted = Cipher.HybridEncrypt( dataToEncrypt, keypair.publicKey )
			const decrypted = Cipher.HybridDecrypt( encrypted, keypair.privateKey )
	
			expect( decrypted.toString() ).toBe( dataToEncrypt )

		} )


		it( 'optionally supports PrivateKey passphares', () => {
			
			const password = 'verystrong-password'

			const keypair = crypto.generateKeyPairSync( 'rsa', {
				modulusLength		: 256 * 8,
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: {
					type		: 'pkcs8',
					format		: 'pem',
					passphrase	: password,
					cipher		: Cipher.ALGORITHM.AES_256_CBC,
				}
			} )


			const encrypted = Cipher.HybridEncrypt( dataToEncrypt, keypair.publicKey )
			const decrypted = Cipher.HybridDecrypt( encrypted, {
				key			: keypair.privateKey,
				passphrase	: password,
			} )
	
			expect( decrypted.toString() ).toBe( dataToEncrypt )

		} )

	} )

} )