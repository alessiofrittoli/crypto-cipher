import crypto from 'crypto'
import { readUint16BE } from '@alessiofrittoli/crypto-buffer/conversion'
import { Cipher } from '@/new'

const dataToEncrypt	= 'my TOP-SECRET message'


describe( 'Cipher - In-Memory Hybrid Encryption/Decryption', () => {

	const keypair = crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: 256 * 8,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs8', format: 'pem' },
	} )


	describe( 'Cipher.HybridEncrypt()', () => {

		it( 'encrpyts the given data', () => {
			
			expect( () => Cipher.HybridEncrypt( dataToEncrypt, keypair.publicKey ) )
				.not.toThrow()
				
		} )


		it( 'returns encrypted key length', () => {

			const encrypted = Cipher.HybridEncrypt( dataToEncrypt, keypair.publicKey )
			
			expect( readUint16BE( encrypted.subarray( 0, 2 ) ) )
				.toBe( 256 )

		} )
		
		
		it( 'embed encrypted key in payload', () => {

			const encrypted		= Cipher.HybridEncrypt( dataToEncrypt, keypair.publicKey )
			const keyLength		= readUint16BE( encrypted.subarray( 0, 2 ) )
			const encryptedKey	= encrypted.subarray( 2, 2 + keyLength )

			expect( encryptedKey.toString() )
				.not.toBe( keypair.publicKey )

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
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase: password, cipher: 'aes-256-cbc' },
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