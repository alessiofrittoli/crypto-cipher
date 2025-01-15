import { bufferEquals } from '@alessiofrittoli/crypto-buffer/common'
import { Cipher } from '@/index'

describe( 'Cipher - In-Memory Buffer Symmetric Encryption/Decryption', () => {
	
	const dataToEncrypt	= 'my TOP-SECRET message'
	const password		= 'verystrong-password'
	
	describe( 'Cipher.encrypt()', () => {
	
		it( 'encrypts data', () => {
			expect( Cipher.encrypt( dataToEncrypt, password ) )
				.toBeInstanceOf( Buffer )
		} )
		
	
		Cipher.ALGORITHMS.map( algorithm => {
			it( `encrypts data with '${ algorithm }' algorithm`, () => {
				expect( Cipher.encrypt( dataToEncrypt, password, { algorithm } ) )
					.toBeInstanceOf( Buffer )
			} )
		} )
	
	
		it( 'encrypts data with custom salt length', () => {
			expect( Cipher.encrypt( dataToEncrypt, password, { salt: 64 } ).length )
				.toBe( 149 )
		} )
	
	
		it( 'encrypts data with custom IV length', () => {
			expect( Cipher.encrypt( dataToEncrypt, password, { iv: 32 } ).length )
				.toBe( 133 )
		} )
		
		
		it( 'encrypts data with custom auth tag length', () => {
			expect( Cipher.encrypt( dataToEncrypt, password, { authTag: 16 } ).length )
				.toBe( 117 )
		} )
	
	
		it( 'encrypts data with custom Additional Authenticated Data length', () => {
			expect( Cipher.encrypt( dataToEncrypt, password, { aad: 64 } ).length )
				.toBe( 149 )
		} )
	
	
		it( 'always produce a unique result', () => {
			const encrypted1 = Cipher.encrypt( dataToEncrypt, password )
			const encrypted2 = Cipher.encrypt( dataToEncrypt, password )
			
			expect( bufferEquals( encrypted1, encrypted2 ) )
				.toBe( false )
		} )
	
	} )
	
	
	describe( 'Cipher.decrypt()', () => {
	
		it( 'decrypts data', () => {
			const encrypted = Cipher.encrypt( dataToEncrypt, password )
			expect( Cipher.decrypt( encrypted, password ).toString() )
				.toBe( dataToEncrypt )
		} )
	
	
		Cipher.ALGORITHMS.map( algorithm => {
			it( `decrypts data with '${ algorithm }' algorithm`, () => {
				const encrypted = Cipher.encrypt( dataToEncrypt, password, { algorithm } )
				expect( Cipher.decrypt( encrypted, password, { algorithm } ).toString() )
					.toBe( dataToEncrypt )
			} )
		} )
	
	} )

} )