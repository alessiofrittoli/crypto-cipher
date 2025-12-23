import { bufferEquals } from '@alessiofrittoli/crypto-buffer'
import { Cipher } from '@/index'

const dataToEncrypt	= 'my TOP-SECRET message'
const secret		= 'verystrong-password'

describe( 'Cipher.Encrypt()', () => {

	it( 'encrypts data', () => {
		expect( Cipher.Encrypt( dataToEncrypt, secret ).length )
			.toBe( 117 )
	} )
	

	Cipher.ALGORITHMS.map( algorithm => {
		it( `encrypts data with '${ algorithm }' algorithm`, () => {
			expect( Cipher.Encrypt( dataToEncrypt, secret, { algorithm } ) )
				.toBeInstanceOf( Buffer )
		} )
	} )


	it( 'encrypts data with custom salt length', () => {
		expect( Cipher.Encrypt( dataToEncrypt, secret, { salt: 64 } ).length )
			.toBe( 149 )
	} )


	it( 'encrypts data with custom IV length', () => {
		expect( Cipher.Encrypt( dataToEncrypt, secret, { iv: 32 } ).length )
			.toBe( 133 )
	} )
	
	
	it( 'encrypts data with custom auth tag length', () => {
		expect( Cipher.Encrypt( dataToEncrypt, secret, { authTag: 4 } ).length )
			.toBe( 105 )
	} )


	it( 'encrypts data with custom Additional Authenticated Data', () => {
		expect( Cipher.Encrypt( dataToEncrypt, secret, { aad: Buffer.from( 'additional-password' ) } ).length )
			.toBe( 104 )
	} )


	it( 'encrypts data with custom Additional Authenticated Data length', () => {
		expect( Cipher.Encrypt( dataToEncrypt, secret, { aadLength: 64 } ).length )
			.toBe( 149 )
	} )


	it( 'always produce a unique result', () => {
		const encrypted1 = Cipher.Encrypt( dataToEncrypt, secret )
		const encrypted2 = Cipher.Encrypt( dataToEncrypt, secret )
		
		expect( bufferEquals( encrypted1, encrypted2 ) )
			.toBe( false )
	} )

} )


describe( 'Cipher.Decrypt()', () => {

	it( 'decrypts data', () => {
		const encrypted = Cipher.Encrypt( dataToEncrypt, secret )
		expect( Cipher.Decrypt( encrypted, secret ).toString() )
			.toBe( dataToEncrypt )
	} )


	Cipher.ALGORITHMS.map( algorithm => {
		it( `decrypts data with '${ algorithm }' algorithm`, () => {
			const encrypted = Cipher.Encrypt( dataToEncrypt, secret, { algorithm } )
			expect( Cipher.Decrypt( encrypted, secret, { algorithm } ).toString() )
				.toBe( dataToEncrypt )
		} )
	} )


	it( 'decrypts data with custom Additional Authenticated Data', () => {
		const encrypted = Cipher.Encrypt( dataToEncrypt, secret, { aad: Buffer.from( 'additional-password' ) } )
		expect( Cipher.Decrypt( encrypted, secret, { aad: Buffer.from( 'additional-password' ) } ).toString() )
			.toBe( dataToEncrypt )
	} )

} )