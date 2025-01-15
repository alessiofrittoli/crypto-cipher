import { bufferEquals } from '@alessiofrittoli/crypto-buffer'
import { Cipher } from '@/index'

const dataToEncrypt	= 'my TOP-SECRET message'
const password		= 'verystrong-password'

describe( 'Cipher.encrypt()', () => {

	it( 'encrypts data', () => {
		expect( Cipher.encrypt( dataToEncrypt, password ).length )
			.toBe( 117 )
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
		expect( Cipher.encrypt( dataToEncrypt, password, { authTag: 4 } ).length )
			.toBe( 105 )
	} )


	it( 'encrypts data with custom Additional Authenticated Data', () => {
		expect( Cipher.encrypt( dataToEncrypt, password, { aad: Buffer.from( 'additional-password' ) } ).length )
			.toBe( 104 )
	} )


	it( 'encrypts data with custom Additional Authenticated Data length', () => {
		expect( Cipher.encrypt( dataToEncrypt, password, { aadLength: 64 } ).length )
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


	it( 'decrypts data with custom Additional Authenticated Data', () => {
		const encrypted = Cipher.encrypt( dataToEncrypt, password, { aad: Buffer.from( 'additional-password' ) } )
		expect( Cipher.decrypt( encrypted, password, { aad: Buffer.from( 'additional-password' ) } ).toString() )
			.toBe( dataToEncrypt )
	} )

} )