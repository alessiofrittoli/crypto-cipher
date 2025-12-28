import { Cipher } from '@/index'


describe( 'Cipher.GetIVLength()', () => {

	it( 'initialises with undefined options', async () => {

		expect( Cipher.GetIVLength() ).toBe( 16 )

	} )

} )


describe( 'Cipher.ResolveOptions()', () => {

	it( 'initialises with undefined options', () => {

		const options = Cipher[ 'ResolveOptions' ]()

		expect( options.salt ).toBe( Cipher.SALT_LENGTH.default )
		expect( options.authTag ).toBe( Cipher.AUTH_TAG_LENGTH.default )
		expect( options.aadLength ).toBe( Cipher.AAD_LENGTH.default )
		expect( options.algorithm ).toBe( Cipher.DEFAULT_ALGORITHM.buffer )
		expect( options.length ).toBe( 32 ) // value based on algorithm
		expect( options.iv ).toBe( 16 ) // value based on algorithm

	} )

} )


describe( 'Cipher.NewKeyIV()', () => {

	it( 'initialises with undefined options', () => {

		const { options, Key, IV, AAD, salt } = Cipher.NewKeyIV()

		expect( Key ).toBeInstanceOf( Buffer )
		expect( Key.length ).toBe( 32 ) // value based on algorithm
		expect( IV ).toBeInstanceOf( Buffer )
		expect( IV.length ).toBe( 16 ) // value based on algorithm
		expect( AAD ).toBeInstanceOf( Buffer )
		expect( AAD.length ).toBe( options.aadLength )
		expect( salt ).toBeInstanceOf( Buffer )
		expect( salt.length ).toBe( options.salt )

	} )

} )