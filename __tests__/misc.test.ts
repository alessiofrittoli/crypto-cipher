import { Readable, Writable } from 'stream'
import type { CoerceToUint8ArrayInput } from '@alessiofrittoli/crypto-buffer'
import { Cipher } from '@/index'

const dataToEncrypt	= 'my TOP-SECRET message'
const password		= 'verystrong-password'


const encryptMockData = ( secret: CoerceToUint8ArrayInput, data: CoerceToUint8ArrayInput ) => {
	const encryptedChunks: Buffer[] = []

	// Create a `Readable` Stream with raw data.
	const input = new Readable( {
		read()
		{
			this.push( data ) // Push data to encrypt
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

	const { encrypt } = Cipher.streamEncrypt( secret, { input, output } )

	return (
		encrypt()
			.then( () => Buffer.concat( encryptedChunks ) )
	)

}

describe( 'Cipher.resolveOptions()', () => {

	it( 'return resolved default options', () => {
		const options = Cipher.resolveOptions()
		expect( options.algorithm ).toBe( Cipher.DEFAULT_ALGORITHM.buffer )
		expect( options.salt ).toBe( Cipher.SALT_LENGTH.default )
		expect( options.iv ).toBe( Cipher.IV_LENGTH.default )
		expect( options.authTag ).toBe( Cipher.AUTH_TAG_LENGTH.default )
		expect( options.aadLength ).toBe( Cipher.AAD_LENGTH.default )
	} )

} )


describe( 'Cipher.newKeyIV()', () => {

	it( 'generates a new Key and IV with default options', () => {
		const { options, Key, IV, AAD, salt } = Cipher.newKeyIV( password )
		expect( options.algorithm ).toBe( Cipher.DEFAULT_ALGORITHM.buffer )
		expect( options.salt ).toBe( Cipher.SALT_LENGTH.default )
		expect( options.iv ).toBe( Cipher.IV_LENGTH.default )
		expect( options.authTag ).toBe( Cipher.AUTH_TAG_LENGTH.default )
		expect( options.aadLength ).toBe( Cipher.AAD_LENGTH.default )
		expect( Key ).toBeInstanceOf( Buffer )
		expect( IV ).toBeInstanceOf( Buffer )
		expect( AAD ).toBeInstanceOf( Buffer )
		expect( salt ).toBeInstanceOf( Buffer )
	} )

} )


describe( 'Cipher.getIVLength()', () => {

	it( 'returns the Initialization Vector length using default options', () => {
		expect( Cipher[ 'getIVLength' ]() )
			.toBe( 16 )
	} )

} )


describe( 'Cipher.streamDecrypt()', () => {

	/**
	 * Mixed chunk content check is skipped when the `Readable` pushes chunks with a chunk length that
	 * is a multiple of the encrypted KeyIV length.
	 * 
	 * e.g. With a `Readable.highWaterMark` of 56 bytes and an encrypted KeyIV length of 112 bytes
	 * the extraction get completed when the second chunk is received.
	 * That means that subsequent chunks are the actual encrypted data, directly piped to the next decryption destination.
	 * 
	 * Mixed content chunks are handled when `Readable.highWaterMark` is not a multiple of the encrypted KeyIV length.
	 * This ensures a proper key extraction without losing encrypted data bytes.
	 * 
	 * e.g. With a `Readable.highWaterMark` of 64 bytes and an encrypted KeyIV length of 112 bytes
	 * the second chunk received contains mixed content:
	 * 48 bytes of KeyIV and 16 bytes of the actual encrypted data (not part of the KeyIV).
	 */
	it( 'handles correctly mixed chunk content', async () => {
		
		const encrypted = await encryptMockData( password, dataToEncrypt )
		// encrypted key length with the given `password` is `112` bytes
		const keyLength = 112

		// Create a `Readable` Stream that pushes encrypted data with a chunk length multiple of `keyLength`.
		const input = new Readable( {
			read()
			{
				let originalBuff = encrypted
				this.push( originalBuff.subarray( 0, keyLength / 2 ) )
				originalBuff = originalBuff.subarray( keyLength / 2 )
				this.push( originalBuff.subarray( 0, keyLength / 2 ) )
				originalBuff = originalBuff.subarray( keyLength / 2 )
				this.push( originalBuff )
				this.push( null )
			},
		} )

		const chunks: Buffer[] = []
		
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


		// Create a `Readable` Stream that pushes encrypted data with a chunk length not multiple of `keyLength`.
		const input2 = new Readable( {
			read()
			{
				let originalBuff = encrypted
				this.push( originalBuff.subarray( 0, ( keyLength / 2 ) + 8 ) )
				originalBuff = originalBuff.subarray( ( keyLength / 2 ) + 8 )
				this.push( originalBuff.subarray( 0, ( keyLength / 2 ) + 8 ) )
				originalBuff = originalBuff.subarray( ( keyLength / 2 ) + 8 )
				this.push( originalBuff )
				this.push( null )
			},
		} )

		const chunks2: Buffer[] = []
		const output2 = new Writable( {
			write( chunk, encoding, callback )
			{
				chunks2.push( chunk )
				callback()
			},
		} )

		const { decrypt: decrypt2 } = await Cipher.streamDecrypt(
			password, { input: input2, output: output2 }
		)
		
		await decrypt2()
	
		const decrypted2 = Buffer.concat( chunks2 )

		expect( decrypted2.toString() )
			.toBe( dataToEncrypt )

	} )


	it( 'throws an Error when encrypted KeyIV extraction fails', async () => {
		
		// Create a `Readable` Stream with encrypted data.
		const input = new Readable( {
			read()
			{
				// end stream without pushing data
				this.push( null )
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

		expect( () => Cipher.streamDecrypt( password, { input, output } ) )
			.rejects.toThrow( 'The extracted KeyIV length is less than the expected length' )

	} )


	it( 'throws an error when input stream `error` event is emitted', async () => {
		
		const encrypted = await encryptMockData( password, dataToEncrypt )

		// Create a `Readable` Stream with encrypted data.
		const input = new Readable( {
			read()
			{
				this.push( encrypted )
				throw new Error( 'Test input error.' )
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

		expect( () => Cipher.streamDecrypt( password, { input, output } ) )
			.rejects.toThrow( 'Test input error.' )

	} )
	
	
	it( 'throws an error when trying to decrypt data with a wrong key', async () => {
		
		const encrypted = await encryptMockData( password, dataToEncrypt )

		// Create a `Readable` Stream with encrypted data.
		const input = new Readable( {
			read()
			{
				this.push( encrypted )
				this.push( null )
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

		expect( () => Cipher.streamDecrypt( 'wrong-password', { input, output } ) )
			.rejects.toThrow( 'error:1C800064:Provider routines::bad decrypt' )

	} )

	
	it( 'throws an error when trying to decrypt corrupted data', async () => {
		
		const encrypted = await encryptMockData( password, dataToEncrypt )

		// Create a `Readable` Stream with encrypted data.
		const input = new Readable( {
			read()
			{
				let originalBuff = encrypted				
				this.push( originalBuff.subarray( 0, 120 ) )
				originalBuff = originalBuff.subarray( 120 )
				this.push( Buffer.from( 'corrupt this data' ) )
				this.push( originalBuff )
				this.push( null )
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

		const { decrypt } = await Cipher.streamDecrypt( password, { input, output } )

		expect( () => decrypt() )
			.rejects.toThrow( 'error:1C80006B:Provider routines::wrong final block length' )

	} )


	it( 'throws an error when the extracted KeyIV length is less than the expected length', async () => {
		
		const encrypted = await encryptMockData( password, dataToEncrypt )

		const input = new Readable( {
			read()
			{
				this.push( encrypted.subarray( 32 ) )
				this.push( null )
			},
		} )

		const chunks: Buffer[] = []
		
		const output = new Writable( {
			write( chunk, encoding, callback )
			{
				chunks.push( chunk )
				callback()
			},
		} )

		expect( () => Cipher.streamDecrypt( password, { input, output } ) )
			.rejects.toThrow( 'The extracted KeyIV length is less than the expected length.' )
		expect( () => Cipher.hybridDecrypt( password, { input, output, rsaKeyLength: 256 } ) )
			.rejects.toThrow( 'The extracted KeyIV length is less than the expected length.' )


	} )

} )