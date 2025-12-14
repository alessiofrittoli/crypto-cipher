import crypto from 'crypto'
import { Transform } from 'stream'
import type { Readable, Writable } from 'stream'
import { writeUint16BE, readUint16BE } from '@alessiofrittoli/crypto-buffer/conversion'
import { coerceToUint8Array, type CoerceToUint8ArrayInput } from '@alessiofrittoli/crypto-buffer/coercion'

import type { Cph } from './types'



/**
 * INTERNAL USE ONLY
 */
interface StreamEncryptOptions
{
	cipher		: crypto.Cipheriv
	encryptedKey: Buffer
	input		: Readable
	output		: Writable
}


/**
 * INTERNAL USE ONLY
 */
interface StreamDecryptOptions
{
	decipher	: crypto.Decipheriv
	input		: Readable
	output		: Writable
}


/**
 * Utility class for AES encryption and decryption following [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) standard reccomendations.
 */
export class Cipher
{
	/**
	 * Cipher default `salt` lengths.
	 */
	static readonly SALT_LENGTH = {
		min		: 16,
		max		: 64,
		default	: 32,
	} as const


	/**
	 * Cipher default `IV` lengths.
	 */
	static readonly IV_LENGTH = {
		min		: 8,
		max		: 32,
		default	: 16,
	} as const


	/**
	 * Cipher default `Auth Tag` lengths.
	 */
	static readonly AUTH_TAG_LENGTH = {
		min		: 4,
		max		: 16,
		default	: 16,
	} as const
	
	
	/**
	 * Cipher default `Additional Authenticated Data` lengths.
	 */
	static readonly AAD_LENGTH = {
		min		: 16,
		max		: 128,
		default	: 32,
	} as const
	

	/**
	 * Default AES algorithms used based on functionality.
	 */
	static readonly DEFAULT_ALGORITHM = {
		buffer: 'aes-256-gcm',
		stream: 'aes-256-cbc',
	} as const


	/**
	 * Supported AES algorithms.
	 */
	static readonly ALGORITHMS: Cph.AesAlgorithm[] = [
		'aes-128-cbc', 'aes-128-ccm', 'aes-128-gcm', 'aes-128-ocb',
		'aes-192-cbc', 'aes-192-ccm', 'aes-192-gcm', 'aes-192-ocb',
		'aes-256-cbc', 'aes-256-ccm', 'aes-256-gcm', 'aes-256-ocb',
		'chacha20-poly1305'
	] as const


	/**
	 * Encrypt in-memory data buffer.
	 *
	 * ⚠️ This is not suitable for large data. Use {@link Cipher.streamEncrypt()} or {@link Cipher.hybridStreamEncrypt()} methods for large data encryption.
	 *
	 * @param	data	The data to encrypt.
	 * @param	secret	The secret key used to encrypt the `data`.
	 * @param	options	( Optional ) Additional options.
	 * @returns	The encrypted result Buffer.
	 */
	static encrypt(
		data	: CoerceToUint8ArrayInput,
		secret	: CoerceToUint8ArrayInput,
		options	: Cph.Options = {},
	): Buffer
	{
		const _data = coerceToUint8Array( data )

		const {
			salt, Key, IV, AAD,
			options: { algorithm, authTag: authTagLength },
		} = Cipher.newKeyIV( secret, options )

		if ( Cipher.isCBC( algorithm ) ) {
			const cipher	= crypto.createCipheriv( algorithm, Key, IV )
			const encrypted	= Buffer.concat( [ cipher.update( _data ), cipher.final() ] )

			return Buffer.concat( [ salt, IV, encrypted ] )
		}


		const cipher = (
			crypto.createCipheriv(
				// @ts-expect-error `crypto.createCipheriv` cannot infer the correct overload based on the given union type algorithm.
				algorithm, Key, IV, { authTagLength }
			)
		)
		
		
		if ( Cipher.isCCM( algorithm ) ) {
			// AES-CCM requires `plaintextLength`
			cipher.setAAD( AAD, { plaintextLength: _data.length } )
		}

		if ( Cipher.isGCM( algorithm ) || Cipher.isOCB( algorithm ) ) {
			// AES-GCM and AES-OCB doesn't require `plaintextLength`
			cipher.setAAD( AAD )
		}

		const encrypted	= Buffer.concat( [ cipher.update( _data ), cipher.final() ] )
		const authTag	= cipher.getAuthTag()

		return Buffer.concat( [ salt, IV, AAD, authTag, encrypted ] )
	}


	/**
	 * Decrypt in-memory data buffer.
	 *
	 * ⚠️ This is not suitable for large data. Use {@link Cipher.streamDecrypt()} or {@link Cipher.hybridStreamDecrypt()} methods for large data decryption.
	 *
	 * @param	data	The data to decrypt.
	 * @param	secret	The secret key used to decrypt the `data`.
	 * @param	options	( Optional ) Additional options. Must be the same used while encrypting data.
	 * @returns	The decrypted data Buffer.
	 */
	static decrypt(
		data	: CoerceToUint8ArrayInput,
		secret	: CoerceToUint8ArrayInput,
		options	: Cph.Options = {},
	): Buffer
	{
		let _data			= coerceToUint8Array( data )
		const _secret		= coerceToUint8Array( secret )
		const _options		= Cipher.resolveOptions( options )
		const { algorithm }	= _options

		const salt		= _data.subarray( 0, _options.salt )
		_data			= _data.subarray( _options.salt )
		const IV		= _data.subarray( 0, _options.iv )
		_data			= _data.subarray( _options.iv )
		const Key		= crypto.scryptSync( _secret, salt, _options.length )

		if ( Cipher.isCBC( algorithm ) ) {
			const decipher = (
				crypto.createDecipheriv( _options.algorithm, Key, IV )
			)

			return (
				Buffer.concat( [ decipher.update( _data ), decipher.final() ] )
			)
		}

		const AADLength		= _options.aadLength
		const authTagLength	= _options.authTag
		const AAD			= _data.subarray( 0, AADLength )
		_data				= _data.subarray( AADLength )
		const authTag		= _data.subarray( 0, authTagLength )
		_data				= _data.subarray( authTagLength )


		const decipher = (
			crypto.createDecipheriv(
				// @ts-expect-error `crypto.createDecipheriv` cannot infer the correct overload based on the given union type algorithm.
				algorithm, Key, IV, { authTagLength }
			)
		)

		if ( Cipher.isCCM( algorithm ) ) {
			// AES-CCM requires `plaintextLength`
			decipher.setAAD( AAD, { plaintextLength: _data.length } )
		}

		if ( Cipher.isGCM( algorithm ) || Cipher.isOCB( algorithm ) ) {
			// AES-GCM and AES-OCB doesn't require `plaintextLength`
			decipher.setAAD( AAD )
		}

		decipher.setAuthTag( authTag )
	
		return (
			Buffer.concat( [ decipher.update( _data ), decipher.final() ] )
		)

	}


	/**
	 * Encrypt a `Readable` to a `Writable` Stream.
	 * 
	 * The `Readable` Stream could be 'in-memory buffer' or 'file' based.
	 * 
	 * @param	secret	The secret key used to encrypt the `data`.
	 * @param	options Additional options.
	 * @returns An object containing:
	 * 	- a new instance of `crypto.Cipheriv` allowing you to add listeners to the `cipher` encryption process.
	 * 	- the actual `encrypt` callback that must be called and awaited in order to start the encryption process.
	 */
	static streamEncrypt(
		secret	: CoerceToUint8ArrayInput,
		options	: Cph.Stream.Symmetric.EncryptOptions,
	): Cph.Stream.Symmetric.EncryptReturnType
	{
		options.algorithm ||= Cipher.DEFAULT_ALGORITHM.stream

		const {
			Key, IV, options: { input, output, algorithm, salt, iv, authTag },
		} = Cipher.newKeyIV<Cph.Stream.Symmetric.EncryptResolvedOptions>( secret, options )

		const encryptedKey = (
			Cipher.encrypt( Buffer.concat( [ Key, IV ] ), secret, { algorithm, salt, iv, authTag } )
		)

		const cipher = crypto.createCipheriv( algorithm, Key, IV )
		const encrypt = () => (
			Cipher.stream( {
				cipher, input, output, encryptedKey
			} )
		)

		return { cipher, encrypt }
	}


	/**
	 * Decrypt a `Readable` to a `Writable` Stream.
	 * 
	 * The `Readable` Stream could be 'in-memory buffer' or 'file' based.
	 * 
	 * @param	secret	The secret key used to encrypt the `data`.
	 * @param	options Additional options.
	 * @returns A new Promise that resolves when Key IV extraction completes returning an object containing:
	 * 	- a new instance of `crypto.Decipheriv` allowing you to add listeners to the `decipher` decryption process.
	 * 	- the actual `decrypt` callback that must be called and awaited in order to start the decryption process.
	 */
	static streamDecrypt(
		secret	: CoerceToUint8ArrayInput,
		options	: Cph.Stream.Symmetric.DecryptOptions,
	): Promise<Cph.Stream.Symmetric.DecryptReturnType>
	{
		options.algorithm ||= Cipher.DEFAULT_ALGORITHM.stream

		const {
			input, output, algorithm, salt, iv, authTag, length
		} = Cipher.resolveOptions<Cph.Stream.Symmetric.DecryptResolvedOptions>( options )

		const keyIvLength = (
			length + iv
			+ salt + iv + authTag
		)

		return (
			Cipher.ExtractKeyIVFromStream( input, keyIvLength )
				.then( ( [ encryptedKeyIV, input ] ) => {
					/**
					 * Check if input has error and re-throw if so.
					 * This is required since `.on( 'error' )` listeners attached in
					 * `Cipher.decipherStream()` get attached too late (error event already emitted).
					 */
					if ( input.errored ) throw input.errored
					
					const KeyIV = (
						Cipher.decrypt( encryptedKeyIV, secret, { algorithm, salt, iv, authTag } )
					)

					const Key		= KeyIV.subarray( 0, length )
					const IV		= KeyIV.subarray( length )
					const decipher	= crypto.createDecipheriv( algorithm, Key, IV )
	
					const decrypt = () => (
						Cipher.decipherStream(
							{ decipher, input, output }
						)
					)
			
					return { decipher, decrypt }
				} )
		)
	}


	/**
	 * Encrypt data using hybrid encryption.
	 * 
	 * @param	data		The data to encrypt.
	 * @param	publicKey	The public key.
	 * @param	options		( Optional ) Additional options.
	 * 
	 * @returns	The encrypted result Buffer.
	 */
	static hybridEncrypt(
		data		: CoerceToUint8ArrayInput,
		publicKey	: crypto.KeyLike,
		options?	: Cph.Options,
	)
	{

		const Key = crypto.randomBytes( 32 )

		const encryptedKey = (
			crypto.publicEncrypt( {
				key			: publicKey,
				padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash	: 'sha256',
			}, Key )
		)

		return Buffer.concat( [
			writeUint16BE( encryptedKey.length ),
			encryptedKey,
			Cipher.encrypt( data, Key, options )
		] )

	}
	
	
	/**
	 * Decrypt data using hybrid decryption.
	 * 
	 * @param	data		The encrypted data to decrypt.
	 * @param	privateKey	The private key.
	 * @param	options		( Optional ) Additional options.
	 * 
	 * @returns	The encrypted result Buffer.
	 */
	static hybridDecrypt(
		data		: CoerceToUint8ArrayInput,
		privateKey	: crypto.KeyLike | { key: crypto.KeyLike, passphrase?: string },
		options?	: Cph.Options,
	)
	{

		const dataBuff			= Buffer.from( coerceToUint8Array( data ) )
		const rsaKeyLength		= readUint16BE( dataBuff.subarray( 0, 2 ) )
		const encryptedKey		= dataBuff.subarray( 2, 2 + rsaKeyLength )
		const encryptedData		= dataBuff.subarray( 2 + rsaKeyLength )
		const rsaPrivateKey		= (
			typeof privateKey === 'object' && 'key' in privateKey ? privateKey.key : privateKey
		)
		const passphrase		= (
			typeof privateKey === 'object' && 'passphrase' in privateKey ? privateKey.passphrase : undefined
		)

		const decryptedKey = (
			crypto.privateDecrypt( {
				key			: rsaPrivateKey,
				passphrase	: passphrase,
				padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash	: 'sha256',
			}, encryptedKey )
		)

		return Cipher.decrypt( encryptedData, decryptedKey, options )
		
	}


	/**
	 * Encrypt a `Readable` to a `Writable` Stream with hybird Encryption.
	 *
	 * The `Readable` Stream could be 'in-memory buffer' or 'file' based.
	 *
	 * @param	secret		The secret key used to encrypt the stream.
	 * @param	publicKey	The RSA public key used to encrypt the symmetric key.
	 * @param	options		Options for the stream encryption.
	 * @returns An object containing:
	 * 	- a new instance of `crypto.Cipheriv` allowing you to add listeners to the `cipher` encryption process.
	 * 	- the actual `encrypt` callback that must be called and awaited in order to start the encryption process.
	 */
	static hybridStreamEncrypt(
		secret		: CoerceToUint8ArrayInput,
		publicKey	: crypto.RsaPublicKey | crypto.RsaPrivateKey | crypto.KeyLike,
		options		: Cph.Stream.Hybrid.EncryptOptions,
	): Cph.Stream.Hybrid.EncryptReturnType
	{
		options.algorithm ||= Cipher.DEFAULT_ALGORITHM.stream

		const {
			Key, IV,
			options: { algorithm, input, output },
		} = Cipher.newKeyIV<Cph.Stream.Hybrid.EncryptResolvedOptions>( secret, options )

		const encryptedKey = (
			crypto.publicEncrypt( publicKey, Buffer.concat( [ Key, IV ] ) )
		)

		const cipher = crypto.createCipheriv( algorithm, Key, IV )
		const encrypt = () => (
			Cipher.stream( {
				cipher, input, output, encryptedKey
			} )
		)

		return { cipher, encrypt }
	}


	/**
	 * Decrypt a `Readable` to a `Writable` Stream with hybrid Decryption.
	 * 
	 * The `Readable` Stream could be 'in-memory buffer' or 'file' based.
	 *
	 * @param	privateKey	The RSA private key used to decrypt the symmetric key.
	 * @param	options		Options for the stream decryption.
	 * @returns A new Promise that resolves when Key IV extraction completes returning an object containing:
	 * 	- a new instance of `crypto.Decipheriv` allowing you to add listeners to the `decipher` decryption process.
	 * 	- the actual `decrypt` callback that must be called and awaited in order to start the decryption process.
	 */
	static hybridStreamDecrypt(
		privateKey	: crypto.RsaPrivateKey | crypto.KeyLike,
		options		: Cph.Stream.Hybrid.DecryptOptions,
	): Promise<Cph.Stream.Hybrid.DecryptReturnType>
	{
		options.algorithm ||= Cipher.DEFAULT_ALGORITHM.stream

		const {
			input, output, algorithm, length, rsaKeyLength
		} = Cipher.resolveOptions<Cph.Stream.Hybrid.DecryptResolvedOptions>( options )

		return (
			Cipher.ExtractKeyIVFromStream( input, rsaKeyLength )
				.then( ( [ encryptedKeyIV, input ] ) => {
					const KeyIV		= crypto.privateDecrypt( privateKey, encryptedKeyIV )
					const Key		= KeyIV.subarray( 0, length )
					const IV		= KeyIV.subarray( length )
					const decipher	= crypto.createDecipheriv( algorithm, Key, IV )
	
					const decrypt = () => (
						Cipher.decipherStream(
							{ decipher, input, output }
						)
					)
			
					return { decipher, decrypt }
				} )
		)
	}


	/**
	 * Handle pipe flow to encrypt a Stream.
	 * 
	 * @param	options Required parameters.
	 * @returns A new Promise that resolves `void` once stream is completed.
	 */
	private static stream( options: StreamEncryptOptions )
	{
		const {
			cipher, encryptedKey, input, output
		} = options

		return (
			new Promise<void>( ( resolve, reject ) => {
				cipher.on( 'error', reject )
				input.on( 'error', reject )
				output.on( 'error', reject )
				output.on( 'finish', resolve )
		
				// output.write( writeUint16BE( encryptedKey.length ) )
				output.write( encryptedKey )
				input.pipe( cipher ).pipe( output )
			} )
		)
	}


	/**
	 * Handle pipe flow to decrypt a Stream.
	 * 
	 * @param	options Required parameters.
	 * @returns A new Promise that resolves `void` once stream is completed.
	 */
	private static decipherStream( options: StreamDecryptOptions )
	{
		const {
			decipher, input, output,
		} = options

		return (
			new Promise<void>( ( resolve, reject ) => {
				decipher.on( 'error', reject )
				input.on( 'error', reject )
				output.on( 'error', reject )
				output.on( 'finish', resolve )

				input.pipe( decipher ).pipe( output )
			} )
		)
	}


	/**
	 * Extract the Cipher Encrypted Symmetric Key and Initialization Vector from an encrypted `Readable` Stream.
	 *
	 * @param	input		The `Readable` Stream.
	 * @param	keyLength	The encrypted key length in bytes. This is used to properly extract the encrypted Cipher Key and Initialization Vector.
	 * @returns	A new Promise that resolve a tuple containing the Cipher Encrypted Symmetric Key and Initialization Vector once fulfilled.
	 */
	private static ExtractKeyIVFromStream(
		input		: Readable,
		keyLength	: number,
	)
	{
		return (
			new Promise<[ KeyIV: Buffer, input: Transform ]>( ( resolve, reject ) => {
				let KeyIV		= Buffer.alloc( 0 )
				let bytesRead	= 0
				let resolved	= false

				const transform = new Transform( {
					async transform( chunk: Buffer, encoding, callback )
					{

						if ( KeyIV.length < keyLength ) {
							KeyIV = Buffer.concat( [ KeyIV, chunk ] )
						}

						bytesRead += chunk.length

						/**
						 * `KeyIV` length may exceed the `keyLength`.
						 * This may occurs when the received chunk length is not a multiple of the `keyLength`.
						 *
						 * In that case the chunk will contain mixed content:
						 * - end of the `KeyIV`.
						 * - begin of the actual encrypted data.
						 *
						 * For a proper data handling we need to:
						 * - cut off the `KeyIV` to `keyLength` bytes.
						 * - recover and push the byte loss to the next piped destination.
						 */
						if ( KeyIV.length > keyLength ) {
							const bytesLoss	= Math.max( 0, KeyIV.length - keyLength )
							KeyIV			= KeyIV.subarray( 0, keyLength )
							const subchunk	= chunk.subarray( bytesLoss * -1 )

							if ( ! resolved ) {
								resolve( [ KeyIV, this ] )
								resolved = true
							}

							/**
							 * Push to the next piped destination.
							 */							
							this.push( subchunk, encoding )

							return callback()
						}


						/**
						 * `KeyIV` has been read.
						 * The Received chunk can now be pushed to the next piped destination.
						 */
						if ( bytesRead > keyLength ) {
							if ( ! resolved ) {
								resolve( [ KeyIV, this ] )
								resolved = true
							}
							/**
							 * Push to the next piped destination.
							 */
							this.push( chunk, encoding )
						}

						return callback()
					},
					final( callback )
					{
						if ( KeyIV.length < keyLength ) {
							return callback(
								new Error( 'The extracted KeyIV length is less than the expected length.' )
							)
						}
						return callback()
					},
				} )

				transform.on( 'error', reject )
				input.on( 'error', error => {
					transform.destroy( error )
					reject( error )
				} )
				input.pipe( transform )
			} )
		)
	}


	/**
	 * Generates a `Scrypt` Symmetric Key and the Initialization Vector with the given options.
	 * 
	 * @param	secret	The secret key.
	 * @param	options	( Optional ) Additional options.
	 * 
	 * @returns An object with the generated `Key`, `IV`, `salt` and resolved `options`. 
	 */
	static newKeyIV<T extends Cph.ResolvedOptions = Cph.ResolvedOptions>(
		secret	: CoerceToUint8ArrayInput,
		options	: Cph.Options = {},
	)
	{
		const _secret	= coerceToUint8Array( secret )
		const _options	= Cipher.resolveOptions<T>( options )
		const salt		= crypto.randomBytes( _options.salt )
		const Key		= crypto.scryptSync( _secret, salt, _options.length )
		const IV		= crypto.randomBytes( _options.iv )
		const AAD		= _options.aad || crypto.scryptSync( Key, salt, _options.aadLength )

		return { options: _options, Key, IV, AAD, salt }
	}


	/**
	 * Resolves the given `options` with `Cipher` defaults and constraints.
	 * 
	 * @param options ( Optional ) Additional options.
	 * @returns The given `options` with `Cipher` defaults and constraints.
	 */
	static resolveOptions<
		T extends Cph.ResolvedOptions = Cph.ResolvedOptions
	>( options: Cph.Options = {} ): T
	{
		const _options = { ...options } as T

		if ( _options.aad ) {
			_options.aad = coerceToUint8Array( _options.aad )
		}

		_options.salt		||= Cipher.SALT_LENGTH.default
		_options.authTag	||= Cipher.AUTH_TAG_LENGTH.default
		_options.aadLength	= _options.aad?.length || _options.aadLength || Cipher.AAD_LENGTH.default
		_options.salt		= Math.min( Math.max( _options.salt, Cipher.SALT_LENGTH.min ), Cipher.SALT_LENGTH.max )
		_options.authTag	= Math.min( Math.max( _options.authTag, Cipher.AUTH_TAG_LENGTH.min ), Cipher.AUTH_TAG_LENGTH.max )
		if ( ! _options.aad ) {
			_options.aadLength	= Math.min( Math.max( _options.aadLength, Cipher.AAD_LENGTH.min ), Cipher.AAD_LENGTH.max )
		}

		const { keyLength, algorithm } = Cipher.getKeyLength( options.algorithm )

		_options.algorithm	= algorithm
		_options.length		= keyLength
		_options.iv			= Cipher.getIVLength( algorithm, options )

		return _options
	}


	/**
	 * Get the Initialization Vector length based on the given algorithm.
	 * 
	 * @param	algorithm The algorithm in use.
	 * @param	options ( Optional ) Additional options. 
	 * @returns	The Initialization Vector length based on the given algorithm
	 */
	private static getIVLength(
		algorithm	: Cph.Options[ 'algorithm' ] = Cipher.DEFAULT_ALGORITHM.buffer,
		options		: Cph.Options = {},
	)
	{
		switch ( algorithm ) {
			case 'aes-128-ccm':
			case 'aes-128-ocb':
			case 'aes-192-ccm':
			case 'aes-192-ocb':
			case 'aes-256-ccm':
			case 'aes-256-ocb':
				return 8
			case 'chacha20-poly1305':
				return 12
			default:
				return (
					Math.min(
						Math.max(
							options.iv || Cipher.IV_LENGTH.default,
							Cipher.IV_LENGTH.min
						), Cipher.IV_LENGTH.max
					)
				)
		}
	}


	/**
	 * Ensure correct key length based on the given algorithm.
	 *
	 * @param	algorithm The AES algorithm name.
	 * @returns	An object with validated `algorithm` and `keyLength`.
	 */
	private static getKeyLength(
		algorithm: Cph.Options[ 'algorithm' ] = Cipher.DEFAULT_ALGORITHM.buffer
	)
	{
		switch ( algorithm ) {
			case 'chacha20-poly1305':
				return {
					algorithm: algorithm,
					keyLength: 256 / 8,
				} as const
			case 'aes-128-cbc':
			case 'aes-128-ccm':
			case 'aes-128-gcm':
			case 'aes-128-ocb':
				return {
					algorithm: algorithm,
					keyLength: 128 / 8, // AES-128 needs a 128 bit (16 bytes)
				} as const
			case 'aes-192-cbc':
			case 'aes-192-ccm':
			case 'aes-192-gcm':
			case 'aes-192-ocb':
				return {
					algorithm: algorithm,
					keyLength: 192 / 8, // AES-192 needs a 192 bit (24 bytes)
				} as const
			case 'aes-256-cbc':
			case 'aes-256-ccm':
			case 'aes-256-gcm':
			case 'aes-256-ocb':
			default:
				return {
					algorithm: algorithm,
					keyLength: 256 / 8, // AES-256 needs a 256 bit (32 bytes)
				} as const
		}
	}


	/**
	 * Check if the given algorithm is a Cipher AES-GCM algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher AES-GCM algorithm. `false` otherwise.
	 */
	static isGCM( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherGCMTypes
	{
		return (
			algorithm === 'aes-128-gcm' ||
			algorithm === 'aes-192-gcm' ||
			algorithm === 'aes-256-gcm'
		)
	}


	/**
	 * Check if the given algorithm is a Cipher AES-CCM algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher AES-CCM algorithm. `false` otherwise.
	 */
	static isCCM( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherCCMTypes
	{
		return (
			algorithm === 'aes-128-ccm' ||
			algorithm === 'aes-192-ccm' ||
			algorithm === 'aes-256-ccm' ||
			algorithm === 'chacha20-poly1305'
		)
	}


	/**
	 * Check if the given algorithm is a Cipher AES-OCB algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher AES-OCB algorithm. `false` otherwise.
	 */
	static isOCB( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherOCBTypes
	{
		return (
			algorithm === 'aes-128-ocb' ||
			algorithm === 'aes-192-ocb' ||
			algorithm === 'aes-256-ocb'
		)
	}


	/**
	 * Check if the given algorithm is a Cipher AES-CBC algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher AES-CBC algorithm. `false` otherwise.
	 */
	static isCBC( algorithm: Cph.AesAlgorithm ): algorithm is Cph.CBCTypes
	{
		return (
			algorithm === 'aes-128-cbc' ||
			algorithm === 'aes-192-cbc' ||
			algorithm === 'aes-256-cbc'
		)
	}
}