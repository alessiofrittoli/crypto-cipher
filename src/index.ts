import crypto from 'crypto'
import type { Readable } from 'stream'

import { extractBytesFromReadable } from '@alessiofrittoli/stream-reader/utils'
import { clamp } from '@alessiofrittoli/math-utils'
import {
	coerceToUint8Array,
	CoerceToUint8ArrayInput,
	readUint16BE,
	writeUint16BE,
} from '@alessiofrittoli/crypto-buffer'
import type { Cph } from '@/types'


export class Cipher
{
	/**
	 * Cipher default `salt` lengths.
	 * 
	 */
	static readonly SALT_LENGTH = {
		min		: 16,
		max		: 64,
		default	: 32,
	} as const


	/**
	 * Cipher default `IV` lengths.
	 * 
	 */
	static readonly IV_LENGTH = {
		min		: 8,
		max		: 32,
		default	: 16,
	} as const


	/**
	 * Cipher default `Auth Tag` lengths.
	 * 
	 */
	static readonly AUTH_TAG_LENGTH = {
		min		: 4,
		max		: 16,
		default	: 16,
	} as const
	
	
	/**
	 * Cipher default `Additional Authenticated Data` lengths.
	 * 
	 */
	static readonly AAD_LENGTH = {
		min		: 16,
		max		: 128,
		default	: 32,
	} as const
	

	static readonly ALGORITHM = {
		AES_128_CBC: 'aes-128-cbc',
		AES_192_CBC: 'aes-192-cbc',
		AES_256_CBC: 'aes-256-cbc',
		AES_128_CCM: 'aes-128-ccm',
		AES_192_CCM: 'aes-192-ccm',
		AES_256_CCM: 'aes-256-ccm',
		AES_128_GCM: 'aes-128-gcm',
		AES_192_GCM: 'aes-192-gcm',
		AES_256_GCM: 'aes-256-gcm',
		AES_128_OCB: 'aes-128-ocb',
		AES_192_OCB: 'aes-192-ocb',
		AES_256_OCB: 'aes-256-ocb',
		CHACHA_20_POLY: 'chacha20-poly1305',
	} as const


	/**
	 * Default AES algorithms used based on functionality.
	 * 
	 */
	static readonly DEFAULT_ALGORITHM = {
		buffer: Cipher.ALGORITHM.AES_256_GCM,
		stream: Cipher.ALGORITHM.AES_256_CBC,
	} as const


	/**
	 * Supported AES algorithms.
	 * 
	 */
	static readonly ALGORITHMS: Cph.AesAlgorithm[] = Object.values( Cipher.ALGORITHM )
	
	
	/**
	 * Encrypt in-memory data buffer.
	 *
	 * ⚠️ This is not suitable for large data. Use {@link Cipher.StreamEncrypt()} or {@link Cipher.HybridStreamEncrypt()} methods for large data encryption.
	 *
	 * @param	data	The data to encrypt.
	 * @param	secret	The secret key used to encrypt the `data`.
	 * @param	options	( Optional ) Additional options.
	 * @returns	The encrypted result Buffer.
	 */
	static Encrypt(
		data	: CoerceToUint8ArrayInput,
		secret	: CoerceToUint8ArrayInput,
		options	: Cph.Options = {},
	)
	{
		const _data = coerceToUint8Array( data )

		const {
			salt, Key, IV, AAD,
			options: { algorithm, authTag: authTagLength },
		} = Cipher.NewKeyIV( { ...options, secret } )


		if ( Cipher.IsCBC( algorithm ) ) {
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
		
		
		if ( Cipher.IsCCM( algorithm ) || Cipher.IsChacha20Poly( algorithm ) ) {
			// AES-CCM requires `plaintextLength`
			cipher.setAAD( AAD, { plaintextLength: _data.length } )
		}

		if ( Cipher.IsGCM( algorithm ) || Cipher.IsOCB( algorithm ) ) {
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
	 * ⚠️ This is not suitable for large data. Use {@link Cipher.StreamDecrypt()} or {@link Cipher.HybridStreamDecrypt()} methods for large data decryption.
	 *
	 * @param	data	The data to decrypt.
	 * @param	secret	The secret key used to decrypt the `data`.
	 * @param	options	( Optional ) Additional options. Must be the same used while encrypting data.
	 * @returns	The decrypted data Buffer.
	 */
	static Decrypt(
		data	: CoerceToUint8ArrayInput,
		secret	: CoerceToUint8ArrayInput,
		options	: Cph.Options = {},
	)
	{
		let _data			= coerceToUint8Array( data )
		const _options		= Cipher.ResolveOptions( options )
		const _secret		= coerceToUint8Array( secret )
		const { algorithm }	= _options

		const salt		= _data.subarray( 0, _options.salt )
		_data			= _data.subarray( _options.salt )
		const IV		= _data.subarray( 0, _options.iv )
		_data			= _data.subarray( _options.iv )
		const Key		= crypto.scryptSync( _secret, salt, _options.length )

		if ( Cipher.IsCBC( algorithm ) ) {
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

		if ( Cipher.IsCCM( algorithm ) || Cipher.IsChacha20Poly( algorithm ) ) {
			// AES-CCM requires `plaintextLength`
			decipher.setAAD( AAD, { plaintextLength: _data.length } )
		}

		if ( Cipher.IsGCM( algorithm ) || Cipher.IsOCB( algorithm ) ) {
			// AES-GCM and AES-OCB doesn't require `plaintextLength`
			decipher.setAAD( AAD )
		}

		decipher.setAuthTag( authTag )
	
		return (
			Buffer.concat( [ decipher.update( _data ), decipher.final() ] )
		)
	}


	/**
	 * Encrypt in-memory data using hybrid encryption.
	 * 
	 * ⚠️ This is not suitable for large data. Use {@link Cipher.HybridStreamEncrypt()} method for large data encryption.
	 * 
	 * @param	data		The data to encrypt.
	 * @param	publicKey	The public key.
	 * @param	options		( Optional ) Additional options.
	 * 
	 * @returns	The encrypted result Buffer.
	 */
	static HybridEncrypt(
		data		: CoerceToUint8ArrayInput,
		publicKey	: crypto.KeyLike,
		options?	: Cph.Options,
	)
	{

		const Key = crypto.randomBytes( 32 )

		const EncryptedKey = (
			crypto.publicEncrypt( {
				key			: publicKey,
				padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash	: 'sha256',
			}, Key )
		)

		return Buffer.concat( [
			writeUint16BE( EncryptedKey.length ),
			EncryptedKey,
			Cipher.Encrypt( data, Key, options )
		] )

	}
	
	
	/**
	 * Decrypt in-memory data using hybrid decryption.
	 * 
	 * ⚠️ This is not suitable for large data. Use {@link Cipher.stream.HybridDecrypt()} method for large data encryption.
	 * 
	 * @param	data		The encrypted data to decrypt.
	 * @param	privateKey	The private key.
	 * @param	options		( Optional ) Additional options.
	 * 
	 * @returns	The encrypted result Buffer.
	 */
	static HybridDecrypt(
		data		: CoerceToUint8ArrayInput,
		privateKey	: Cph.PrivateKey,
		options?	: Cph.Options,
	)
	{

		const dataBuff			= Buffer.from( coerceToUint8Array( data ) )
		const rsaKeyLength		= readUint16BE( dataBuff.subarray( 0, 2 ) )
		const encryptedKey		= dataBuff.subarray( 2, 2 + rsaKeyLength )
		const encryptedData		= dataBuff.subarray( 2 + rsaKeyLength )
		const {
			privateKey: rsaPrivateKey, passphrase
		} = Cipher.GetPrivateKey( privateKey )

		const decryptedKey = (
			crypto.privateDecrypt( {
				key			: rsaPrivateKey,
				passphrase	: passphrase,
				padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash	: 'sha256',
			}, encryptedKey )
		)

		return Cipher.Decrypt( encryptedData, decryptedKey, options )
		
	}


	/**
	 * Cipher stream based functions.
	 * 
	 */
	static stream = {
		/**
		 * Encrypt stream data.
		 * 
		 * @param	secret	The secret key used to encrypt the data.
		 * @param	options An object defining required options. See {@link Cph.Stream.EncryptOptions} for more info.
		 * 
		 * @returns A new Promise that resolves `void` once stream encryption is completed.
		 */
		Encrypt(
			secret	: CoerceToUint8ArrayInput,
			options	: Cph.Stream.EncryptOptions,
		)
		{
			options.algorithm ||= Cipher.DEFAULT_ALGORITHM.stream
			
			const {
				Key, IV, options: { input, output, algorithm, salt, iv, authTag },
			} = Cipher.NewKeyIV<Cph.Stream.EncryptResolvedOptions>( options )
			
			const encryptedKey = (
				Cipher.Encrypt( Buffer.concat( [ Key, IV ] ), secret, { algorithm, salt, iv, authTag } )
			)
	
			const cipher = crypto.createCipheriv( algorithm, Key, IV )

			return Cipher.stream.Cipher( {
				cipher, input, output, encryptedKey
			} )
		},
		/**
		 * Decrypt stream data.
		 * 
		 * @param	secret	The secret key used to decrypt the data.
		 * @param	options	An object defining required options. See {@link Cph.Stream.DecryptOptions} for more info.
		 * 
		 * @returns	A new Promise that resolves `void` once stream decryption is completed.
		 */
		Decrypt(
			secret	: CoerceToUint8ArrayInput,
			options	: Cph.Stream.DecryptOptions,
		)
		{
			options.algorithm ||= Cipher.DEFAULT_ALGORITHM.stream

			const {
				input, output, algorithm, salt, iv, authTag, length
			} = Cipher.ResolveOptions<Cph.Stream.DecryptResolvedOptions>( options )

			return new Promise<void>( ( resolve, reject ) => {
				input.on( 'error', reject )
				output.on( 'error', reject )

				return (
					Cipher.stream.ExtractKeyLength( input )
						.then( Cipher.stream.ExtractKeyIV )
						.then( async ( [ EncryptedKeyIV, input ] ) => {
							
							input.on( 'error', reject )

							const KeyIV = (
								Cipher.Decrypt( EncryptedKeyIV, secret, { algorithm, salt, iv, authTag } )
							)

							const Key		= KeyIV.subarray( 0, length )
							const IV		= KeyIV.subarray( length )
							const decipher	= crypto.createDecipheriv( algorithm, Key, IV )

							await Cipher.stream.Decipher( {
								decipher, input, output
							} )

							resolve()
						} )
						.catch( reject )
				)
			} )

		},
		/**
		 * Encrypt stream data using hybrid encryption.
		 * 
		 * @param	publicKey	The public key.
		 * @param	options		An object defining required options. See {@link Cph.Stream.EncryptOptions} for more info.
		 * 
		 * @returns	A new Promise that resolves `void` once stream encryption is completed.
		 */
		HybridEncrypt(
			publicKey	: crypto.KeyLike,
			options		: Cph.Stream.EncryptOptions,
		) {

			options.algorithm ||= Cipher.DEFAULT_ALGORITHM.stream

			const {
				Key, IV,
				options: { algorithm, input, output },
			} = Cipher.NewKeyIV<Cph.Stream.EncryptResolvedOptions>( options )

			const encryptedKey = (
				crypto.publicEncrypt( {
					key			: publicKey,
					padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
					oaepHash	: 'sha256',
				}, Buffer.concat( [ Key, IV ] ) )
			)
	
			const cipher = crypto.createCipheriv( algorithm, Key, IV )
			
			return Cipher.stream.Cipher( {
				cipher, encryptedKey, input, output
			} )

		},
		/**
		 * Decrypt stream data using hybrid decryption.
		 * 
		 * @param	privateKey	The private key.
		 * @param	options		An object defining required options. See {@link Cph.Stream.DecryptOptions} for more info.
		 * 
		 * @returns	A new Promise that resolves `void` once stream decryption is completed.
		 */
		HybridDecrypt(
			privateKey	: Cph.PrivateKey,
			options		: Cph.Stream.DecryptOptions,
		) {

			const { input, output } = options

			const { keyLength, algorithm } = (
				Cipher.GetKeyLength( options.algorithm || Cipher.DEFAULT_ALGORITHM.stream )
			)

			return (
				new Promise<void>( ( resolve, reject ) => {
					input.on( 'error', reject )
					output.on( 'error', reject )

					return (
						Cipher.stream.ExtractKeyLength( input )
							.then( Cipher.stream.ExtractKeyIV )
							.then( ( [ EncryptedKeyIV, input ] ) => (
								{
									...( Cipher.DecryptKeyIV( {
										privateKey, EncryptedKeyIV, keyLength,
									} ) ),
									input,
								}
							) )
							.then( async ( { Key, IV, input } ) => {
								input.on( 'error', reject )
								const decipher = crypto.createDecipheriv( algorithm, Key, IV )

								await Cipher.stream.Decipher(
									{ decipher, input, output }
								)
								
								resolve()
							} )
							.catch( reject )
					)
				} )
			)

		},
		/**
		 * Handle pipe flow to encrypt a Stream.
		 * 
		 * @param	options Required parameters.
		 * @returns A new Promise that resolves `void` once stream is completed.
		 */
		Cipher( options: Cph.Stream.CipherOptions ) {
			const {
				cipher, encryptedKey, input, output
			} = options

			return (
				new Promise<void>( ( resolve, reject ) => {
					cipher.on( 'error', reject )
					input.on( 'error', reject )
					output.on( 'error', reject )
					output.on( 'finish', resolve )
			
					output.write( writeUint16BE( encryptedKey.length ) )
					output.write( encryptedKey )
					input.pipe( cipher ).pipe( output )
				} )
			)
		},
		/**
		 * Handle pipe flow to decrypt a Stream.
		 * 
		 * @param	options Required parameters.
		 * @returns A new Promise that resolves `void` once stream is completed.
		 */
		Decipher( options: Cph.Stream.DecipherOptions ) {
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
		},
		ExtractKeyLength( input: Readable ): Promise<Cph.Stream.ExtractedKeyLength> {
			return (
				extractBytesFromReadable( input, 2 )
					.then( ( [ KeyLength, output ] ) => [
						readUint16BE( KeyLength ), output
					] )
			)
		},
		ExtractKeyIV( [ KeyLength, input ]: Cph.Stream.ExtractedKeyLength ) {
			return (
				extractBytesFromReadable( input, KeyLength )
			)
		},
	}


	/**
	 * Decrypt Key and Initialization Vector.
	 * 
	 * @param	options An object containing required data.
	 * @returns	An object containing decrpyted `Key` and `IV`.
	 */
	private static DecryptKeyIV( options: Cph.Decrypt.ExtractKeyOptions )
	{
		const { privateKey, EncryptedKeyIV, keyLength } = options

		const {
			privateKey: rsaPrivateKey, passphrase
		} = Cipher.GetPrivateKey( privateKey )

		const KeyIV = crypto.privateDecrypt( {
			key			: rsaPrivateKey,
			passphrase	: passphrase,
			padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash	: 'sha256',
		}, EncryptedKeyIV )

		const Key	= KeyIV.subarray( 0, keyLength )
		const IV	= KeyIV.subarray( keyLength )

		return { Key, IV }
	}

	
	private static GetPrivateKey( privateKey: Cph.PrivateKey )
	{
		const rsaPrivateKey		= (
			typeof privateKey === 'object' && 'key' in privateKey ? privateKey.key : privateKey
		)
		const passphrase		= (
			typeof privateKey === 'object' && 'passphrase' in privateKey ? privateKey.passphrase : undefined
		)

		return { privateKey: rsaPrivateKey, passphrase }
	}


	/**
	 * Generates a `Scrypt` Symmetric Key and the Initialization Vector with the given options.
	 * 
	 * @param options (Optional) Additional options.
	 * 
	 * @returns An object with the generated `Key`, `IV`, `salt` and resolved `options`. 
	 */
	static NewKeyIV<T extends Cph.ResolvedOptions = Cph.ResolvedOptions>(
		options	: Cph.NewKeyIVOptions = {},
	)
	{
		const { secret } = options
		const _options	= Cipher.ResolveOptions<T>( options )
		const _secret	= secret ? coerceToUint8Array( secret ) : crypto.randomBytes( _options.length )
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
	private static ResolveOptions<
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
		_options.salt		= clamp( _options.salt, Cipher.SALT_LENGTH.min, Cipher.SALT_LENGTH.max )
		_options.authTag	= clamp( _options.authTag, Cipher.AUTH_TAG_LENGTH.min, Cipher.AUTH_TAG_LENGTH.max )
		

		if ( ! _options.aad ) {
			/**
			 * Clamp AAD length if user did not give us the AAD buffer.
			 * 
			 */
			_options.aadLength = clamp( _options.aadLength, Cipher.AAD_LENGTH.min, Cipher.AAD_LENGTH.max )
		}

		const { keyLength, algorithm } = Cipher.GetKeyLength( options.algorithm )

		_options.algorithm	= algorithm
		_options.length		= keyLength
		_options.iv			= Cipher.GetIVLength( algorithm, options )

		return _options
	}


	/**
	 * Get the Initialization Vector length based on the given algorithm.
	 * 
	 * @param	algorithm The algorithm in use.
	 * @param	options ( Optional ) Additional options. 
	 * @returns	The Initialization Vector length based on the given algorithm
	 */
	static GetIVLength(
		algorithm	: Cph.Options[ 'algorithm' ] = Cipher.DEFAULT_ALGORITHM.buffer,
		options		: Cph.Options = {},
	)
	{
		switch ( algorithm ) {
			case Cipher.ALGORITHM.AES_128_CCM:
			case Cipher.ALGORITHM.AES_192_CCM:
			case Cipher.ALGORITHM.AES_256_CCM:
			case Cipher.ALGORITHM.AES_128_OCB:
			case Cipher.ALGORITHM.AES_192_OCB:
			case Cipher.ALGORITHM.AES_256_OCB:
				return 8
			case Cipher.ALGORITHM.CHACHA_20_POLY:
				return 12
			default:
				return clamp(
					options.iv || Cipher.IV_LENGTH.default,
					Cipher.IV_LENGTH.min,
					Cipher.IV_LENGTH.max,
				)
		}
	}


	/**
	 * Ensure correct key length based on the given algorithm.
	 *
	 * @param	algorithm The AES algorithm name.
	 * @returns	An object with validated `algorithm` and `keyLength`.
	 */
	static GetKeyLength(
		algorithm: Cph.Options[ 'algorithm' ] = Cipher.DEFAULT_ALGORITHM.buffer
	)
	{
		switch ( algorithm ) {
			case Cipher.ALGORITHM.CHACHA_20_POLY:
				return {
					algorithm: algorithm,
					keyLength: 256 / 8,
				} as const
			case Cipher.ALGORITHM.AES_128_CBC:
			case Cipher.ALGORITHM.AES_128_CCM:
			case Cipher.ALGORITHM.AES_128_GCM:
			case Cipher.ALGORITHM.AES_128_OCB:
				return {
					algorithm: algorithm,
					keyLength: 128 / 8, // AES-128 needs a 128 bit (16 bytes)
				} as const
			case Cipher.ALGORITHM.AES_192_CBC:
			case Cipher.ALGORITHM.AES_192_CCM:
			case Cipher.ALGORITHM.AES_192_GCM:
			case Cipher.ALGORITHM.AES_192_OCB:
				return {
					algorithm: algorithm,
					keyLength: 192 / 8, // AES-192 needs a 192 bit (24 bytes)
				} as const
			case Cipher.ALGORITHM.AES_256_CBC:
			case Cipher.ALGORITHM.AES_256_CCM:
			case Cipher.ALGORITHM.AES_256_GCM:
			case Cipher.ALGORITHM.AES_256_OCB:
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
	static IsGCM( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherGCMTypes
	{
		return (
			algorithm === Cipher.ALGORITHM.AES_128_GCM ||
			algorithm === Cipher.ALGORITHM.AES_192_GCM ||
			algorithm === Cipher.ALGORITHM.AES_256_GCM
		)
	}


	/**
	 * Check if the given algorithm is a Cipher AES-CCM algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher AES-CCM algorithm. `false` otherwise.
	 */
	static IsCCM( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherCCMTypes
	{
		return (
			algorithm === Cipher.ALGORITHM.AES_128_CCM ||
			algorithm === Cipher.ALGORITHM.AES_192_CCM ||
			algorithm === Cipher.ALGORITHM.AES_256_CCM
		)
	}
	
	
	/**
	 * Check if the given algorithm is a Cipher chacha20-poly1305 algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher chacha20-poly1305 algorithm. `false` otherwise.
	 */
	static IsChacha20Poly( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherChaCha20Poly1305Types
	{
		return (
			algorithm === Cipher.ALGORITHM.CHACHA_20_POLY
		)
	}


	/**
	 * Check if the given algorithm is a Cipher AES-OCB algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher AES-OCB algorithm. `false` otherwise.
	 */
	static IsOCB( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherOCBTypes
	{
		return (
			algorithm === Cipher.ALGORITHM.AES_128_OCB ||
			algorithm === Cipher.ALGORITHM.AES_192_OCB ||
			algorithm === Cipher.ALGORITHM.AES_256_OCB
		)
	}


	/**
	 * Check if the given algorithm is a Cipher AES-CBC algorithm.
	 * 
	 * @param algorithm The AES Algorithm to check.
	 * @returns `true` if the given algorithm is a Cipher AES-CBC algorithm. `false` otherwise.
	 */
	static IsCBC( algorithm: Cph.AesAlgorithm ): algorithm is Cph.CBCTypes
	{
		return (
			algorithm === Cipher.ALGORITHM.AES_128_CBC ||
			algorithm === Cipher.ALGORITHM.AES_192_CBC ||
			algorithm === Cipher.ALGORITHM.AES_256_CBC
		)
	}

}