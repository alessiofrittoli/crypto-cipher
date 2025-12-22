import crypto from 'crypto'
import { clamp } from '@alessiofrittoli/math-utils'
import { coerceToUint8Array, CoerceToUint8ArrayInput } from '@alessiofrittoli/crypto-buffer'
import { Cph } from '@/new/types'


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
	

	/**
	 * Default AES algorithms used based on functionality.
	 * 
	 */
	static readonly DEFAULT_ALGORITHM = {
		buffer: 'aes-256-gcm',
		stream: 'aes-256-cbc',
	} as const


	/**
	 * Supported AES algorithms.
	 * 
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
		
		
		if ( Cipher.IsCCM( algorithm ) ) {
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
	 * ⚠️ This is not suitable for large data. Use {@link Cipher.streamDecrypt()} or {@link Cipher.hybridStreamDecrypt()} methods for large data decryption.
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

		if ( Cipher.IsCCM( algorithm ) ) {
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
	static GetKeyLength(
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
	static IsGCM( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherGCMTypes
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
	static IsCCM( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherCCMTypes
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
	static IsOCB( algorithm: Cph.AesAlgorithm ): algorithm is crypto.CipherOCBTypes
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
	static IsCBC( algorithm: Cph.AesAlgorithm ): algorithm is Cph.CBCTypes
	{
		return (
			algorithm === 'aes-128-cbc' ||
			algorithm === 'aes-192-cbc' ||
			algorithm === 'aes-256-cbc'
		)
	}

}