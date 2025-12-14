import type crypto from 'crypto'
import type { Readable, Writable } from 'stream'
import type { CoerceToUint8ArrayInput } from '@alessiofrittoli/crypto-buffer'

/**
 * Cipher types.
 */
export namespace Cph
{
	/** Cipher CBC algorithm types. */
	export type CBCTypes = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc'
	
	
	/** Cipher supported algorithm types. */
	export type AesAlgorithm = (
		| crypto.CipherCCMTypes | crypto.CipherGCMTypes
		| crypto.CipherOCBTypes | Cph.CBCTypes | crypto.CipherChaCha20Poly1305Types
	)
	
	
	/**
	 * Common Cipher options.
	 * @template T The AES algorithm type.
	 */
	export interface Options<T extends Cph.AesAlgorithm = Cph.AesAlgorithm>
	{
		/** The Cipher algorithm to use. Default: `aes-256-gcm` | `aes-256-cbc`. */
		algorithm?: T
		/** The salt length. Minimum: `16`, Maximum: `64`. Default: `32`. */
		salt?: number
		/** The `IV` length. Minimum: `8`, Maximum: `32`. Default: `16`. */
		iv?: number
		/** The `authTag` length. Minimum: `4`, Maximum: `16`. Default: `16`. */
		authTag?: number
		/** Custom `Additional Authenticated Data`. */
		aad?: CoerceToUint8ArrayInput
		/** The `AAD` length. Minimum: `16`, Maximum: `128`. Default: `32`. */
		aadLength?: number
	}


	/**
	 * Resolved Common options.
	 */
	export interface ResolvedOptions<
		T extends Cph.AesAlgorithm = Cph.AesAlgorithm
	> extends Required<Omit<Cph.Options<T>, 'aad'>>
	{
		/** The symmetric key length. */
		length: number
		aad?: Uint8Array
	}


	export namespace Stream
	{
		export namespace Symmetric
		{
			/**
			 * Options for encrypting a stream.
			 */
			export interface EncryptOptions extends Cph.Options<Cph.CBCTypes>
			{
				/** The `Readable` Stream from where raw data to encrypt is read. */
				input: Readable
				/** The `Writable` Stream where encrypted data is written. */
				output: Writable
			}


			/**
			 * Resolved Stream Encrypt options (symmetric and hybrid).
			 */
			export type EncryptResolvedOptions = (
				Cph.ResolvedOptions
				& Required<Cph.Stream.Symmetric.EncryptOptions>
			)


			/**
			 * Returnign object from `Cipher.encryptStream()` method.
			 */
			export interface EncryptReturnType
			{
				/** The `crypto.Cipheriv` instance. */
				cipher: crypto.Cipheriv
				/** The actual `encrypt` callback that must be called and awaited in order to start the encryption process. */
				encrypt	: () => Promise<void>
			}


			/**
			 * Options for decrypting a stream (symmetric).
			 */
			export interface DecryptOptions extends Cph.Stream.Symmetric.EncryptOptions
			{
				/** The `Readable` Stream from where encrypted data is read. */
				input: Readable
				/** The `Writable` Stream where decrypted data is written. */
				output: Writable
			}
			
			
			/**
			 * Resolved Stream Decrypt options (symmetric).
			 */
			export type DecryptResolvedOptions = (
				Cph.ResolvedOptions
				& Required<Cph.Stream.Symmetric.DecryptOptions>
			)


			export interface DecryptReturnType
			{
				/** The `crypto.Decipheriv` instance. */
				decipher: crypto.Decipheriv
				/** The actual `decrypt` callback that must be called and awaited in order to start the decryption process. */
				decrypt	: () => Promise<void>
			}
		}


		export namespace Hybrid
		{
			/**
			 * Alias for {@link Cph.Stream.Symmetric.EncryptOptions}
			 */
			export type EncryptOptions = Cph.Stream.Symmetric.EncryptOptions


			/**
			 * Alias for {@link Cph.Stream.Symmetric.EncryptResolvedOptions}
			 */
			export type EncryptResolvedOptions = Cph.Stream.Symmetric.EncryptResolvedOptions


			/**
			 * Options for decrypting a stream.
			 */
			export interface DecryptOptions extends Cph.Stream.Symmetric.DecryptOptions
			{
				/** The RSA key length in bytes used while encrypting data. This is used to properly extract the encrypted Cipher Key and Initialization Vector. */
				rsaKeyLength: number
			}
			
			
			/**
			 * Resolved Stream Decrypt options.
			 */
			export type DecryptResolvedOptions = (
				Cph.ResolvedOptions
				& Required<Cph.Stream.Hybrid.DecryptOptions>
			)


			/**
			 * Alias for {@link Cph.Stream.Symmetric.EncryptReturnType}
			 */
			export type EncryptReturnType = Cph.Stream.Symmetric.EncryptReturnType


			/**
			 * Alias for {@link Cph.Stream.Symmetric.DecryptReturnType}
			 */
			export type DecryptReturnType = Cph.Stream.Symmetric.DecryptReturnType
		}
	}
}

