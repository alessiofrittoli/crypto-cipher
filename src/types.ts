import type {
	CipherCCMTypes, CipherGCMTypes, CipherOCBTypes, CipherChaCha20Poly1305Types,
	KeyLike,
	Cipheriv,
	Decipheriv
} from 'crypto'
import type { Readable, Transform, Writable } from 'stream'
import type { CoerceToUint8ArrayInput } from '@alessiofrittoli/crypto-buffer'


/**
 * Cipher types.
 * 
 */
export namespace Cph
{
	/** Cipher CBC algorithm types. */
	export type CBCTypes = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc'
	
	
	/** Cipher supported algorithm types. */
	export type AesAlgorithm = (
		| CipherCCMTypes | CipherGCMTypes
		| CipherOCBTypes | Cph.CBCTypes | CipherChaCha20Poly1305Types
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


	export interface NewKeyIVOptions<T extends Cph.AesAlgorithm = Cph.AesAlgorithm> extends Cph.Options<T>
	{
		secret?: CoerceToUint8ArrayInput
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
		/** The Additional Authentication Data. */
		aad?: Uint8Array
	}


	export type PrivateKey = KeyLike | { key: KeyLike, passphrase?: string }
	
	export namespace Stream
	{
		/**
		 * Options for encrypting a stream.
		 * 
		 */
		export interface EncryptOptions extends Cph.Options<Cph.CBCTypes>
		{
			/** The `Readable` Stream from where raw data to encrypt is read. */
			input: Readable
			/** The `Writable` Stream where encrypted data is written. */
			output: Writable
		}


		/**
		 * Options for decrypting a stream.
		 * 
		 */
		export type DecryptOptions = Cph.Stream.EncryptOptions

		/**
		 * Resolved Stream Encrypt options.
		 * 
		 */
		export type EncryptResolvedOptions = (
			Cph.ResolvedOptions
			& Required<Cph.Stream.EncryptOptions>
		)


		/**
		 * Resolved Stream Decrypt options.
		 * 
		 */
		export type DecryptResolvedOptions = (
			Cph.ResolvedOptions
			& Required<Cph.Stream.DecryptOptions>
		)

		/**
		 * INTERNAL USE ONLY
		 */
		export interface CipherOptions
		{
			cipher		: Cipheriv
			encryptedKey: Buffer
			input		: Readable
			output		: Writable
		}

		/**
		 * INTERNAL USE ONLY
		 */
		export interface DecipherOptions
		{
			decipher	: Decipheriv
			input		: Readable
			output		: Writable
		}


		export type ExtractedKeyLength = [ KeyLength: number, input: Readable | Transform ]
		export type ExtractedBytes = [ DataRead: Buffer, input: Transform ]
	}


	export namespace Decrypt
	{
		export interface ExtractKeyOptions
		{
			privateKey: Cph.PrivateKey
			EncryptedKeyIV: Buffer
			keyLength: number
		}
	}
}