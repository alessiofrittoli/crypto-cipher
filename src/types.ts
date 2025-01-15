import { CoerceToUint8ArrayInput } from '@alessiofrittoli/crypto-buffer'
import type crypto from 'crypto'
import type { Readable, Writable } from 'stream'

export namespace Cph
{
	/** Cipher CBC algorithm types. */
	export type CBCTypes = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc'
	
	
	/** Cipher supported algorithm types. */
	export type AesAlgorithm = (
		| crypto.CipherCCMTypes | crypto.CipherGCMTypes
		| crypto.CipherOCBTypes | Cph.CBCTypes
	)
	
	
	/**
	 * Common Cipher options.
	 * @template T The AES algorithm type.
	 */
	export interface Options<T extends Cph.AesAlgorithm = Cph.AesAlgorithm>
	{
		/** The Cipher algorithm to use. Default: `aes-256-gcm`. */
		algorithm?: T
		/** The salt length. Minimum: `16`, Maximum: `64`. Default: `32`. */
		salt?: number
		/** The `IV` length. Minimum: `8`, Maximum: `32`. Default: `16`. */
		iv?: number
		/** The `authTag` length. Minimum: `4`, Maximum: `16`. Default: `16`. */
		authTag?: number
		/** Custom `Additional Authenticated Data`. */
		aad?: CoerceToUint8ArrayInput
		/** The `AAD` length. Minimum: `16`, Maximum: `4096`. Default: `32`. */
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
		}


		export namespace Hybrid
		{
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
		}
	}
}

