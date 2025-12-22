import type {
	CipherCCMTypes, CipherGCMTypes, CipherOCBTypes, CipherChaCha20Poly1305Types
} from 'crypto'
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
	
}