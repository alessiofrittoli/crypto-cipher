# Crypto Cipher 🔐

[![NPM Latest Version][version-badge]][npm-url] [![Coverage Status][coverage-badge]][coverage-url] [![Socket Status][socket-badge]][socket-url] [![NPM Monthly Downloads][downloads-badge]][npm-url] [![Dependencies][deps-badge]][deps-url]

[![GitHub Sponsor][sponsor-badge]][sponsor-url]

[version-badge]: https://img.shields.io/npm/v/%40alessiofrittoli%2Fcrypto-cipher
[npm-url]: https://npmjs.org/package/%40alessiofrittoli%2Fcrypto-cipher
[coverage-badge]: https://coveralls.io/repos/github/alessiofrittoli/crypto-cipher/badge.svg
[coverage-url]: https://coveralls.io/github/alessiofrittoli/crypto-cipher
[socket-badge]: https://socket.dev/api/badge/npm/package/@alessiofrittoli/crypto-cipher
[socket-url]: https://socket.dev/npm/package/@alessiofrittoli/crypto-cipher/overview
[downloads-badge]: https://img.shields.io/npm/dm/%40alessiofrittoli%2Fcrypto-cipher.svg
[deps-badge]: https://img.shields.io/librariesio/release/npm/%40alessiofrittoli%2Fcrypto-cipher
[deps-url]: https://libraries.io/npm/%40alessiofrittoli%2Fcrypto-cipher
[sponsor-badge]: https://img.shields.io/static/v1?label=Fund%20this%20package&message=%E2%9D%A4&logo=GitHub&color=%23DB61A2
[sponsor-url]: https://github.com/sponsors/alessiofrittoli

## Node.js Cipher cryptograph utility library

### Table of Contents

- [Getting started](#getting-started)
- [Key features](#key-features)
- [What's changed](#whats-changed)
- [Migration guide](#migration-guide)
- [API Reference](#api-reference)
  - [Constants](#constants)
  - [Methods](#methods)
    - [`Cipher.Encrypt()`](#cipherencrypt)
    - [`Cipher.Decrypt()`](#cipherdecrypt)
    - [`Cipher.HybridEncrypt()`](#cipherhybridencrypt)
    - [`Cipher.HybridDecrypt()`](#cipherhybriddecrypt)
    - [`Cipher.stream.Encrypt()`](#cipherstreamencrypt)
    - [`Cipher.stream.Decrypt()`](#cipherstreamdecrypt)
    - [`Cipher.stream.HybridEncrypt()`](#cipherstreamhybridencrypt)
    - [`Cipher.stream.HybridDecrypt()`](#cipherstreamhybriddecrypt)
  - [Types](#types)
- [Examples](#examples)
  - [In-memory data buffer encryption/decryption](#in-memory-data-buffer-encryptiondecryption)
  - [In-memory data buffer hybrid encryption/decryption](#in-memory-data-buffer-hybrid-encryptiondecryption)
  - [In-memory data stream encryption/decryption](#in-memory-data-stream-encryptiondecryption)
  - [In-memory data stream with hybrid encryption/decryption](#in-memory-data-stream-with-hybrid-encryptiondecryption)
  - [File based data stream encryption/decryption](#file-based-data-stream-encryptiondecryption)
  - [File based data stream with hybrid encryption/decryption](#file-based-data-stream-with-hybrid-encryptiondecryption)
- [Development](#development)
  - [ESLint](#eslint)
  - [Jest](#jest)
- [Contributing](#contributing)
- [Security](#security)
- [Credits](#made-with-)

---

### Getting started

The `crypto-cipher` library provides AES encryption and decryption functionality, supporting both in-memory buffers and streams. It adheres to the [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) standard recommendations.

⚠️ Note that every performed operation cannot be accomplished client-side and must be executed on a back-end server.

It is part of the [`crypto`](https://npmjs.com/search?q=%40alessiofrittoli%2Fcrypto) utility libraries and can be installed by running the following command:

```bash
npm i @alessiofrittoli/crypto-cipher
```

or using `pnpm`

```bash
pnpm i @alessiofrittoli/crypto-cipher
```

---

### Key features

- Supports multiple AES algorithms (`CCM`, `GCM`, `OCB`, `CBC`) and even `chacha20-poly1305`.
- In-memory buffer encryption and decrpytion.
- Robust support for encrypting and decrypting streams (in-memory and file based).
- Hybrid encryption methods for combining symmetric and asymmetric cryptography.

#### Security Considerations

- Random `salt` and `IV` generation.
- AEAD - Authenticated encryption modes with proper `authTag` and `Additional Authenticated Data` handling.

#### Readable and Modular

- Separation of concerns with clear method responsibilities.
- Comprehensive JSDoc comments enhance maintainability and readability.

---

### What's Changed

🎉 Core updates in the latest release:

- `Cipher` methods have been refactored to provide a solid and easy usage
- [`Cipher.HybridEncrypt()`](#cipherhybridencrypt) and [`Cipher.HybridDecrypt()`](#cipherhybriddecrypt) have been added. These methods will allow you to encrypt/decrypt in-memory buffer data using hybrid encryption algorithms.
- `Cipher.stream` subgroup has been added to keep method names consistent across the library.
- hybrid encryption doesn't require a password anymore which was redundant. an RSA key pair is all what you need.
- providing RSA key length during hybrid decryption is no longer needed.

---

### Migration guide

#### Migrating from v2.x.x to v3.0.0

**`Cipher.encrypt()`**

Is now renamed to **`Cipher.Encrypt()`**. It's API implementation remain the same.

---

**`Cipher.decrypt()`**

Is now renamed to **`Cipher.Decrypt()`**. It's API implementation remain the same.

---

**`Cipher.streamEncrypt()`**

**Before**

```ts
await Cipher.streamEncrypt(password, { input, output }).encrypt();
```

**Now**

```ts
await Cipher.stream.Encrypt(password, { input, output });
```

---

**`Cipher.streamDecrypt()`**

**Before**

```ts
const { decrypt } = await Cipher.streamDecrypt(password, { input, output });

await decrypt();
```

**Now**

```ts
await Cipher.stream.Decrypt(password, { input, output });
```

---

**`Cipher.hybridEncrypt()`**

**Before**

```ts
const { encrypt } = Cipher.hybridEncrypt(
  password,
  {
    key: keyPair.publicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "SHA-256",
  },
  { input, output }
);
await encrypt();
```

**Now**

```ts
await Cipher.stream.HybridEncrypt(keyPair.publicKey, { input, output });
```

---

**`Cipher.hybridDecrypt()`**

**Before**

```ts
const { decrypt } = await Cipher.hybridDecrypt(
  {
    key: keyPair.privateKey,
    passphrase: passphrase,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "SHA-256",
  },
  { input, output, rsaKeyLength }
);

await decrypt();
```

**Now**

```ts
await Cipher.stream.HybridDecrypt(
  { key: keyPair.privateKey, passphrase },
  { input, output }
);
```

**Or even**

```ts
await Cipher.stream.HybridDecrypt(keyPair.privateKey, { input, output });
```

---

### API Reference

#### Constants

##### `Cipher.SALT_LENGTH`

Defines the minimum, maximum, and default lengths for salt.

<details>
<summary>Properties</summary>

| Property  | Value |
| --------- | ----- |
| `min`     | 16    |
| `max`     | 64    |
| `default` | 32    |

</details>

---

##### `Cipher.IV_LENGTH`

Defines the minimum, maximum, and default lengths for initialization vectors (IV).

<details>
<summary>Properties</summary>

| Property  | Value |
| --------- | ----- |
| `min`     | 8     |
| `max`     | 32    |
| `default` | 16    |

</details>

---

##### `Cipher.AUTH_TAG_LENGTH`

Defines the minimum, maximum, and default lengths for authentication tags.

<details>
<summary>Properties</summary>

| Property  | Value |
| --------- | ----- |
| `min`     | 4     |
| `max`     | 16    |
| `default` | 16    |

</details>

---

##### `Cipher.AAD_LENGTH`

Defines the minimum, maximum, and default lengths for additional authenticated data (AAD).

<details>
<summary>Properties</summary>

| Property  | Value |
| --------- | ----- |
| `min`     | 16    |
| `max`     | 4096  |
| `default` | 32    |

</details>

---

##### `Cipher.DEFAULT_ALGORITHM`

Specifies default AES algorithms for buffer and stream operations.

<details>
<summary>Properties</summary>

| Operation | Algorithm     | Description                                                                           |
| --------- | ------------- | ------------------------------------------------------------------------------------- |
| `buffer`  | `aes-256-gcm` | Default algorithm used for buffer data encryption/decryption                          |
| `stream`  | `aes-256-cbc` | Default algorithm used for stream encryption/decryption (Cipher Block Chaining mode). |

</details>

---

##### `Cipher.ALGORITHM`

An object defining algorithm names.

<details>
<summary>Properties</summary>

| Property         | Value               |
| ---------------- | ------------------- |
| `AES_128_CBC`    | 'aes-128-cbc'       |
| `AES_192_CBC`    | 'aes-192-cbc'       |
| `AES_256_CBC`    | 'aes-256-cbc'       |
| `AES_128_CCM`    | 'aes-128-ccm'       |
| `AES_192_CCM`    | 'aes-192-ccm'       |
| `AES_256_CCM`    | 'aes-256-ccm'       |
| `AES_128_GCM`    | 'aes-128-gcm'       |
| `AES_192_GCM`    | 'aes-192-gcm'       |
| `AES_256_GCM`    | 'aes-256-gcm'       |
| `AES_128_OCB`    | 'aes-128-ocb'       |
| `AES_192_OCB`    | 'aes-192-ocb'       |
| `AES_256_OCB`    | 'aes-256-ocb'       |
| `CHACHA_20_POLY` | 'chacha20-poly1305' |

</details>

---

##### `Cipher.ALGORITHMS`

An array of supported AES algorithms. This array includes all values in [`Cipher.ALGORITHM`](#cipheralgorithm) constant.

---

#### Methods

##### `Cipher.Encrypt()`

Encrypts an in-memory data buffer.

> [!WARNING]
> This is not suitable for large data encryption. Use [`Cipher.stream.Encrypt()`](#cipherstreamencrypt) or [`Cipher.stream.HybridEncrypt()`](#cipherstreamhybridencrypt) methods for large data encryption.

<details>

<summary>Parameters</summary>

| Name      | Type                      | Description                               |
| --------- | ------------------------- | ----------------------------------------- |
| `data`    | `CoerceToUint8ArrayInput` | Data to encrypt.                          |
| `secret`  | `CoerceToUint8ArrayInput` | Secret key for encryption.                |
| `options` | `Cph.Options`             | (Optional) Additional encryption options. |

</details>

---

<details>

<summary>Returns</summary>

Type: `Buffer`

The encrypted result buffer.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Options`](#cphoptionst) for more informations about additional encryption options.
- See [In-memory data buffer encryption/decryption](#in-memory-data-buffer-encryptiondecryption) examples.

---

##### `Cipher.Decrypt()`

Decrypts an in-memory data buffer.

> [!WARNING]
> This is not suitable for large data decryption. Use [`Cipher.stream.Decrypt()`](#cipherstreamdecrypt) or [`Cipher.stream.HybridDecrypt()`](#cipherstreamhybriddecrypt) methods for large data decryption.

<details>

<summary>Parameters</summary>

| Name      | Type                      | Description                                            |
| --------- | ------------------------- | ------------------------------------------------------ |
| `data`    | `CoerceToUint8ArrayInput` | Data to decrypt.                                       |
| `secret`  | `CoerceToUint8ArrayInput` | Secret key for decryption.                             |
| `options` | `Cph.Options`             | (Optional) Decryption options (must match encryption). |

</details>

---

<details>

<summary>Returns</summary>

Type: `Buffer`

The decrypted result buffer.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Options`](#cphoptionst) for more informations about additional decryption options.
- See [In-memory data buffer encryption/decryption](#in-memory-data-buffer-encryptiondecryption) examples.

---

##### `Cipher.HybridEncrypt()`

Encrypts in-memory data using hybrid encryption.

> [!WARNING]
> This is not suitable for large data encryption. Use [`Cipher.stream.HybridEncrypt()`](#cipherstreamhybridencrypt) method for large data encryption.

---

> [!WARNING]
> Please, note that when using hybrid encryption/decryption algorithms:
>
> - an RSA keypair is required.
> - if a passphrase is set for the Private Key, please make sure to use one of the Cipher Block Chaining algorithm or `chacha20-poly1305` algorithm:
>   - aes-128-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-192-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-256-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - chacha20-poly1305 (`type` can only be `pkcs1`)

<details>

<summary style="cursor:pointer">Parameters</summary>

| Parameter | Type                      | Default | Description                    |
| --------- | ------------------------- | ------- | ------------------------------ |
| `data`    | `CoerceToUint8ArrayInput` | -       | The data to encrypt.           |
| `key`     | `crypto.KeyLike`          | -       | The RSA Public Key.            |
| `options` | `Cph.Options`             | -       | (Optional) Additional options. |

</details>

---

<details>

<summary>Returns</summary>

Type: `Buffer`

The encrypted result buffer.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Options`](#cphoptionst) for more informations about additional decryption options.
- See [In-memory data buffer hybrid encryption/decryption](#in-memory-data-buffer-hybrid-encryptiondecryption) example.

---

##### `Cipher.HybridDecrypt()`

Decrypts in-memory data using hybrid encryption.

> [!WARNING]
> This is not suitable for large data decryption. Use [`Cipher.stream.HybridDecrypt()`](#cipherstreamhybriddecrypt) method for large data decryption.

---

> [!WARNING]
> Please, note that when using hybrid encryption/decryption algorithms:
>
> - an RSA keypair is required.
> - if a passphrase is set for the Private Key, please make sure to use one of the Cipher Block Chaining algorithm or `chacha20-poly1305` algorithm:
>   - aes-128-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-192-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-256-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - chacha20-poly1305 (`type` can only be `pkcs1`)

<details>

<summary style="cursor:pointer">Parameters</summary>

| Parameter | Type                      | Default | Description                    |
| --------- | ------------------------- | ------- | ------------------------------ |
| `data`    | `CoerceToUint8ArrayInput` | -       | The data to encrypt.           |
| `key`     | `Cph.PrivateKey`          | -       | The RSA Private Key.           |
| `options` | `Cph.Options`             | -       | (Optional) Additional options. |

</details>

---

<details>

<summary style="cursor:pointer">Returns</summary>

Type: `Buffer`.

The encrypted result Buffer.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.PrivateKey`](#cphprivatekey) for accepted formats.
- See [`Cph.Options`](#cphoptionst) for more informations about additional decryption options.
- See [In-memory data buffer hybrid encryption/decryption](#in-memory-data-buffer-hybrid-encryptiondecryption) example.

---

##### `Cipher.stream.Encrypt()`

Encrypt stream data.

<details>

<summary>Parameters</summary>

| Name                | Type                        | Default       | Description                                              |
| ------------------- | --------------------------- | ------------- | -------------------------------------------------------- |
| `secret`            | `CoerceToUint8ArrayInput`   | -             | The secret key used to encrypt the data.                 |
| `options`           | `Cph.Stream.EncryptOptions` | -             | An object defining required options.                     |
| `options.input`     | `Readable`                  | -             | The `Readable` Stream where raw data to encrypt is read. |
| `options.output`    | `Writable`                  | -             | The `Writable` Stream where encrypted data is written.   |
| `options.algorithm` | `Cph.CBCTypes`              | `aes-256-cbc` | One of the Cipher Block Chaining algorithm.              |

</details>

---

<details>

<summary style="cursor:pointer">Returns</summary>

Type: `Promise<void>`

A new Promise that resolves `void` once stream encryption is completed.

</details>

---

- See [In-memory data stream encryption/decryption](#in-memory-data-stream-encryptiondecryption) example.

---

##### `Cipher.stream.Decrypt()`

Decrypt stream data.

<details>

<summary>Parameters</summary>

| Name                | Type                        | Default       | Description                                            |
| ------------------- | --------------------------- | ------------- | ------------------------------------------------------ |
| `secret`            | `CoerceToUint8ArrayInput`   | -             | The secret key used to decrypt the data.               |
| `options`           | `Cph.Stream.DecryptOptions` | -             | An object defining required options.                   |
| `options.input`     | `Readable`                  | -             | The `Readable` Stream where encrypted data is read.    |
| `options.output`    | `Writable`                  | -             | The `Writable` Stream where decrypted data is written. |
| `options.algorithm` | `Cph.CBCTypes`              | `aes-256-cbc` | One of the Cipher Block Chaining algorithm.            |

</details>

---

<details>

<summary style="cursor:pointer">Returns</summary>

Type: `Promise<void>`

A new Promise that resolves `void` once stream decryption is completed.

</details>

---

- See [In-memory data stream encryption/decryption](#in-memory-data-stream-encryptiondecryption) example.

---

##### `Cipher.stream.HybridEncrypt()`

Encrypt stream data using hybrid encryption.

> [!WARNING]
> Please, note that when using hybrid encryption/decryption algorithms:
>
> - an RSA keypair is required.
> - if a passphrase is set for the Private Key, please make sure to use one of the Cipher Block Chaining algorithm or `chacha20-poly1305` algorithm:
>   - aes-128-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-192-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-256-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - chacha20-poly1305 (`type` can only be `pkcs1`)

<details>

<summary style="cursor:pointer">Parameters</summary>

| Parameter           | Type                        | Default       | Description                                              |
| ------------------- | --------------------------- | ------------- | -------------------------------------------------------- |
| `key`               | `crypto.KeyLike`            | -             | The RSA Public Key.                                      |
| `options`           | `Cph.Stream.EncryptOptions` | -             | An object defining required options.                     |
| `options.input`     | `Readable`                  | -             | The `Readable` Stream where raw data to encrypt is read. |
| `options.output`    | `Writable`                  | -             | The `Writable` Stream where encrypted data is written.   |
| `options.algorithm` | `Cph.CBCTypes`              | `aes-256-cbc` | One of the Cipher Block Chaining algorithm.              |

</details>

---

<details>

<summary>Returns</summary>

Type: `Promise<void>`

A new Promise that resolves `void` once stream encryption is completed.

</details>

---

- See [In-memory data stream with hybrid encryption/decryption](#in-memory-data-stream-with-hybrid-encryptiondecryption) example.

---

##### `Cipher.stream.HybridDecrypt()`

Decrypt stream data using hybrid decryption.

> [!WARNING]
> Please, note that when using hybrid encryption/decryption algorithms:
>
> - an RSA keypair is required.
> - if a passphrase is set for the Private Key, please make sure to use one of the Cipher Block Chaining algorithm or `chacha20-poly1305` algorithm:
>   - aes-128-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-192-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-256-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - chacha20-poly1305 (`type` can only be `pkcs1`)

<details>

<summary style="cursor:pointer">Parameters</summary>

| Parameter           | Type                        | Default       | Description                                            |
| ------------------- | --------------------------- | ------------- | ------------------------------------------------------ |
| `key`               | `Cph.PrivateKey`            | -             | The RSA Private Key.                                   |
| `options`           | `Cph.Stream.DecryptOptions` | -             | An object defining required options.                   |
| `options.input`     | `Readable`                  | -             | The `Readable` Stream where encrypted data is read.    |
| `options.output`    | `Writable`                  | -             | The `Writable` Stream where decrypted data is written. |
| `options.algorithm` | `Cph.CBCTypes`              | `aes-256-cbc` | One of the Cipher Block Chaining algorithm.            |

</details>

---

<details>

<summary>Returns</summary>

Type: `Promise<void>`

A new Promise that resolves `void` once stream encryption is completed.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.PrivateKey`](#cphprivatekey) for accepted formats.
- See [In-memory data stream with hybrid encryption/decryption](#in-memory-data-stream-with-hybrid-encryptiondecryption) example.

---

#### Types

##### `CoerceToUint8ArrayInput`

This module supports different input data types and it uses the [`coerceToUint8Array`](https://npmjs.com/package/@alessiofrittoli/crypto-buffer#coercetouint8array) utility function from [`@alessiofrittoli/crypto-buffer`](https://npmjs.com/package/@alessiofrittoli/crypto-buffer) to convert it to a `Uint8Array`.

- See [`coerceToUint8Array`](https://npmjs.com/package/@alessiofrittoli/crypto-buffer#coercetouint8array) for more informations about the supported input types.

---

##### `Cph.CBCTypes`

AES Cipher Block Chaining algorithms.

---

##### `Cph.AesAlgorithm`

All supported AES algorithms.

---

##### `Cph.Options<T>`

Common options in encryption/decryption processes.

<details>

<summary>Type parameters</summary>

| Parameter | Default            | Description                                                                            |
| --------- | ------------------ | -------------------------------------------------------------------------------------- |
| `T`       | `Cph.AesAlgorithm` | Accepted algorithm in `Cph.Options`. This is usefull to constraint specifc algorithms. |

</details>

---

<details>

<summary>Properties</summary>

| Property    | Type                      | Default                      | Description                                                                                                                                                    |
| ----------- | ------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `algorithm` | `T`                       | `aes-256-gcm \| aes-256-cbc` | Accepted algorithms.                                                                                                                                           |
| `salt`      | `number`                  | `32`                         | The `salt` length in bytes. Minimum: `16`, Maximum: `64`.                                                                                                      |
| `iv`        | `number`                  | `16`                         | The Initialization Vector length in bytes. Minimum: `8`, Maximum: `32`.                                                                                        |
| `authTag`   | `number`                  | `16`                         | The `authTag` length in bytes. Minimum: `4`, Maximum: `16`.                                                                                                    |
| `aad`       | `CoerceToUint8ArrayInput` | -                            | Custom Additional Authenticated Data. `aadLength` is then automatically resolved. If not provided, a random AAD is generated with a max length of `aadLength`. |
| `aadLength` | `number`                  | `32`                         | The auto generated AAD length in bytes. Minimum: `16`, Maximum: `128`.                                                                                         |

</details>

---

##### `Cph.Stream.EncryptOptions`

Stream symmetric encryption options.

<details>

<summary>Properties</summary>

| Property    | Type           | Description                                                   |
| ----------- | -------------- | ------------------------------------------------------------- |
| `input`     | `Readable`     | The `Readable` Stream from where raw data to encrypt is read. |
| `output`    | `Writable`     | The `Writable` Stream where encrypted data is written.        |
| `algorithm` | `Cph.CBCTypes` | One of the Cipher Block Chaining algorithm.                   |

</details>

---

##### `Cph.Stream.DecryptOptions`

Stream symmetric decryption options.

- Alias of [`Cph.Stream.EncryptOptions`](#cphstreamencryptoptions).

<details>

<summary>Properties</summary>

| Property    | Type           | Description                                              |
| ----------- | -------------- | -------------------------------------------------------- |
| `input`     | `Readable`     | The `Readable` Stream from where encrypted data is read. |
| `output`    | `Writable`     | The `Writable` Stream where decrypted data is written.   |
| `algorithm` | `Cph.CBCTypes` | One of the Cipher Block Chaining algorithm.              |

</details>

---

##### `Cph.PrivateKey`

The RSA Private Key.

It could be:

- a `crypto.KeyLike`
- an object defining `key` and `passphrase` where `key` is a `crypto.KeyLike`

---

### Examples

#### In-memory data buffer encryption/decryption

The simpliest way to encrypt/decrypt in-memory data buffers.

```ts
// encrypt
const data = "my top-secret data";
const password = "my-very-strong-password";

const encrypted = Cipher.Encrypt(data, password);

// decrypt
const decrypted = Cipher.Decrypt(encrypted, password);
console.log(decrypted); // Outputs: my top-secret data
```

---

#### In-memory data buffer hybrid encryption/decryption

Hybrid encryption offers an higher level of security since only the RSA Private Key owner will be able to decrypt the data.

> [!WARNING]
> Please, note that when using hybrid encryption/decryption algorithms:
>
> - an RSA keypair is required.
> - if a passphrase is set for the Private Key, please make sure to use one of the Cipher Block Chaining algorithm or `chacha20-poly1305` algorithm:
>   - aes-128-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-192-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-256-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - chacha20-poly1305 (`type` can only be `pkcs1`)

##### Keypair

```ts
import { Cipher } from "@alessiofrittoli/crypto-cipher";

const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 512 * 8, // 4096 bits
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
});

// or you can optionally set a custom passphrase
const passphrase = "custompassphrase";

const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 512 * 8, // 4096 bits
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: {
    type: "pkcs1",
    format: "pem",
    passphrase,
    cipher: Cipher.ALGORITHM.CHACHA_20_POLY,
  },
});
```

```ts
import { Cipher } from "@alessiofrittoli/crypto-cipher";

// encrypt
const data = "my top-secret data";
const encrypted = Cipher.HybridEncrypt(data, keypair.publicKey);

// decrypt
const decrypted = Cipher.HybridDecrypt(encrypted, {
  key: keypair.privateKey,
  passphrase,
});
```

---

#### In-memory data stream encryption/decryption

The in-memory data stream comes pretty handy when, for example, we need to stream encrypted data within a Server Response or to decrypt stream data from a Server Response.

##### Streaming

```ts
// /api/stream-encrypt

import { Readable, Writable } from "stream";
import { Stream } from "@alessiofrittoli/stream-writer";

const routeHandler = () => {
  const password = "my-very-strong-password";
  const stream = new Stream();
  const headers = new Headers(stream.headers);

  const input = Readable.from([
    Buffer.from("Chunk n.1"),
    Buffer.from("Chunk n.2"),
    Buffer.from("Chunk n.3"),
    Buffer.from("Chunk n.4"),
  ]);

  // `Writable` Stream where encrypted data is written
  const output = new Writable({
    async write(chunk, encoding, callback) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      await stream.write(chunk);
      callback();
    },
    async final(callback) {
      await stream.close();
      callback();
    },
  });

  Cipher.stream.Encrypt(password, { input, output }).catch(async () => {
    await stream.close();
  });

  return (
    // encrypted stream
    new Response(stream.readable, { headers })
  );
};
```

##### Decrypting received stream

```ts
// /api/stream-decrypt

import { Transform, Writable } from "stream";
import { Cipher } from "@alessiofrittoli/crypto-cipher";
import { StreamReader } from "@alessiofrittoli/stream-reader";

const password = "my-very-strong-password";

const routeHandler = () =>
  fetch("/api/stream-encrypt").then((response) => {
    if (!response.body) {
      return new Respone(null, { status: 400 });
    }

    // web stream where decrypted data is written
    const stream = new Stream<Buffer, string>({
      transform(chunk, controller) {
        controller.enqueue(chunk.toString());
      },
    });
    const headers = new Headers(stream.headers);

    headers.set("Content-Type", "text/html");

    const reader = new StreamReader<Uint8Array, Buffer, false>(response.body, {
      inMemory: false,
      transform: Buffer.from,
    });

    const input = new Transform();

    reader.on("data", (chunk) => input.push(chunk));
    reader.on("close", () => input.end());

    reader.read();

    // `Writable` Stream where encrypted data is written
    const output = new Writable({
      async write(chunk: Buffer, encoding, callback) {
        await stream.write(chunk);
        callback();
      },
      final(callback) {
        stream.close();
        callback();
      },
    });

    Cipher.stream.Decrypt(password, { input, output }).catch(async (error) => {
      console.error(error);
      await stream.close();
    });

    return new Response(stream.readable, { headers });
  });
```

---

#### In-memory data stream with hybrid encryption/decryption

Hybrid encryption offers an higher level of security since only the RSA Private Key owner will be able to decrypt the data.

> [!WARNING]
> Please, note that when using hybrid encryption/decryption algorithms:
>
> - an RSA keypair is required.
> - if a passphrase is set for the Private Key, please make sure to use one of the Cipher Block Chaining algorithm or `chacha20-poly1305` algorithm:
>   - aes-128-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-192-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-256-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - chacha20-poly1305 (`type` can only be `pkcs1`)

##### Keypair

```ts
import { Cipher } from "@alessiofrittoli/crypto-cipher";

const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 512 * 8, // 4096 bits
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
});

// or you can optionally set a custom passphrase
const passphrase = "custompassphrase";

const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 512 * 8, // 4096 bits
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: {
    type: "pkcs1",
    format: "pem",
    passphrase,
    cipher: Cipher.ALGORITHM.CHACHA_20_POLY,
  },
});
```

##### Encrypt

```ts
const data = "my top-secret data";
/** Store encrypted chunks for next example. */
const encryptedChunks: Buffer[] = [];

// Create a `Readable` Stream with raw data.
const input = new Readable({
  read() {
    this.push(data); // Push data to encrypt
    this.push(null); // Signal end of stream
  },
});

// Create a `Writable` Stream where encrypted data is written
const output = new Writable({
  write(chunk, encoding, callback) {
    // push written chunk to `encryptedChunks` for further usage.
    encryptedChunks.push(chunk);
    callback();
  },
});

await Cipher.stream.HybridEncrypt(keyPair.publicKey, { input, output });
```

---

##### Decrypt

```ts
/** Store decrypted chunks. */
const chunks: Buffer[] = [];
// Create a `Readable` Stream with encrypted data.
const input = Readable.from(encryptedChunks);

// Create a `Writable` Stream where decrypted data is written
const output = new Writable({
  write(chunk, encoding, callback) {
    chunks.push(chunk);
    callback();
  },
});

await Cipher.stream.HybridDecrypt(
  {
    key: keyPair.privateKey,
    passphrase, // optional passhrase (required if set while generating keypair).
  },
  { input, output }
);

console.log(Buffer.concat(chunks).toString()); // Outputs: 'my top-secret data'
```

---

#### File based data stream encryption/decryption

Nothig differs from the [In-memory data stream encryption/decryption](#in-memory-data-stream-encryptiondecryption) example, except for `input` and `output` streams which now comes directly from files reading/writing.

##### Encrypt a file

```ts
import fs from "fs";

const password = "my-very-strong-password";

// input where raw data to encrypt is read
const input = fs.createReadStream("my-very-large-top-secret-file.pdf");
// output where encrypted data is written
const output = fs.createWriteStream("my-very-large-top-secret-file.encrypted");
// encrypt
await Cipher.stream.Encrypt(password, { input, output });
```

---

##### Decrypt a file

```ts
import fs from "fs";

const password = "my-very-strong-password";

// input where encrypted data is read
const input = fs.createReadStream("my-very-large-top-secret-file.encrypted");
// output where decrypted data is written
const output = fs.createWriteStream(
  "my-very-large-top-secret-file-decrypted.pdf"
);
// decrypt
await Cipher.stream.Decrypt(password, { input, output });
```

---

#### File based data stream with hybrid encryption/decryption

Nothig differs from the [In-memory data stream with hybrid encryption/decryption](#in-memory-data-stream-with-hybrid-encryptiondecryption) example, except for `input` and `output` streams which now comes directly from files reading/writing.

> [!WARNING]
> Please, note that when using hybrid encryption/decryption algorithms:
>
> - an RSA keypair is required.
> - if a passphrase is set for the Private Key, please make sure to use one of the Cipher Block Chaining algorithm or `chacha20-poly1305` algorithm:
>   - aes-128-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-192-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - aes-256-cbc (`type` can be `pkcs1` or `pkcs8`)
>   - chacha20-poly1305 (`type` can only be `pkcs1`)

##### Keypair

```ts
import { Cipher } from "@alessiofrittoli/crypto-cipher";

const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 512 * 8, // 4096 bits
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
});

// or you can optionally set a custom passphrase
const passphrase = "custompassphrase";

const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 512 * 8, // 4096 bits
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: {
    type: "pkcs1",
    format: "pem",
    passphrase,
    cipher: Cipher.ALGORITHM.CHACHA_20_POLY,
  },
});
```

##### Encrypt a file

```ts
import fs from "fs";

// input where raw data to encrypt is read
const input = fs.createReadStream("my-very-large-top-secret-file.pdf");
// output where encrypted data is written
const output = fs.createWriteStream("my-very-large-top-secret-file.encrypted");
// encrypt
await Cipher.stream.HybridEncrypt(keyPair.publicKey, { input, output });
```

---

##### Decrypt a file

```ts
import fs from "fs";

// input where encrypted data is read
const input = fs.createReadStream("my-very-large-top-secret-file.encrypted");
// output where decrypted data is written
const output = fs.createWriteStream(
  "my-very-large-top-secret-file-decrypted.pdf"
);
// decrypt
const { decrypt } = await Cipher.stream.HybridDecrypt(
  {
    key: keyPair.privateKey,
    passphrase, // optional passhrase (required if set while generating keypair).
  },
  { input, output }
);
```

---

### Development

#### Install depenendencies

```bash
npm install
```

or using `pnpm`

```bash
pnpm i
```

#### Build the source code

Run the following command to test and build code for distribution.

```bash
pnpm build
```

#### [ESLint](https://www.npmjs.com/package/eslint)

warnings / errors check.

```bash
pnpm lint
```

#### [Jest](https://npmjs.com/package/jest)

Run all the defined test suites by running the following:

```bash
# Run tests and watch file changes.
pnpm test:watch

# Run tests in a CI environment.
pnpm test:ci
```

- See [`package.json`](./package.json) file scripts for more info.

Run tests with coverage.

An HTTP server is then started to serve coverage files from `./coverage` folder.

⚠️ You may see a blank page the first time you run this command. Simply refresh the browser to see the updates.

```bash
test:coverage:serve
```

---

### Contributing

Contributions are truly welcome!

Please refer to the [Contributing Doc](./CONTRIBUTING.md) for more information on how to start contributing to this project.

Help keep this project up to date with [GitHub Sponsor][sponsor-url].

[![GitHub Sponsor][sponsor-badge]][sponsor-url]

---

### Security

If you believe you have found a security vulnerability, we encourage you to **_responsibly disclose this and NOT open a public issue_**. We will investigate all legitimate reports. Email `security@alessiofrittoli.it` to disclose any security vulnerabilities.

### Made with ☕

<table style='display:flex;gap:20px;'>
  <tbody>
    <tr>
      <td>
        <img alt="avatar" src='https://avatars.githubusercontent.com/u/35973186' style='width:60px;border-radius:50%;object-fit:contain;'>
      </td>
      <td>
        <table style='display:flex;gap:2px;flex-direction:column;'>
          <tbody>
              <tr>
                <td>
                  <a href='https://github.com/alessiofrittoli' target='_blank' rel='noopener'>Alessio Frittoli</a>
                </td>
              </tr>
              <tr>
                <td>
                  <small>
                    <a href='https://alessiofrittoli.it' target='_blank' rel='noopener'>https://alessiofrittoli.it</a> |
                    <a href='mailto:info@alessiofrittoli.it' target='_blank' rel='noopener'>info@alessiofrittoli.it</a>
                  </small>
                </td>
              </tr>
          </tbody>
        </table>
      </td>
    </tr>
  </tbody>
</table>
