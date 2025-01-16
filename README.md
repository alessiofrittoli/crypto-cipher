# Crypto Cipher 🔐

[![NPM Latest Version][version-badge]][npm-url] [![Coverage Status][coverage-badge]][coverage-url] [![NPM Monthly Downloads][downloads-badge]][npm-url] [![Dependencies][deps-badge]][deps-url]

[version-badge]: https://img.shields.io/npm/v/%40alessiofrittoli%2Fcrypto-cipher
[npm-url]: https://npmjs.org/package/%40alessiofrittoli%2Fcrypto-cipher
[coverage-badge]: https://coveralls.io/repos/github/alessiofrittoli/crypto-cipher/badge.svg
[coverage-url]: https://coveralls.io/github/alessiofrittoli/crypto-cipher
[downloads-badge]: https://img.shields.io/npm/dm/%40alessiofrittoli%2Fcrypto-cipher.svg
[deps-badge]: https://img.shields.io/librariesio/release/npm/%40alessiofrittoli%2Fcrypto-cipher
[deps-url]: https://libraries.io/npm/%40alessiofrittoli%2Fcrypto-cipher

## Node.js Cipher cryptograph utility library

### Table of Contents

- [Getting started](#getting-started)
- [Key features](#key-features)
- [API Reference](#api-reference)
  - [Importing the library](#importing-the-library)
  - [Constants](#constants)
  - [Methods](#methods)
    - [`Cipher.encrypt()`](#cipherencrypt)
    - [`Cipher.decrypt()`](#cipherdecrypt)
    - [`Cipher.streamEncrypt()`](#cipherstreamencrypt)
    - [`Cipher.streamDecrypt()`](#cipherstreamencrypt)
    - [`Cipher.hybridEncrypt()`](#cipherhybridencrypt)
    - [`Cipher.hybridDecrypt()`](#cipherhybriddecrypt)
  - [Types](#types)
- [Examples](#examples)
  - [In-memory data buffer encryption/decryption](#in-memory-data-buffer-encryptiondecryption)
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
- Robust support for encrypting and decrypting streams (in-memory and file based), with seamless handling of key/IV extraction.
- Hybrid encryption methods for combining symmetric and asymmetric cryptography.

#### Options Management

- A solid options resolver mechanism ensures consistent handling of defaults and constraints.

#### Security Considerations

- Random `salt` and `IV` generation.
- Authenticated encryption modes with proper `authTag` and `Additional Authenticated Data` handling.

#### Readable and Modular

- Separation of concerns with clear method responsibilities.
- Comprehensive JSDoc comments enhance maintainability and readability.

---

### API Reference

#### Constants

##### `SALT_LENGTH`

Defines the minimum, maximum, and default lengths for salt.

<details>
<summary>Properties</summary>

| Property   | Value |
|------------|-------|
| `min`      | 16    |
| `max`      | 64    |
| `default`  | 32    |

</details>

---

##### `IV_LENGTH`

Defines the minimum, maximum, and default lengths for initialization vectors (IV).

<details>
<summary>Properties</summary>

| Property   | Value |
|------------|-------|
| `min`      | 8     |
| `max`      | 32    |
| `default`  | 16    |

</details>

---

##### `AUTH_TAG_LENGTH`

Defines the minimum, maximum, and default lengths for authentication tags.

<details>
<summary>Properties</summary>

| Property   | Value |
|------------|-------|
| `min`      | 4     |
| `max`      | 16    |
| `default`  | 16    |

</details>

---

##### `AAD_LENGTH`

Defines the minimum, maximum, and default lengths for additional authenticated data (AAD).

<details>
<summary>Properties</summary>

| Property   | Value |
|------------|-------|
| `min`      | 16    |
| `max`      | 4096  |
| `default`  | 32    |

</details>

---

##### `DEFAULT_ALGORITHM`

Specifies default AES algorithms for buffer and stream operations.

<details>
<summary>Properties</summary>

| Operation  | Algorithm    |
|------------|--------------|
| `buffer`   | `aes-256-gcm` |
| `stream`   | `aes-256-cbc` |

</details>

---

##### `ALGORITHMS`

Supported AES algorithms:

<details>
<summary>Properties</summary>

- `aes-128-gcm`
- `aes-192-gcm`
- `aes-256-gcm`
- `aes-128-ccm`
- `aes-192-ccm`
- `aes-256-ccm`
- `aes-128-ocb`
- `aes-192-ocb`
- `aes-256-ocb`
- `aes-128-cbc`
- `aes-192-cbc`
- `aes-256-cbc`
- `chacha20-poly1305`

</details>

---

#### Methods

##### `Cipher.encrypt()`

Encrypts an in-memory data buffer.

⚠️ This is not suitable for large data.
Use [`Cipher.streamEncrypt()`](#cipherstreamencrypt) or [`Cipher.hybridEncrypt()`](#cipherhybridencrypt) methods for large data encryption.

<details>

<summary>Parameters</summary>

| Name     | Type                    | Description                             |
|----------|-------------------------|-----------------------------------------|
| `data`   | `CoerceToUint8ArrayInput` | Data to encrypt.                        |
| `secret` | `CoerceToUint8ArrayInput` | Secret key for encryption.              |
| `options`| `Cph.Options`           | (Optional) Additional encryption options.|

</details>

---

<details>

<summary>Returns</summary>

Type: `Buffer`

- The encrypted result buffer.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Options`](#cphoptionst) for more informations about additional encryption options.
- See [In-memory data buffer encryption/decryption](#in-memory-data-buffer-encryptiondecryption) examples.

---

##### `Cipher.decrypt()`

Decrypts an in-memory data buffer.

⚠️ This is not suitable for large data.
Use [`Cipher.streamDecrypt()`](#cipherstreamdecrypt) or [`Cipher.hybridDecrypt()`](#cipherhybriddecrypt) methods for large data decryption.

<details>

<summary>Parameters</summary>

| Name     | Type                    | Description                             |
|----------|-------------------------|-----------------------------------------|
| `data`   | `CoerceToUint8ArrayInput` | Data to decrypt.                        |
| `secret` | `CoerceToUint8ArrayInput` | Secret key for decryption.              |
| `options`| `Cph.Options`           | (Optional) Decryption options (must match encryption).|

</details>

---

<details>

<summary>Returns</summary>

Type: `Buffer`

- The decrypted result buffer.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Options`](#cphoptionst) for more informations about additional decryption options.
- See [In-memory data buffer encryption/decryption](#in-memory-data-buffer-encryptiondecryption) examples.

---

##### `Cipher.streamEncrypt()`

Encrypts a `Readable` stream to a `Writable` stream.

<details>

<summary>Parameters</summary>

| Name      | Type                              | Description                           |
|-----------|-----------------------------------|---------------------------------------|
| `secret`  | `CoerceToUint8ArrayInput`         | Secret key for encryption.            |
| `options` | `Cph.Stream.Symmetric.EncryptOptions` | Stream encryption options.        |

</details>

---

<details>

<summary>Returns</summary>

Type: `Promise<void>`

- A new Promise that resolves when the stream encryption is complete.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Stream.Symmetric.EncryptOptions`](#cphstreamsymmetricencryptoptions) for more informations about additional encryption options.
- See [In-memory data stream encryption/decryption](#in-memory-data-stream-encryptiondecryption) examples.
- See [File based data stream encryption/decryption](#file-based-data-stream-encryptiondecryption) examples.

---

##### `Cipher.streamDecrypt()`

Decrypts a `Readable` stream to a `Writable` stream.

<details>

<summary>Parameters</summary>

| Name      | Type                              | Description                           |
|-----------|-----------------------------------|---------------------------------------|
| `secret`  | `CoerceToUint8ArrayInput`         | Secret key for decryption.            |
| `options` | `Cph.Stream.Symmetric.DecryptOptions` | Stream decryption options.            |

</details>

---

<details>

<summary>Returns</summary>

Type: `Promise<void>`

- A new Promise that resolves when the stream decryption is complete.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Stream.Symmetric.DecryptOptions`](#cphstreamsymmetricdecryptoptions) for more informations about additional decryption options.
- See [In-memory data stream encryption/decryption](#in-memory-data-stream-encryptiondecryption) examples.
- See [File based data stream encryption/decryption](#file-based-data-stream-encryptiondecryption) examples.

---

##### `Cipher.hybridEncrypt()`

Encrypts a stream using hybrid encryption (symmetric + RSA).

<details>

<summary>Parameters</summary>

| Name        | Type                              | Description                           |
|-------------|-----------------------------------|---------------------------------------|
| `secret`    | `CoerceToUint8ArrayInput`         | Symmetric secret key.                 |
| `publicKey` | `crypto.RsaPublicKey \| crypto.KeyLike` | RSA public key used to encrypt the generated symmetric key. |
| `options`   | `Cph.Stream.Hybrid.EncryptOptions` | Stream encryption options.        |

</details>

---

<details>

<summary>Returns</summary>

Type: `Promise<void>`

- A new Promise that resolves when hybrid encryption is complete.

</details>

---

- See [`CoerceToUint8ArrayInput`](#coercetouint8arrayinput) for more informations about supported input data types.
- See [`Cph.Stream.Hybrid.EncryptOptions`](#cphstreamhybridencryptoptions) for more informations about additional encryption options.
- See [In-memory data stream with hybrid encryption/decryption](#in-memory-data-stream-with-hybrid-encryptiondecryption) examples.
- See [File based data stream with hybrid encryption/decryption](#file-based-data-stream-with-hybrid-encryptiondecryption) examples.

---

##### `Cipher.hybridDecrypt()`

Decrypts a stream using hybrid decryption (symmetric + RSA).

<details>

<summary>Parameters</summary>

| Name         | Type                              | Description                           |
|--------------|-----------------------------------|---------------------------------------|
| `privateKey` | `crypto.RsaPrivateKey \| crypto.KeyLike` | RSA private key for used to decrpyt the encrypted symmetric key. |
| `options`    | `Cph.Stream.Hybrid.DecryptOptions` | Stream decryption options.           |

</details>

---

<details>

<summary>Returns</summary>

Type: `Promise<void>`

- A new Promise that resolves when hybrid decryption is complete.

</details>

---

- See [`Cph.Stream.Hybrid.DecryptOptions`](#cphstreamhybriddecryptoptions) for more informations about decryption options.
- See [In-memory data stream with hybrid encryption/decryption](#in-memory-data-stream-with-hybrid-encryptiondecryption) examples.
- See [File based data stream with hybrid encryption/decryption](#file-based-data-stream-with-hybrid-encryptiondecryption) examples.

---

#### Types

##### `CoerceToUint8ArrayInput`

This module supports different input data types and it uses the [`coerceToUint8Array`](https://npmjs.com/package/@alessiofrittoli/crypto-buffer#coercetouint8array) utility function from [`@alessiofrittoli/crypto-buffer`](https://npmjs.com/package/@alessiofrittoli/crypto-buffer) to convert it to a `Uint8Array`.

- See [`coerceToUint8Array`](https://npmjs.com/package/@alessiofrittoli/crypto-buffer#coercetouint8array) for more informations about the supported input types.

---

##### `CBCTypes`

Cipher CBC algorithm types.

---

##### `AesAlgorithm`

Supported AES algorithm types.

---

##### `Cph.Options<T>`

Common options in encryption/decryption processes.

<details>

<summary>Type parameters</summary>

| Parameter   | Default        | Description |
|-------------|----------------|-------------|
| `T`         | `AesAlgorithm` | Accepted algorithm in `Cph.Options`. This is usefull to constraint specifc algorithms. |

</details>

---

<details>

<summary>Properties</summary>

| Property    | Type     | Default       | Description |
|-------------|----------|---------------|-------------|
| `algorithm` | `T`      | `aes-256-gcm \| aes-256-cbc` | Accepted algorithms. |
| `salt`      | `number` | `32` | The `salt` length in bytes. Minimum: `16`, Maximum: `64`. |
| `iv`        | `number` | `16` | The Initialization Vector length in bytes. Minimum: `8`, Maximum: `32`. |
| `authTag`   | `number` | `16` | The `authTag` length in bytes. Minimum: `4`, Maximum: `16`. |
| `aad`       | `CoerceToUint8ArrayInput` | - | Custom Additional Authenticated Data. `aadLength` is then automatically resolved. If not provided, a random AAD is generated with a max length of `aadLength`. |
| `aadLength` | `number` | `32` | The auto generated AAD length in bytes. Minimum: `16`, Maximum: `128`. |

</details>

---

##### `Cph.Stream.Symmetric.EncryptOptions`

Stream symmetric encryption options.

- Extends [`Cph.Options<Cph.CBCTypes>`](#cphoptionst).

<details>

<summary>Properties</summary>

| Property | Type     | Description |
|----------|----------|-------------|
| `input`  | `Readable` | The `Readable` Stream from where raw data to encrypt is read. |
| `output` | `Writable` | The `Writable` Stream where encrypted data is written. |

</details>

---

##### `Cph.Stream.Symmetric.DecryptOptions`

Stream symmetric decryption options.

- Extends [`Cph.Stream.Symmetric.EncryptOptions`](#cphstreamsymmetricencryptoptions).

<details>

<summary>Properties</summary>

| Property | Type     | Description |
|----------|----------|-------------|
| `input`  | `Readable` | The `Readable` Stream from where encrypted data is read. |
| `output` | `Writable` | The `Writable` Stream where decrypted data is written. |

</details>

---

##### `Cph.Stream.Hybrid.EncryptOptions`

Stream hybrid encryption options.

- Alias for [`Cph.Stream.Symmetric.EncryptOptions`](#cphstreamsymmetricencryptoptions)

---

##### `Cph.Stream.Hybrid.DecryptOptions`

Stream hybrid decryption options.

- Extends [`Cph.Stream.Symmetric.DecryptOptions`](#cphstreamsymmetricdecryptoptions).

<details>

<summary>Properties</summary>

| Property       | Type     | Description |
|----------------|----------|-------------|
| `rsaKeyLength` | `number` | The RSA key length in bytes used while encrypting data. This is used to properly extract the encrypted Cipher Key and Initialization Vector from the encrypted data. |

</details>

---

### Examples

#### Importing the library

```ts
import { Cipher } from '@alessiofrittoli/crypto-cipher'
import type { Cph as CipherTypes } from '@alessiofrittoli/crypto-cipher/types'
```

#### In-memory data buffer encryption/decryption

The simpliest way to encrypt/decrypt in-memory data buffers.

```ts
// encrypt
const data      = 'my top-secret data'
const password  = 'my-very-strong-password'

const encrypted = Cipher.encrypt( data, password )

// decrypt
const decrypted = Cipher.decrypt( encrypted, password )
console.log( decrypted ) // Outputs: my top-secret data
```

---

#### In-memory data stream encryption/decryption

The in-memory data stream comes pretty handy when, for example, we need to stream encrypted data within a Server Response or to decrypt stream data from a Server Response.

##### Streaming

```ts
// /api/stream-encrypt

import { Readable, Writable } from 'stream'

const routeHandler = () => {
  const data      = 'my top-secret data'
  const password  = 'my-very-strong-password'
  const stream    = new TransformStream()
  const writer    = stream.writable.getWriter()
  
  // Create a `Readable` Stream with raw data.
  const input = new Readable( {
    read()
    {
      this.push( data )
      this.push( null ) // Signal end of stream
    },
  } )
      
  // `Writable` Stream where encrypted data is written
  const output = new Writable( {
    write( chunk, encoding, callback )
    {
      writer.write( chunk )
      callback()
    },
    final( callback )
    {
      writer.close()
      callback()
    }
  } )
  
  Cipher.streamEncrypt( password, { input, output } )
  
  return (
    // encrypted stream
    new Response( stream.readable )
  )
}
```

##### Decrypting received stream

```ts
// /api/stream-decrypt

import { Transform, Writable } from 'stream'
import { StreamReader } from '@alessiofrittoli/stream-reader'

const password = 'my-very-strong-password'

const routeHandler = () => (
  fetch( '/api/stream-encrypt' )
    .then( response => {

      if ( ! response.body ) {
        return (
          new Respone( null, { status: 400 } )
        )
      }

      const stream  = new TransformStream()
      const writer  = stream.writable.getWriter()
      const reader  = new StreamReader( response.body )
      const input   = new Transform()
      
      reader.read()
      

      reader.on( 'read', chunk => {
        input.push( chunk )
      } )
      reader.on( 'close', () => {
        input.push( null )
      } )

      const output = new Writable( {
        write( chunk, encoding, callback )
        {
          writer.write( chunk )
          callback()
        },
        final( callback ) {
          writer.close()
          callback()
        },
      } )
      
      Cipher.streamDecrypt( password, { input, output } )
      
      return (
        // decrypted stream
        new Response( stream.readable )
      )
      
    } )
)
```

---

#### In-memory data stream with hybrid encryption/decryption

Hybrid encryption offers an higher level of security by encrypting the generated symmetric key with asymmetric RSA keys.

##### Keypair

```ts
const password  = 'my-very-strong-password'

/** RSA modulus length is required for proper key extraction during decryption process. */
const rsaKeyLength = 512 // bytes
const keyPair = crypto.generateKeyPairSync( 'rsa', {
  modulusLength       : rsaKeyLength * 8, // 4096 bits
  publicKeyEncoding   : { type: 'spki', format: 'pem' },
  privateKeyEncoding  : { type: 'pkcs1', format: 'pem' },
} )


// or you can optionally set a custom passphrase
const keyPair = crypto.generateKeyPairSync( 'rsa', {
  modulusLength       : rsaKeyLength * 8, // 4096 bits
  publicKeyEncoding   : { type: 'spki', format: 'pem' },
  privateKeyEncoding  : { type: 'pkcs1', format: 'pem', passphrase: password, cipher: 'aes-256-cbc' },
} )
```

##### Encrypt

```ts
const data = 'my top-secret data'
/** Store encrypted chunks for next example. */
const encryptedChunks: Buffer[] = []

// Create a `Readable` Stream with raw data.
const input = new Readable( {
  read()
  {
    this.push( data ) // Push data to encrypt
    this.push( null ) // Signal end of stream
  },
} )
    
// Create a `Writable` Stream where encrypted data is written
const output = new Writable( {
  write( chunk, encoding, callback )
  {
    // push written chunk to `encryptedChunks` for further usage.
    encryptedChunks.push( chunk )
    callback()
  }
} )

await Cipher.hybridEncrypt( password, {
  key       : keyPair.publicKey,
  padding   : crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash  : 'SHA-256',
}, { input, output } )

```

---

##### Decrypt

```ts
/** Store decrypted chunks. */
const chunks: Buffer[] = []
// Create a `Readable` Stream with encrypted data.
const input = new Readable( {
  read()
  {
    this.push( Buffer.concat( encryptedChunks ) ) // Push data to decrypt
    this.push( null ) // Signal end of stream
  },
} )

// Create a `Writable` Stream where decrypted data is written
const output = new Writable( {
  write( chunk, encoding, callback )
  {
    chunks.push( chunk )
    callback()
  },
} )

await Cipher.hybridDecrypt(
  {
    key       : keyPair.privateKey,
    passphrase: password, // optional passhrase (required if set while generating keypair).
    padding   : crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash  : 'SHA-256',
  }, { input, output, rsaKeyLength }
)

console.log( Buffer.concat( chunks ).toString() ) // Outputs: 'my top-secret data'
```

---

#### File based data stream encryption/decryption

Nothig differs from the [In-memory data stream encryption/decryption](#in-memory-data-stream-encryptiondecryption) example, except for `input` and `output` streams which now comes directly from files reading/writing.

##### Encrypt a file

```ts
import fs from 'fs'

const password = 'my-very-strong-password'

// input where raw data to encrypt is read
const input = fs.createReadStream( 'my-very-large-top-secret-file.pdf' )
// output where encrypted data is written
const output = fs.createWriteStream( 'my-very-large-top-secret-file.encrypted' )
// encrypt
await Cipher.streamEncrypt( password, { input, output } )
```

---

##### Decrypt a file

```ts
import fs from 'fs'

const password = 'my-very-strong-password'

// input where encrypted data is read
const input = fs.createReadStream( 'my-very-large-top-secret-file.encrypted' )
// output where decrypted data is written
const output = fs.createWriteStream( 'my-very-large-top-secret-file-decrypted.pdf' )
// decrypt
await Cipher.streamDecrypt( password, { input, output } )
```

---

#### File based data stream with hybrid encryption/decryption

Nothig differs from the [In-memory data stream with hybrid encryption/decryption](#in-memory-data-stream-with-hybrid-encryptiondecryption) example, except for `input` and `output` streams which now comes directly from files reading/writing.

##### Keypair

```ts
const password  = 'my-very-strong-password'

/** RSA modulus length is required for proper key extraction during decryption process. */
const rsaKeyLength = 512 // bytes
const keyPair = crypto.generateKeyPairSync( 'rsa', {
  modulusLength       : rsaKeyLength * 8, // 4096 bits
  publicKeyEncoding   : { type: 'spki', format: 'pem' },
  privateKeyEncoding  : { type: 'pkcs1', format: 'pem' },
} )


// or you can optionally set a custom passphrase
const keyPair = crypto.generateKeyPairSync( 'rsa', {
  modulusLength       : rsaKeyLength * 8, // 4096 bits
  publicKeyEncoding   : { type: 'spki', format: 'pem' },
  privateKeyEncoding  : { type: 'pkcs1', format: 'pem', passphrase: password, cipher: 'aes-256-cbc' },
} )
```

##### Encrypt a file

```ts
import fs from 'fs'

const password = 'my-very-strong-password'

// input where raw data to encrypt is read
const input = fs.createReadStream( 'my-very-large-top-secret-file.pdf' )
// output where encrypted data is written
const output = fs.createWriteStream( 'my-very-large-top-secret-file.encrypted' )
// encrypt
await Cipher.hybridEncrypt( password, {
  key       : keyPair.publicKey,
  padding   : crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash  : 'SHA-256',
}, { input, output } )
```

---

##### Decrypt a file

```ts
import fs from 'fs'

const password = 'my-very-strong-password'

// input where encrypted data is read
const input = fs.createReadStream( 'my-very-large-top-secret-file.encrypted' )
// output where decrypted data is written
const output = fs.createWriteStream( 'my-very-large-top-secret-file-decrypted.pdf' )
// decrypt
await Cipher.hybridDecrypt(
  {
    key       : keyPair.privateKey,
    passphrase: password, // optional passhrase (required if set while generating keypair).
    padding   : crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash  : 'SHA-256',
  }, { input, output, rsaKeyLength }
)
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

You can eventually run specific suits like so:

```bash
pnpm test:buffer-in-memory
pnpm test:file-symmetric
pnpm test:file-hybrid
pnpm test:stream-symmetric
pnpm test:stream-hybrid
pnpm test:misc
```

Run tests with coverage.

An HTTP server is then started to serve coverage files from `./coverage` folder.

⚠️ You may see a blank page the first time you run this command. Simply refresh the browser to see the updates.

```bash
test:coverage:serve
```

---

### Contributing

Contributions are truly welcome!\
Please refer to the [Contributing Doc](./CONTRIBUTING.md) for more information on how to start contributing to this project.

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
