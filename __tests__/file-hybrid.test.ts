import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import { Cipher } from '@/index'
import { bufferEquals } from '@alessiofrittoli/crypto-buffer'


const getPaths = ( file: string, basepath: string ) => {
	const parsed		= path.parse( file )
	const inputpath		= path.join( basepath, `${ parsed.name }${ parsed.ext }` )
	const encryptedPath	= path.join( basepath, `${ parsed.name }-encrypted` )
	const decryptedPath	= path.join( basepath, `${ parsed.name }-decrypted${ parsed.ext }` )

	return { basepath, inputpath, encryptedPath, decryptedPath }
}


describe( 'Cipher - In-Memory Stream Hybrid Encryption/Decryption', () => {

	const dataToEncrypt	= 'my TOP-SECRET message'
	const password		= 'verystrong-password'

	const rsaBytes	= 512
	const keyPair	= crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: rsaBytes * 8, // 4096 bits
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase: password, cipher: 'aes-256-cbc' }
	} )

	let basepath: string,
		inputpath: string,
		encryptedPath: string,
		decryptedPath: string;

	beforeAll( () => {
		const tempPath	= fs.mkdtempSync( 'file-stream-hybrid' )
		const paths		= getPaths( 'file.txt', tempPath )
		basepath		= paths.basepath
		inputpath		= paths.inputpath
		encryptedPath	= paths.encryptedPath
		decryptedPath	= paths.decryptedPath

		fs.writeFileSync( inputpath, dataToEncrypt )
	} )

	afterAll( () => {
		fs.rmSync( basepath, { recursive: true } )
	} )


	it( 'encrypts a file based stream', async () => {

		// input where raw data to encrypt is read
		const input = fs.createReadStream( inputpath )
		// output where encrypted data is written
		const output = fs.createWriteStream( encryptedPath )
		// encrypt
		const { encrypt } = Cipher.hybridStreamEncrypt( password, {
			key			: keyPair.publicKey,
			padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash	: 'SHA-256',
		}, { input, output } )

		await encrypt()

		const encrypted = fs.readFileSync( encryptedPath )
		
		expect( bufferEquals( encrypted, Buffer.from( dataToEncrypt ) ) )
			.not.toBe( true )
		
	} )

	
	it( 'decrypts a file based stream', async () => {

		// input where encrypted data is read
		const input = fs.createReadStream( encryptedPath )
		// output where decrypted data is written
		const output = fs.createWriteStream( decryptedPath )
		// decrypt
		const { decrypt } = await Cipher.hybridStreamDecrypt(
			{
				key			: keyPair.privateKey,
				passphrase	: password,
				padding		: crypto.constants.RSA_PKCS1_OAEP_PADDING,
				oaepHash	: 'SHA-256',
			}, { input, output, rsaKeyLength: rsaBytes }
		)
		
		await decrypt()

		const decrypted = fs.readFileSync( decryptedPath )
		
		expect( bufferEquals( decrypted, Buffer.from( dataToEncrypt ) ) )
			.toBe( true )
	
	} )

} )