import fs from 'fs'
import path from 'path'
import { Cipher } from '@/index'
import { bufferEquals } from '@alessiofrittoli/crypto-buffer'


const getPaths = ( file: string, basepath: string ) => {
	const parsed		= path.parse( file )
	const inputpath		= path.join( basepath, `${ parsed.name }${ parsed.ext }` )
	const encryptedPath	= path.join( basepath, `${ parsed.name }-encrypted` )
	const decryptedPath	= path.join( basepath, `${ parsed.name }-decrypted${ parsed.ext }` )

	return { basepath, inputpath, encryptedPath, decryptedPath }
}


describe( 'Cipher - File Based Stream Symmetric Encryption/Decryption', () => {
	
	const dataToEncrypt	= 'my TOP-SECRET message'
	const password		= 'verystrong-password'

	let basepath: string,
		inputpath: string,
		encryptedPath: string,
		decryptedPath: string;

	beforeAll( () => {
		const tempPath	= fs.mkdtempSync( 'file-stream-symmetric' )
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

	
	it( 'encrypts a file based stream with Cipher Symmetric Key', async () => {
		// input where raw data to encrypt is read
		const input = fs.createReadStream( inputpath )
		// output where encrypted data is written
		const output = fs.createWriteStream( encryptedPath )
		// encrypt
		await Cipher.streamEncrypt( password, { input, output } )

		const encrypted = fs.readFileSync( encryptedPath )
		
		expect( bufferEquals( encrypted, Buffer.from( dataToEncrypt ) ) )
			.not.toBe( true )
	} )


	it( 'decrypts a file based stream with Cipher Symmetric Key', async () => {
		// input where encrypted data is read
		const input = fs.createReadStream( encryptedPath )
		// output where decrypted data is written
		const output = fs.createWriteStream( decryptedPath )
		// decrypt
		await Cipher.streamDecrypt( password, { input, output } )

		const decrypted = fs.readFileSync( decryptedPath )
		
		expect( bufferEquals( decrypted, Buffer.from( dataToEncrypt ) ) )
			.toBe( true )
	} )
	
} )
