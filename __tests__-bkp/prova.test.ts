import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import { Cipher } from '@/index'
import { Readable, Transform } from 'stream'
import { readUint16BE, writeUint16BE } from '@alessiofrittoli/crypto-buffer'


const getPaths = ( file: string, basepath: string ) => {
	const parsed		= path.parse( file )
	const inputpath		= path.join( basepath, `${ parsed.name }${ parsed.ext }` )
	const encryptedPath	= path.join( basepath, `${ parsed.name }-encrypted` )
	const decryptedPath	= path.join( basepath, `${ parsed.name }-decrypted${ parsed.ext }` )

	return { basepath, inputpath, encryptedPath, decryptedPath }
}

// const dataToEncrypt	= 'my TOP-SECRET message'+ crypto.randomBytes( 512 ).toString( 'base64' )
const dataToEncrypt	= 'my TOP-SECRET message'


describe( 'test', () => {

	let basepath: string,
		inputpath: string,
		encryptedPath: string,
		decryptedPath: string;

	beforeAll( () => {
		const tempPath	= fs.mkdtempSync( 'file-stream-hybrid-new' )
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

	
	const rsaBytes	= 512
	const keyPair	= crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: rsaBytes * 8, // 4096 bits
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs1', format: 'pem' },
	} )

	it( 'encrypt', async () => {
	


		// input where raw data to encrypt is read
		const input = fs.createReadStream( inputpath )
		// output where encrypted data is written
		const output = fs.createWriteStream( encryptedPath )

		await Cipher.NewStreamHybridEncrypt( keyPair.publicKey, {
			input, output
		} )

	} )


	it( 'decrypt', async () => {

		// console.log( 'encrypted filesize', fs.statSync( encryptedPath ).size )
		
		// input where encrypted data is read
		// const input = fs.createReadStream( encryptedPath, { highWaterMark: 512 / 3 } )
		const input = fs.createReadStream( encryptedPath, { highWaterMark: 256 } )
		// output where decrypted data is written
		const output = fs.createWriteStream( decryptedPath )


		try {

			await Cipher.NewStreamHybridDecrypt( keyPair.privateKey, {
				input, output
			} )



			// let readBytes = 0
			// restInput.pipe( new Transform( {
			// 	transform( chunk: Buffer, encoding, callback ) {
			// 		readBytes += chunk.length
			// 		console.log( 'final piped receivd', readBytes )
			// 		this.push( chunk, encoding )
			// 		return callback()
			// 	},
			// } ) )
			

			// await new Promise( resolve => {
			// 	input.on( 'end', resolve )
			// } )
		} catch ( error ) {
			console.error( 'Caught error', error );
		}

		return


		// let KeyLength: number = 0
		// let KeyLengthRead = false
		// let bytesRead	= 0
		// let resolved	= false

		// // extractKeyLength( input )

		// input
		// 	.pipe( new Transform( {
		// 		async transform( chunk: Buffer, encoding, callback )
		// 		{
		// 			// console.log( 'KeyLength', KeyLength )
					
		// 			// if ( KeyLength === 0 ) {
		// 			// 	KeyLengthRead = true
		// 			// 	KeyLength = readUint16BE( chunk.subarray( 0, 2 ) )
		// 			// }

		// 			// console.log( 'reading chunk', chunk )
					
		// 			console.log( 'received chunk', chunk.length )
					
		// 			this.push( chunk, encoding )

		// 			return callback()
		// 		},
		// 		final( callback )
		// 		{
		// 			console.log( 'final' )
					
		// 			// if ( KeyIV.length < keyLength ) {
		// 			// 	return callback(
		// 			// 		new Error( 'The extracted KeyIV length is less than the expected length.' )
		// 			// 	)
		// 			// }
		// 			return callback()
		// 		},
		// 	} ) )
		// 	.pipe( new Transform( {
		// 		transform( chunk, encoding, callback ) {
		// 			console.log( '2-received chunk', chunk.length )
					
		// 			this.push( chunk, encoding )

		// 			return callback()
		// 		},
		// 	} ) )

		
		// await new Promise( resolve => {
		// 	input.on( 'end', resolve )
		// } )

		// // console.log( 'first 2 bytes', await input.read( 2 ) )
		
		// // await new Promise( ( resolve, reject ) => {

		// // 	let KeyLength: number = 0
		// // 	let KeyLengthRead = false
		// // 	let bytesRead	= 0
		// // 	let resolved	= false

		// // 	input.on( 'end', resolve )

		// // 	input.pipe( new Transform( {
		// // 		async transform( chunk: Buffer, encoding, callback )
		// // 		{
		// // 			console.log( 'KeyLength', KeyLength )
					
		// // 			if ( KeyLength === 0 ) {
		// // 				KeyLengthRead = true
		// // 				KeyLength = readUint16BE( chunk.subarray( 0, 2 ) )
		// // 			}

		// // 			console.log( 'reading chunk', chunk )
					
		// // 			this.push( chunk, encoding )
		// // 			return callback()
		// // 		},
		// // 		final( callback )
		// // 		{
		// // 			// if ( KeyIV.length < keyLength ) {
		// // 			// 	return callback(
		// // 			// 		new Error( 'The extracted KeyIV length is less than the expected length.' )
		// // 			// 	)
		// // 			// }
		// // 			return callback()
		// // 		},
		// // 	} ) )

		// // } )

	} )

} )