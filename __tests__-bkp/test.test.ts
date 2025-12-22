import fs from "fs"
import path from "path"
import { Transform } from "stream"

it( '', async () => {

	const input = fs.createReadStream( path.resolve( process.cwd(), '__tests__', 'file-symmetric.test.ts' ), { highWaterMark: 50 } )

	input
		.pipe( new Transform( {
			transform( chunk: Buffer, encoding, callback ) {
				
				console.log( `transform 1 read chunk size ${ chunk.length }` )
				
				this.push( Buffer.from( 'Ciao lello.' ), encoding )
				// callback()
			},
		} ) )
	input.pipe( new Transform( {
			transform( chunk: Buffer, encoding, callback ) {
				
				console.log( `transform 2 read chunk size ${ chunk.length }` )

				console.log( chunk.toString() )
				

				this.push( chunk, encoding )
				callback()

			},
		} ) )

	await new Promise( resolve => {
		input.on( 'end', resolve )
	} )



} )