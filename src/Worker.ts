import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import workerpool from 'workerpool';

// Binary format:
// - 2 byte: cost (uint16, big endian)
// - 1 byte: blockSize (4 bit) + parallelization (4 bit)
// - 1 byte: keylen
// - 16 byte: salt
// - keylen byte: derived key
// Total: 20 + keylen byte

interface ScryptParams {
	cost: number,
	blockSize: number,
	parallelization: number,
	keylen: number
}

async function compare( data: string, hash: Buffer ): Promise<boolean> {
	let returnValue: boolean = false;

	if( data && ( 0 < data.length ) && ( 2048 >= data.length ) ) {
		if( Buffer.isBuffer( hash ) && 20 < hash.length ) {
			const keylen: number = hash.readUInt8( 3 );
			const expectedLength: number = 20 + keylen;
			if( expectedLength === hash.length ) {
				try {
					const blockSizeParallelization: number = hash.readUInt8( 2 );
					const cost: number = hash.readUInt16BE( 0 );
					const blockSize: number = blockSizeParallelization >> 4; // 4 high bits
					const parallelization: number = blockSizeParallelization & 0x0F; // 4 low bits
					const salt: Buffer = hash.subarray( 4, 20 );
					const storedKey: Buffer = hash.subarray( 20 );
					const derivedKey: Buffer = scryptSync(
						data,
						salt,
						keylen,
						{
							cost: cost,
							blockSize: blockSize,
							parallelization: parallelization,
							maxmem: ( 128 * cost * blockSize * parallelization * 2 )
						}
					);
					returnValue = timingSafeEqual( derivedKey, storedKey );
				} catch( error ) {
					throw ( error instanceof Error ? error : new Error( 'Derivation failed' ) );
				}
			} else {
				throw new Error( 'Invalid hash buffer length' );
			}
		} else {
			throw new Error( 'Missing or invalid hash buffer' );
		}
	} else {
		throw new Error( 'Missing, invalid or too much data' );
	}
	return returnValue;
}

async function hash( data: string, params: ScryptParams ): Promise<Buffer> {
	let returnValue: Buffer;

	if( data && ( 0 < data.length ) && ( 2048 >= data.length ) ) {
		if( ( 1023 < params.cost ) && ( 65537 > params.cost ) ) {
			// Check if cost is a power of 2
			if( 0 === ( params.cost & ( params.cost - 1 ) ) ) {
				if( ( 0 < params.blockSize ) && ( 16 > params.blockSize ) ) {
					if( ( 0 < params.parallelization ) && ( 16 > params.parallelization ) ) {
						if( ( 15 < params.keylen ) && ( 256 > params.keylen ) ) {
							try {
								const salt: Buffer = randomBytes( 16 ); // 128 bit
								const derivedKey: Buffer = scryptSync(
									data,
									salt,
									params.keylen,
									{
										cost: params.cost,
										blockSize: params.blockSize,
										parallelization: params.parallelization,
										maxmem: ( 128 * params.cost * params.blockSize * params.parallelization * 2 )
									}
								);
								if( derivedKey.length === params.keylen ) {
									returnValue = Buffer.allocUnsafe( 20 + params.keylen );
									// cost (2 byte, big endian)
									returnValue.writeUInt16BE( params.cost, 0 );
									// blockSize (4 bit) & parallelization (4 bit) in 1 byte
									returnValue.writeUInt8( ( params.blockSize << 4 ) | params.parallelization, 2 );
									// keylen (1 byte)
									returnValue.writeUInt8( params.keylen, 3 );
									// salt (16 byte)
									salt.copy( returnValue, 4 );
									// hash (keylen byte)
									derivedKey.copy( returnValue, 20 );
								} else {
									throw new Error( 'Derived key length does not match keylen' );
								}
							} catch( error ) {
								throw ( error instanceof Error ? error : new Error( 'Derivation failed' ) );
							}
						} else {
							throw new Error( 'Invalid keylen (16-255)' );
						}
					} else {
						throw new Error( 'Invalid parallelization parameter (1-15)' );
					}
				} else {
					throw new Error( 'Invalid blockSize parameter (1-15)' );
				}
			} else {
				throw new Error( 'Invalid cost (not be a power of 2)' );
			}
		} else {
			throw new Error( 'Invalid cost parameter (1024-65535)' );
		}
	} else {
		throw new Error( 'Missing, invalid or too much data' );
	}
	return returnValue;
}

workerpool.worker( {
	compare: compare,
	hash: hash
} );
