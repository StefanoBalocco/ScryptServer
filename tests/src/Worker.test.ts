import test from 'ava';
import path from 'path';
import workerpool from 'workerpool';

interface ScryptParams {
	cost: number;
	blockSize: number;
	parallelization: number;
	saltlen: number;
	keylen: number;
}

const defaultParams: ScryptParams = {
	cost: 4096,
	blockSize: 8,
	parallelization: 1,
	saltlen: 16,
	keylen: 32
};

let pool: workerpool.Pool;

test.before( () => {
	pool = workerpool.pool(
		path.join( import.meta.dirname, '..', '..', 'dist', 'Worker.js' ),
		{ minWorkers: 1, maxWorkers: 2 }
	);
} );

test.after.always( async() => {
	await pool.terminate();
} );

// Hash tests

test.serial( 'hash: generates valid hash with default parameters', async( t ) => {
	const result = await pool.exec( 'hash', [ 'password123', defaultParams ] ) as string;
	t.truthy( result );
	t.is( typeof result, 'string' );
	// Verify valid base64
	const buffer = Buffer.from( result, 'base64' );
	t.truthy( buffer.length > 0 );
	// Verify binary version (0x02)
	t.is( buffer[ 0 ], 0x02 );
} );

test.serial( 'hash: generates different hashes for same password (random salt)', async( t ) => {
	const hash1 = await pool.exec( 'hash', [ 'password123', defaultParams ] ) as string;
	const hash2 = await pool.exec( 'hash', [ 'password123', defaultParams ] ) as string;
	t.not( hash1, hash2 );
} );

test.serial( 'hash: correct output length', async( t ) => {
	const params: ScryptParams = { cost: 4096, blockSize: 1, parallelization: 1, saltlen: 20, keylen: 64 };
	const result = await pool.exec( 'hash', [ 'test', params ] ) as string;
	const buffer = Buffer.from( result, 'base64' );
	// Format: 4 byte header + saltlen + keylen
	t.is( buffer.length, 4 + params.saltlen + params.keylen );
} );

test.serial( 'hash: error with empty data', async( t ) => {
	await t.throwsAsync(
		() => pool.exec( 'hash', [ '', defaultParams ] ),
		{ message: /Missing, invalid or too much data/ }
	);
} );

test.serial( 'hash: error with data too long (>2048 characters)', async( t ) => {
	const longData = 'a'.repeat( 2049 );
	await t.throwsAsync(
		() => pool.exec( 'hash', [ longData, defaultParams ] ),
		{ message: /Missing, invalid or too much data/ }
	);
} );

test.serial( 'hash: accepts data of 2048 characters', async( t ) => {
	const maxData = 'a'.repeat( 2048 );
	const result = await pool.exec( 'hash', [ maxData, defaultParams ] ) as string;
	t.truthy( result );
} );

test.serial( 'hash: error with cost too low', async( t ) => {
	const params: ScryptParams = { ...defaultParams, cost: 2048 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid cost parameter/ }
	);
} );

test.serial( 'hash: error with cost too high', async( t ) => {
	const params: ScryptParams = { ...defaultParams, cost: 1048576 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid cost parameter/ }
	);
} );

test.serial( 'hash: error with cost not power of 2', async( t ) => {
	const params: ScryptParams = { ...defaultParams, cost: 5000 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid cost.*power of 2/ }
	);
} );

test.serial( 'hash: accepts minimum cost (4096)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, cost: 4096 };
	const result = await pool.exec( 'hash', [ 'test', params ] ) as string;
	t.truthy( result );
} );

test.serial( 'hash: accepts maximum cost (524288)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, cost: 524288 };
	const result = await pool.exec( 'hash', [ 'test', params ] ) as string;
	t.truthy( result );
} );

test.serial( 'hash: error with invalid blockSize (0)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, blockSize: 0 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid blockSize/ }
	);
} );

test.serial( 'hash: error with invalid blockSize (17)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, blockSize: 17 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid blockSize/ }
	);
} );

test.serial( 'hash: accepts valid blockSize range (1-16)', async( t ) => {
	for( const blockSize of [ 1, 8, 16 ] ) {
		const params: ScryptParams = { ...defaultParams, blockSize };
		const result = await pool.exec( 'hash', [ 'test', params ] ) as string;
		t.truthy( result, `blockSize ${blockSize} should be valid` );
	}
} );

test.serial( 'hash: error with invalid parallelization (0)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, parallelization: 0 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid parallelization/ }
	);
} );

test.serial( 'hash: error with invalid parallelization (17)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, parallelization: 17 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid parallelization/ }
	);
} );

test.serial( 'hash: accepts valid parallelization range (1-16)', async( t ) => {
	for( const parallelization of [ 1, 8, 16 ] ) {
		const params: ScryptParams = { ...defaultParams, parallelization };
		const result = await pool.exec( 'hash', [ 'test', params ] ) as string;
		t.truthy( result, `parallelization ${parallelization} should be valid` );
	}
} );

test.serial( 'hash: error with saltlen too short (15)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, saltlen: 15 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid saltlen/ }
	);
} );

test.serial( 'hash: error with saltlen too long (48)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, saltlen: 48 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid saltlen/ }
	);
} );

test.serial( 'hash: accepts valid saltlen range (16-47)', async( t ) => {
	for( const saltlen of [ 16, 32, 47 ] ) {
		const params: ScryptParams = { ...defaultParams, saltlen };
		const result = await pool.exec( 'hash', [ 'test', params ] ) as string;
		t.truthy( result, `saltlen ${saltlen} should be valid` );
	}
} );

test.serial( 'hash: error with keylen too short (15)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, keylen: 15 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid keylen/ }
	);
} );

test.serial( 'hash: error with keylen too long (272)', async( t ) => {
	const params: ScryptParams = { ...defaultParams, keylen: 272 };
	await t.throwsAsync(
		() => pool.exec( 'hash', [ 'test', params ] ),
		{ message: /Invalid keylen/ }
	);
} );

test.serial( 'hash: accepts valid keylen range (16-271)', async( t ) => {
	for( const keylen of [ 16, 64, 271 ] ) {
		const params: ScryptParams = { ...defaultParams, keylen };
		const result = await pool.exec( 'hash', [ 'test', params ] ) as string;
		t.truthy( result, `keylen ${keylen} should be valid` );
	}
} );

// Compare tests

test.serial( 'compare: verifies correct password', async( t ) => {
	const password = 'mySecretPassword';
	const hash = await pool.exec( 'hash', [ password, defaultParams ] ) as string;
	const result = await pool.exec( 'compare', [ password, hash ] ) as boolean;
	t.true( result );
} );

test.serial( 'compare: rejects wrong password', async( t ) => {
	const hash = await pool.exec( 'hash', [ 'correctPassword', defaultParams ] ) as string;
	const result = await pool.exec( 'compare', [ 'wrongPassword', hash ] ) as boolean;
	t.false( result );
} );

test.serial( 'compare: works with various parameters', async( t ) => {
	const params: ScryptParams = {
		cost: 8192,
		blockSize: 4,
		parallelization: 2,
		saltlen: 24,
		keylen: 48
	};
	const password = 'testPassword';
	const hash = await pool.exec( 'hash', [ password, params ] ) as string;
	const result = await pool.exec( 'compare', [ password, hash ] ) as boolean;
	t.true( result );
} );

test.serial( 'compare: error with empty hash', async( t ) => {
	await t.throwsAsync(
		() => pool.exec( 'compare', [ 'password', '' ] ),
		{ message: /Missing or invalid hash/ }
	);
} );

test.serial( 'compare: error with corrupted hash', async( t ) => {
	await t.throwsAsync(
		() => pool.exec( 'compare', [ 'password', 'invalidbase64!!!' ] ),
		{ message: /Missing or invalid hash|Invalid hash buffer/ }
	);
} );

test.serial( 'compare: error with hash too short', async( t ) => {
	const shortHash = Buffer.from( [ 0x02, 0x00, 0x00 ] ).toString( 'base64' );
	await t.throwsAsync(
		() => pool.exec( 'compare', [ 'password', shortHash ] ),
		{ message: /Missing or invalid hash buffer/ }
	);
} );

test.serial( 'compare: error with unsupported binary version', async( t ) => {
	// Create a fake hash with version 0x03 (unsupported)
	const fakeHash = Buffer.alloc( 52 );
	fakeHash[ 0 ] = 0x03; // unsupported version
	await t.throwsAsync(
		() => pool.exec( 'compare', [ 'password', fakeHash.toString( 'base64' ) ] ),
		{ message: /Unsupported binary version/ }
	);
} );

test.serial( 'compare: error with empty data', async( t ) => {
	const hash = await pool.exec( 'hash', [ 'password', defaultParams ] ) as string;
	await t.throwsAsync(
		() => pool.exec( 'compare', [ '', hash ] ),
		{ message: /Missing, invalid or too much data/ }
	);
} );

test.serial( 'compare: error with data too long', async( t ) => {
	const hash = await pool.exec( 'hash', [ 'password', defaultParams ] ) as string;
	const longData = 'a'.repeat( 2049 );
	await t.throwsAsync(
		() => pool.exec( 'compare', [ longData, hash ] ),
		{ message: /Missing, invalid or too much data/ }
	);
} );

// Binary format encoding/decoding tests

test.serial( 'binary format: encodes parameters correctly', async( t ) => {
	const params: ScryptParams = {
		cost: 16384, // log2 = 14, stored as 14-12 = 2
		blockSize: 8, // stored as 8-1 = 7
		parallelization: 4, // stored as 4-1 = 3
		saltlen: 20, // stored as 20-16 = 4
		keylen: 32 // stored as 32-16 = 16
	};
	const hash = await pool.exec( 'hash', [ 'test', params ] ) as string;
	const buffer = Buffer.from( hash, 'base64' );

	// Byte 0: version
	t.is( buffer[ 0 ], 0x02 );

	// Byte 1: blockSize-1 (4 bit high) | parallelization-1 (4 bit low)
	t.is( buffer[ 1 ], ( 7 << 4 ) | 3 ); // 0x73

	// Byte 2: (log2(cost)-12) (3 bit high) | saltlen-16 (5 bit low)
	t.is( buffer[ 2 ], ( 2 << 5 ) | 4 ); // 0x44

	// Byte 3: keylen-16
	t.is( buffer[ 3 ], 16 );
} );

test.serial( 'binary format: decodes parameters in compare', async( t ) => {
	// Test that compare correctly decodes parameters
	// using limit values
	const params: ScryptParams = {
		cost: 8192, // minimum different from default (4096)
		blockSize: 1, // minimum different from default (8)
		parallelization: 2, // minimum different from default (1)
		saltlen: 16, // minimum
		keylen: 16 // minimum
	};
	const password = 'extremeParams';
	const hash = await pool.exec( 'hash', [ password, params ] ) as string;
	const result = await pool.exec( 'compare', [ password, hash ] ) as boolean;
	t.true( result );
} );

test.serial( 'binary format: minimum values encoded correctly', async( t ) => {
	const params: ScryptParams = {
		cost: 4096, // min, log2 = 12, stored as 0
		blockSize: 1, // min, stored as 0
		parallelization: 1, // min, stored as 0
		saltlen: 16, // min, stored as 0
		keylen: 16 // min, stored as 0
	};
	const password = 'minParams';
	const hash = await pool.exec( 'hash', [ password, params ] ) as string;
	const buffer = Buffer.from( hash, 'base64' );

	t.is( buffer[ 0 ], 0x02 );
	t.is( buffer[ 1 ], 0x00 ); // blockSize-1=0, parallelization-1=0
	t.is( buffer[ 2 ], 0x00 ); // cost shift=0, saltlen-16=0
	t.is( buffer[ 3 ], 0x00 ); // keylen-16=0

	// Verify that compare works
	const result = await pool.exec( 'compare', [ password, hash ] ) as boolean;
	t.true( result );
} );
