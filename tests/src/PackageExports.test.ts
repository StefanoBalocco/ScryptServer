import test from 'ava';

const packageName: string = '@stefanobalocco/scryptserver';

interface ScryptClientModule {
	default: unknown;
	ScryptClient: unknown;
	ScryptServer?: unknown;
	DefaultConfig?: unknown;
}

// Computed string import so TypeScript never resolves the package name at compile time
const rootModule: ScryptClientModule = await import( packageName ) as ScryptClientModule;

test( 'package root: default export equals the named ScryptClient export', ( t ) => {
	t.is( rootModule.default, rootModule.ScryptClient );
} );

test( 'package root: has no ScryptServer export', ( t ) => {
	t.falsy( rootModule.ScryptServer );
} );

test( 'package root: has no DefaultConfig export', ( t ) => {
	t.falsy( rootModule.DefaultConfig );
} );

test( 'package: ScryptServer subpath is not exported', async( t ) => {
	const subpath: string = packageName + '/ScryptServer';
	await t.throwsAsync(
		async() => { await import( subpath ); },
		{ code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' }
	);
} );

test( 'package: DefaultConfig subpath is not exported', async( t ) => {
	const subpath: string = packageName + '/DefaultConfig';
	await t.throwsAsync(
		async() => { await import( subpath ); },
		{ code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' }
	);
} );
