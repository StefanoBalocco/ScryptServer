import test from 'ava';
import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import path from 'path';
import { pathToFileURL } from 'node:url';
import { createTestConfig } from './TestConfig.js';

type TestConfig = ReturnType<typeof createTestConfig>;

interface ScryptServerInstance {
	Start: () => Promise<void>;
	Stop: () => Promise<void>;
	reloadCertificates: () => Promise<void>;
}

type ScryptServerConstructor = new ( config: TestConfig ) => ScryptServerInstance;

const serverModule: { ScryptServer: ScryptServerConstructor } = await import( path.join( import.meta.dirname, '..', '..', 'dist', 'ScryptServer.js' ) );
const ScryptServer: ScryptServerConstructor = serverModule.ScryptServer;

const logFileWaitTimeoutMs: number = 5000;

async function waitForLogFile( filePath: string, timeoutMs: number ): Promise<boolean> {
	const retryIntervalMs: number = 50;
	const deadline: number = Date.now() + timeoutMs;
	let returnValue: boolean = false;
	while( !returnValue && ( Date.now() < deadline ) ) {
		try {
			await access( filePath );
			returnValue = true;
		} catch {
			await new Promise<void>( ( resolve ) => { setTimeout( resolve, retryIntervalMs ); } );
		}
	}
	return returnValue;
}

// Lifecycle tests

test.serial( 'Start: starts without throwing when certificate files are missing', async( t ) => {
	const server: ScryptServerInstance = new ScryptServer( createTestConfig( {
		port: 0,
		certificate: '/nonexistent/certificate.pem',
		certificateKey: '/nonexistent/certificateKey.pem'
	} ) );
	try {
		await t.notThrowsAsync( () => server.Start() );
		await t.notThrowsAsync( () => server.reloadCertificates() );
	} finally {
		await server.Stop();
	}
} );

test.serial( 'Stop: accepts Stop when server never started', async( t ) => {
	const server: ScryptServerInstance = new ScryptServer( createTestConfig() );
	await t.notThrowsAsync( () => server.Stop() );
} );

test.serial( 'logpath: configured log file is created in an isolated child process', async( t ) => {
	const directory: string = await mkdtemp( join( tmpdir(), 'scryptserver-' ) );
	try {
		const serverUrl: string = pathToFileURL( join( import.meta.dirname, '..', '..', 'dist', 'ScryptServer.js' ) ).href;
		const scriptContent: string = [
			`import { access } from 'node:fs/promises';`,
			`import { join } from 'node:path';`,
			``,
			`const serverUrl = ${JSON.stringify( serverUrl )};`,
			`const logDirectory = ${JSON.stringify( directory )};`,
			`const logFilePath = join( logDirectory, 'ScryptServer.log' );`,
			`const waitTimeoutMs = 5000;`,
			``,
			`async function waitForLogFile( timeoutMs ) {`,
			`	const retryIntervalMs = 50;`,
			`	const deadline = Date.now() + timeoutMs;`,
			`	let returnValue = false;`,
			`	while( !returnValue && ( Date.now() < deadline ) ) {`,
			`		try {`,
			`			await access( logFilePath );`,
			`			returnValue = true;`,
			`		} catch {`,
			`			await new Promise( ( resolve ) => { setTimeout( resolve, retryIntervalMs ); } );`,
			`		}`,
			`	}`,
			`	return returnValue;`,
			`}`,
			``,
			`const module = await import( serverUrl );`,
			`const server = new module.ScryptServer( {`,
			`	minWorkers: 1,`,
			`	maxWorkers: 1,`,
			`	logpath: logDirectory,`,
			`	ip: '127.0.0.1',`,
			`	port: 0,`,
			`	certificate: undefined,`,
			`	certificateKey: undefined`,
			`} );`,
			`await server.Stop();`,
			`process.exitCode = ( await waitForLogFile( waitTimeoutMs ) ) ? 0 : 1;`
		].join( '\n' );
		const scriptPath: string = join( directory, 'logpath-test.mjs' );
		await writeFile( scriptPath, scriptContent );
		const child: ChildProcessWithoutNullStreams = spawn( process.execPath, [ scriptPath ] );
		let childStdout: string = '';
		let childStderr: string = '';
		child.stdout.on( 'data', ( chunk: Buffer ) => { childStdout += chunk.toString(); } );
		child.stderr.on( 'data', ( chunk: Buffer ) => { childStderr += chunk.toString(); } );
		const exitCode: number = await new Promise<number>( ( resolve, reject ) => {
			child.once( 'error', reject );
			child.once( 'close', ( code: number | null ) => {
				if( null === code ) {
					reject( new Error( 'child process closed without an exit code' ) );
				} else {
					resolve( code );
				}
			} );
		} );
		t.is( exitCode, 0, ( childStdout + childStderr ).trim() );
		const logFileExists: boolean = await waitForLogFile( join( directory, 'ScryptServer.log' ), logFileWaitTimeoutMs );
		t.true( logFileExists );
	} finally {
		await rm( directory, { recursive: true, force: true } );
	}
} );

test.serial( 'logpath: leaves no active handles in the parent process', ( t ) => {
	interface ActiveHandle {
		constructor: { name: string };
	}
	interface ActiveHandlesProcess extends NodeJS.Process {
		_getActiveHandles: () => ActiveHandle[];
	}
	const activeHandleTypes: string[] = ( process as unknown as ActiveHandlesProcess )._getActiveHandles().map( ( handle: ActiveHandle ) => handle.constructor.name );
	t.deepEqual( activeHandleTypes, [] );
} );
