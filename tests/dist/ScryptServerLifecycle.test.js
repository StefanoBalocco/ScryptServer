import test from 'ava';
import { spawn } from 'node:child_process';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import path from 'path';
import { pathToFileURL } from 'node:url';
import { createTestConfig } from './TestConfig.js';
const serverModule = await import(path.join(import.meta.dirname, '..', '..', 'dist', 'ScryptServer.js'));
const ScryptServer = serverModule.ScryptServer;
const logFileWaitTimeoutMs = 5000;
async function waitForLogFile(filePath, timeoutMs) {
    const retryIntervalMs = 50;
    const deadline = Date.now() + timeoutMs;
    let returnValue = false;
    while (!returnValue && (Date.now() < deadline)) {
        try {
            await access(filePath);
            returnValue = true;
        }
        catch {
            await new Promise((resolve) => { setTimeout(resolve, retryIntervalMs); });
        }
    }
    return returnValue;
}
test.serial('Start: starts without throwing when certificate files are missing', async (t) => {
    const server = new ScryptServer(createTestConfig({
        port: 0,
        certificate: '/nonexistent/certificate.pem',
        certificateKey: '/nonexistent/certificateKey.pem'
    }));
    try {
        await t.notThrowsAsync(() => server.Start());
        await t.notThrowsAsync(() => server.reloadCertificates());
    }
    finally {
        await server.Stop();
    }
});
test.serial('Stop: accepts Stop when server never started', async (t) => {
    const server = new ScryptServer(createTestConfig());
    await t.notThrowsAsync(() => server.Stop());
});
test.serial('logpath: configured log file is created in an isolated child process', async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'scryptserver-'));
    try {
        const serverUrl = pathToFileURL(join(import.meta.dirname, '..', '..', 'dist', 'ScryptServer.js')).href;
        const scriptContent = [
            `import { access } from 'node:fs/promises';`,
            `import { join } from 'node:path';`,
            ``,
            `const serverUrl = ${JSON.stringify(serverUrl)};`,
            `const logDirectory = ${JSON.stringify(directory)};`,
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
        ].join('\n');
        const scriptPath = join(directory, 'logpath-test.mjs');
        await writeFile(scriptPath, scriptContent);
        const child = spawn(process.execPath, [scriptPath]);
        let childStdout = '';
        let childStderr = '';
        child.stdout.on('data', (chunk) => { childStdout += chunk.toString(); });
        child.stderr.on('data', (chunk) => { childStderr += chunk.toString(); });
        const exitCode = await new Promise((resolve, reject) => {
            child.once('error', reject);
            child.once('close', (code) => {
                if (null === code) {
                    reject(new Error('child process closed without an exit code'));
                }
                else {
                    resolve(code);
                }
            });
        });
        t.is(exitCode, 0, (childStdout + childStderr).trim());
        const logFileExists = await waitForLogFile(join(directory, 'ScryptServer.log'), logFileWaitTimeoutMs);
        t.true(logFileExists);
    }
    finally {
        await rm(directory, { recursive: true, force: true });
    }
});
test.serial('logpath: leaves no active handles in the parent process', (t) => {
    const activeHandleTypes = process._getActiveHandles().map((handle) => handle.constructor.name);
    t.deepEqual(activeHandleTypes, []);
});
