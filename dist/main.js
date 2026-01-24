import mri from 'mri';
import { readFile } from 'node:fs/promises';
import path from 'path';
import ZeptoLogger from 'zeptologger';
import { DefaultConfig } from './DefaultConfig.js';
import { ScryptServer } from './ScryptServer.js';
const _logger = ZeptoLogger.GetLogger();
let _config = DefaultConfig;
try {
    const args = mri(process.argv.slice(2), {
        alias: { c: 'config' }
    });
    if (args.config) {
        const _filename = path.resolve(args.config);
        const _userConfigData = await readFile(_filename, 'utf8');
        const _userConfig = JSON.parse(_userConfigData);
        _config = { ...DefaultConfig, ..._userConfig };
    }
    const _server = new ScryptServer(_config);
    process.on('SIGHUP', async () => {
        _server._logOpenStream();
        await _server.reloadCertificates();
    });
    process.on('SIGTERM', async () => {
        await _server.Stop();
        process.exit(0);
    });
    process.on('SIGINT', async () => {
        await _server.Stop();
        process.exit(0);
    });
    await _server.Start();
}
catch (error) {
    _logger.log(ZeptoLogger.LogLevel.CRITICAL, 'exception while starting the server: ' + (error instanceof Error ? error.message : error));
    process.exit(1);
}
