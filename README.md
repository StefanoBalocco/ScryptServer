# ScryptServer

A microservice that exposes a scrypt API server to separate computationally expensive hashing from Node.js applications.

This package includes both a **server** component (ScryptServer) and a **client** library (ScryptClient) for easy integration.

## Server

### Starting the Server

```bash
# Start the server with default configuration
npm start

# Or start with a custom configuration file
npm start -- -c /path/to/config.json
# or
npm start -- --config /path/to/config.json
```

### Configuration

The server can be configured using a JSON configuration file. By default, it uses these settings:

```json
{
  "minWorkers": 2,          // Minimum number of worker threads (default: half of CPU cores)
  "maxWorkers": 4,          // Maximum number of worker threads (default: number of CPU cores)
  "logpath": "./log",       // Directory for log files
  "ip": "127.0.0.1",        // IP address to bind
  "port": 8001,             // Port to listen on
  "certificate": null,      // Path to SSL certificate file (optional)
  "certificateKey": null    // Path to SSL certificate key file (optional)
}
```

Create a custom configuration file and pass it with the `-c` or `--config` option to override any of these defaults.

### API Endpoints

#### HASH
POST `/hash`

Hashes data using scrypt with configurable parameters.

Request body (JSON):
- `data` (string, required): The data to hash (max 2048 characters)
- `cost` (number, required): CPU/memory cost parameter (must be power of 2, range: 4096-524288)
- `blockSize` (number, required): Block size parameter (range: 1-16)
- `parallelization` (number, required): Parallelization parameter (range: 1-16)
- `saltlen` (number, required): Salt length in bytes (range: 16-47)
- `keylen` (number, required): Desired key length in bytes (range: 16-271)

Example request:
```json
{
  "data": "password123",
  "cost": 16384,
  "blockSize": 8,
  "parallelization": 1,
  "saltlen": 16,
  "keylen": 32
}
```

Example response:
```json
{
  "result": "base64-encoded-hash"
}
```

#### COMPARE
POST `/compare`

Compares data against an existing scrypt hash.

Request body (JSON):
- `data` (string, required): The data to verify
- `hash` (string, required): The base64-encoded hash to compare against

Example request:
```json
{
  "data": "password123",
  "hash": "base64-encoded-hash"
}
```

Example response:
```json
{
  "result": true
}
```

### Binary Hash Format

The scrypt implementation uses a custom binary format with versioning.

Version 2 is structured as follows:
- 1 byte: binary version (0x02)
- 1 byte: blockSize - 1 (4 bit, between 1 and 16) & parallelization - 1 (4 bit, between 1 and 16)
- 1 byte: (log2 cost) - 12 (3 bit, between 12 and 19 that's mean 4096-524288) & saltlen - 16 (5 bit, between 16 and 47)
- 1 byte: keylen - 16 (between 16 and 271)
- saltlen bytes: salt
- keylen bytes: derived key
- Total: 4 + saltlen + keylen bytes

Version 1 was:
- 1 byte: binary version (0x01)
- 2 bytes: cost (uint16, big endian)
- 1 byte: blockSize (4 bits) + parallelization (4 bits)
- 1 byte: saltlen
- 1 byte: keylen
- saltlen bytes: salt
- keylen bytes: derived key
- Total: 6 + saltlen + keylen bytes

### HTTPS Configuration

To enable HTTPS, configure the `certificate` and `certificateKey` paths in your configuration file:

```json
{
  "certificate": "/path/to/cert.pem",
  "certificateKey": "/path/to/key.pem"
}
```

### Logging and Signals

- Logs are written to `{logpath}/ScryptServer.log`
- Send SIGHUP signal to reload SSL certificates and reopen log files without restarting

## Client

The package includes a TypeScript/JavaScript client library that provides:
- Easy integration with the scrypt server
- Automatic fallback to local scrypt computation if the server is unavailable
- Connection pooling with configurable timeouts
- Full TypeScript support
- Intelligent retry mechanism with exponential backoff (new in v1.1)

### Installation

```bash
npm install scryptserver
```

### Client Usage

```typescript
import { ScryptClient } from 'scryptserver';

// Initialize the client with default settings
const client = new ScryptClient('http://localhost:8001');

// Or with custom configuration
const client = new ScryptClient(
  'http://localhost:8001',     // Server URL
  {                            // Default scrypt parameters
    cost: 16384,
    blockSize: 8,
    parallelization: 1,
    saltlen: 16,
    keylen: 32
  },
  undefined,                    // CA certificate buffer (for HTTPS)
  1                            // Max local workers for fallback
);

// Hash a password
const hashResult = await client.hash('myPassword');
if (hashResult.result) {
  console.log('Hash (base64):', hashResult.result); // string
} else {
  console.error('Error:', hashResult.error);
}

// Hash with custom parameters
const customHashResult = await client.hash('myPassword', {
  cost: 32768,
  blockSize: 8,
  parallelization: 1,
  saltlen: 18,
  keylen: 64
});

// Compare a password using base64 string
const compareResult = await client.compare('myPassword', hashResult.result);
if (compareResult.result !== undefined) {
  console.log('Match:', compareResult.result); // boolean
} else {
  console.error('Error:', compareResult.error);
}

// Clean up when done
await client.destroy();
```

### Client Configuration

The ScryptClient constructor accepts the following parameters:

- `baseUrl` (string): The URL of the scrypt server
- `defaultParams` (Partial<ScryptParams>, optional): Default scrypt parameters
    - `cost` (default: 16384): CPU/memory cost parameter
    - `blockSize` (default: 8): Block size parameter
    - `parallelization` (default: 1): Parallelization parameter
    - `saltlen` (default: 16): Salt length in bytes
    - `keylen` (default: 32): Key length in bytes
- `cacert` (Buffer, optional): CA certificate for HTTPS connections
- `maxConcurrencyFallback` (number, default: -1): Maximum worker threads for local fallback
    - `-1`: Auto-detect (uses 1/4 of CPU cores, minimum 1)
    - `0`: Disable fallback completely
    - `> 0`: Use specified number of workers

### Retry Mechanism

The client now includes an intelligent retry mechanism with exponential backoff:
- When the server fails, it marks it as offline for an increasing duration
- Initial backoff: 5 seconds
- Backoff increases by 5 seconds per consecutive failure
- Maximum backoff: 5 minutes
- The client automatically attempts local computation during server downtime
- Server availability is rechecked after the backoff period expires

### Connection Settings

The client uses the following connection timeouts:
- Connect timeout: 2000ms
- Headers timeout: 5000ms
- Body timeout: 5000ms
- Keep-alive timeout: 4000ms
- Keep-alive max timeout: 10000ms

### Fallback Mechanism

The client includes an automatic fallback mechanism:
- If the server is unavailable or returns an error, the client automatically computes the hash locally
- Local computation uses worker threads to avoid blocking the main thread
- The worker pool is created only if `maxConcurrencyFallback > 0`
- Set `maxConcurrencyFallback` to 0 to disable this feature
- During server backoff periods, fallback is used immediately without attempting server connection

### Error Handling

Both hash and compare methods return an object with either:
- `result`: The successful result (string for hash, boolean for compare)
- `error`: An error message if the operation failed

Always check for the presence of `error` before using `result`.


## Changes in v1.2.0
- **Binary format updated (version 0x02)**:
   - Extended cost range (between 2^12 to 2^19)
   - Extended keylen range (16-271)
   - Extended blockSize and parallelization range (1-16)
   - Reduced saltlen range (16-47)
   - Total size now: 4 + saltlen + keylen bytes
   - Backward compatible with version 1

## Changes in v1.1.0

- **ScryptClient constructor parameter order changed**:
   - Previous: `new ScryptClient(baseUrl, cacert, maxConcurrency, defaultParams)`
   - Current: `new ScryptClient(baseUrl, defaultParams, cacert, maxConcurrency)`

- **Hash method now returns base64 string instead of Buffer**:
   - Previous: `hash()` returned `ScryptResponse<Buffer>`
   - Current: `hash()` returns `ScryptResponse<string>` (base64 encoded)

- **Compare method simplified**:
   - Removed: `compareFromBase64()` method
   - `compare()` now only accepts base64 strings (previously accepted Buffer)

- **Binary format updated with version support**:
   - Added version byte (0x01) at the beginning
   - Changed salt from fixed 16 bytes to variable length (saltlen parameter)
   - Total size now: 6 + saltlen + keylen bytes

- **ScryptParams interface expanded**:
   - Added `saltlen` parameter (range: 16-255, default: 16)

---

Based on a my previous project (bcryptServer: https://github.com/stefanobalocco/bcryptServer).
