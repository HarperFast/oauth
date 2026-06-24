/**
 * Node ESM loader that mocks the `harper` module for unit tests.
 *
 * Mirrors the Bun preload (../../.bun/preload.js) so Node and Bun see the
 * same Resource shape under unit tests. Importing the real `harper` package
 * opens the system RocksDB at module-load time, and RocksDB does not
 * support multiple processes accessing the same database read-write — so
 * `node --test` running test files as parallel subprocesses contends for
 * the LOCK file, surfacing as a flaky `IO error: ... Resource temporarily
 * unavailable opening database` (sometimes via a downstream
 * `TypeError: Cannot read properties of undefined (reading 'localhost')`
 * unhandled rejection that the test runner reports as a failed test).
 *
 * Wired in via `--import ./test/helpers/harper-mock.mjs` in npm test
 * scripts. Once harper exposes a read-only RocksDB mode (in flight) this
 * mock can be dropped — RocksDB *does* support multi-process access in
 * read-only mode, so plugin unit tests could open the real DB read-only
 * without contention.
 */
import { register } from 'node:module';

const HARPER_MOCK_SOURCE = `
export class Resource {
	static loadAsInstance = false;
	_context = null;
	getContext() { return this._context; }
	setContext(c) { this._context = c; }
}
export class RequestTarget {}
export const logger = {
	trace() {}, debug() {}, info() {}, warn() {}, error() {}, fatal() {}, notify() {},
};
`;

const HARPER_MOCK_URL = 'harper-mock:harper';

const loaderSource = `
const HARPER_MOCK_URL = ${JSON.stringify(HARPER_MOCK_URL)};
const HARPER_MOCK_SOURCE = ${JSON.stringify(HARPER_MOCK_SOURCE)};

export async function resolve(specifier, context, nextResolve) {
	if (specifier === 'harper') {
		return { url: HARPER_MOCK_URL, format: 'module', shortCircuit: true };
	}
	return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
	if (url === HARPER_MOCK_URL) {
		return { format: 'module', source: HARPER_MOCK_SOURCE, shortCircuit: true };
	}
	return nextLoad(url, context);
}
`;

register(`data:text/javascript,${encodeURIComponent(loaderSource)}`, import.meta.url);
