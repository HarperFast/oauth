/**
 * Node ESM loader that mocks the `harper` module for unit tests.
 *
 * Mirrors the Bun preload (../../.bun/preload.js) so Node and Bun see the
 * same Resource shape under unit tests. Importing the real `harper` package
 * eagerly opens RocksDB (regressed in harper 5.0.7's `dist/resources/
 * databases.js` line 113 — open() became an instance method that opens
 * synchronously). With multiple test-file subprocesses or any other process
 * holding the system DB lock, the eager open fails and surfaces an async
 * "Cannot read properties of undefined (reading 'localhost')" rejection that
 * the Node test runner reports as a flaky test failure.
 *
 * Wired in via `--import ./test/helpers/harper-mock.mjs` in npm test
 * scripts. Removing this once harper provides a lazy / opt-in DB init
 * mode is the right long-term fix.
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
