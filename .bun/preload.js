/**
 * Bun test setup file
 * This runs before any tests and sets up the environment for Harper mocks
 */

import { mock } from 'bun:test';

// Mock the harper module to prevent initialization errors in Bun
// Harper's threadServer.js tries to call database() functions during module init
// which fail in test environment
//
// This mock Resource class provides enough functionality for OAuthResource to extend
// and for tests to work properly
const CREDENTIAL_REJECTION = Symbol('harper.bearerValidator.credentialRejection');
function markCredentialRejection(error) {
	if (!error || typeof error !== 'object') {
		throw new TypeError('markCredentialRejection expects an Error or object');
	}
	error[CREDENTIAL_REJECTION] = true;
	return error;
}
function credentialRejectionError(message = 'Invalid bearer credential', statusCode = 401) {
	const error = new Error(message);
	error.statusCode = statusCode;
	return markCredentialRejection(error);
}
function isCredentialRejection(error) {
	return Boolean(error && typeof error === 'object' && error[CREDENTIAL_REJECTION] === true);
}

mock.module('harper', () => {
	return {
		Resource: class Resource {
			static loadAsInstance = false;

			// Context storage for request handling
			_context = null;

			getContext() {
				return this._context;
			}

			setContext(context) {
				this._context = context;
			}
		},
		logger: {
			trace() {},
			debug() {},
			info() {},
			warn() {},
			error() {},
			fatal() {},
			notify() {},
		},
		markCredentialRejection,
		credentialRejectionError,
		isCredentialRejection,
	};
});
