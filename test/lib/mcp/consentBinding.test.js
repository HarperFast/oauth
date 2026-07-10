/**
 * Tests for the CIMD consent browser-binding helpers.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	CONSENT_COOKIE_NAME,
	buildConsentCookie,
	consentNonceMatches,
	generateConsentNonce,
	hashConsentNonce,
	readConsentNonce,
} from '../../../dist/lib/mcp/consentBinding.js';

describe('consentBinding', () => {
	it('generates unique url-safe nonces', () => {
		const a = generateConsentNonce();
		const b = generateConsentNonce();
		assert.notEqual(a, b);
		assert.match(a, /^[A-Za-z0-9_-]{40,}$/);
	});

	it('buildConsentCookie sets the security attributes', () => {
		const cookie = buildConsentCookie('nonce-value');
		assert.match(cookie, new RegExp(`^${CONSENT_COOKIE_NAME}=nonce-value; `));
		assert.match(cookie, /HttpOnly/);
		assert.match(cookie, /Secure/);
		assert.match(cookie, /SameSite=Lax/);
		assert.match(cookie, /Path=\//);
		assert.match(cookie, /Max-Age=\d+/);
	});

	it('readConsentNonce finds the cookie among others and trims whitespace', () => {
		const request = { headers: { cookie: `a=1;  ${CONSENT_COOKIE_NAME}=the-nonce ; b=2` } };
		assert.equal(readConsentNonce(request), 'the-nonce');
	});

	it('readConsentNonce returns undefined when absent or malformed', () => {
		assert.equal(readConsentNonce(undefined), undefined);
		assert.equal(readConsentNonce({ headers: {} }), undefined);
		assert.equal(readConsentNonce({ headers: { cookie: '' } }), undefined);
		assert.equal(readConsentNonce({ headers: { cookie: 'other=1' } }), undefined);
		assert.equal(readConsentNonce({ headers: { cookie: 'no-equals-sign' } }), undefined);
	});

	it('readConsentNonce does not match cookie names that merely contain the name', () => {
		const request = { headers: { cookie: `x_${CONSENT_COOKIE_NAME}=wrong` } };
		assert.equal(readConsentNonce(request), undefined);
	});

	it('consentNonceMatches round-trips and rejects mismatches', () => {
		const nonce = generateConsentNonce();
		const hash = hashConsentNonce(nonce);
		assert.equal(consentNonceMatches(nonce, hash), true);
		assert.equal(consentNonceMatches('other-nonce', hash), false);
		assert.equal(consentNonceMatches(undefined, hash), false);
		assert.equal(consentNonceMatches(nonce, undefined), false);
		assert.equal(consentNonceMatches(nonce, 'not-a-hash'), false);
	});
});
