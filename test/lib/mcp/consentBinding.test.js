/**
 * Tests for the CIMD consent browser-binding helpers (per-flow __Host- cookie).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	buildConsentCookie,
	consentNonceMatches,
	generateConsentFlowId,
	generateConsentNonce,
	hashConsentNonce,
	readConsentNonce,
} from '../../../dist/lib/mcp/consentBinding.js';

describe('consentBinding', () => {
	it('generates unique url-safe flow ids and nonces', () => {
		assert.notEqual(generateConsentFlowId(), generateConsentFlowId());
		assert.notEqual(generateConsentNonce(), generateConsentNonce());
		assert.match(generateConsentFlowId(), /^[A-Za-z0-9_-]+$/);
		assert.match(generateConsentNonce(), /^[A-Za-z0-9_-]{40,}$/);
	});

	it('buildConsentCookie uses a __Host- per-flow name and required attributes', () => {
		const cookie = buildConsentCookie('flow123', 'nonce-value');
		assert.match(cookie, /^__Host-mcp_consent_flow123=nonce-value; /);
		assert.match(cookie, /Secure/);
		assert.match(cookie, /HttpOnly/);
		assert.match(cookie, /SameSite=Lax/);
		assert.match(cookie, /Path=\//);
		assert.match(cookie, /Max-Age=\d+/);
		// __Host- forbids a Domain attribute (that's what blocks sibling injection).
		assert.doesNotMatch(cookie, /Domain=/i);
	});

	it('readConsentNonce reads the per-flow cookie among others', () => {
		const request = { headers: { cookie: `a=1; __Host-mcp_consent_flowA=the-nonce ; b=2` } };
		assert.equal(readConsentNonce(request, 'flowA'), 'the-nonce');
	});

	it('readConsentNonce is flow-scoped — a different flow id does not match', () => {
		const request = { headers: { cookie: `__Host-mcp_consent_flowA=nonceA` } };
		assert.equal(readConsentNonce(request, 'flowB'), undefined);
		assert.equal(readConsentNonce(request, undefined), undefined);
	});

	it('concurrent flows keep independent cookies', () => {
		const request = {
			headers: { cookie: `__Host-mcp_consent_flowA=nonceA; __Host-mcp_consent_flowB=nonceB` },
		};
		assert.equal(readConsentNonce(request, 'flowA'), 'nonceA');
		assert.equal(readConsentNonce(request, 'flowB'), 'nonceB');
	});

	it('readConsentNonce returns undefined when absent or malformed', () => {
		assert.equal(readConsentNonce(undefined, 'f'), undefined);
		assert.equal(readConsentNonce({ headers: {} }, 'f'), undefined);
		assert.equal(readConsentNonce({ headers: { cookie: '' } }, 'f'), undefined);
		assert.equal(readConsentNonce({ headers: { cookie: 'other=1' } }, 'f'), undefined);
		assert.equal(readConsentNonce({ headers: { cookie: 'no-equals-sign' } }, 'f'), undefined);
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
