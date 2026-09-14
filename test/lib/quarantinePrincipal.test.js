import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	makeQuarantinePrincipal,
	isQuarantinePrincipal,
	redactQuarantinePrincipal,
} from '../../dist/lib/quarantinePrincipal.js';

describe('quarantinePrincipal', () => {
	it('makeQuarantinePrincipal embeds the claim and a 16-hex random suffix', () => {
		const principal = makeQuarantinePrincipal('attacker@example.com');
		assert.match(principal, /^unverified:attacker@example\.com#[0-9a-f]{16}$/);
	});

	it('isQuarantinePrincipal recognizes a minted principal and rejects others', () => {
		assert.equal(isQuarantinePrincipal(makeQuarantinePrincipal('claim')), true);
		assert.equal(isQuarantinePrincipal('admin@example.com'), false);
		assert.equal(isQuarantinePrincipal('unverified:claim#not-hex'), false);
		assert.equal(isQuarantinePrincipal(42), false);
	});

	it('redactQuarantinePrincipal replaces the random suffix so it never reaches a log line', () => {
		const principal = makeQuarantinePrincipal('attacker@example.com');
		const redacted = redactQuarantinePrincipal(principal);

		assert.equal(redacted, 'unverified:attacker@example.com#<redacted>');
		assert.doesNotMatch(redacted, /#[0-9a-f]{16}$/);
	});

	it('redactQuarantinePrincipal leaves non-quarantine values unchanged', () => {
		assert.equal(redactQuarantinePrincipal('admin@example.com'), 'admin@example.com');
	});
});
