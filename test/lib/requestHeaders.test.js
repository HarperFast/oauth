/**
 * Tests for the wrapper-aware request header reader.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getRequestHeader } from '../../dist/lib/requestHeaders.js';

describe('getRequestHeader', () => {
	it('reads from a plain IncomingMessage.headers object (tests)', () => {
		assert.equal(getRequestHeader({ cookie: 'a=1' }, 'cookie'), 'a=1');
		assert.equal(getRequestHeader({ referer: '/x' }, 'Referer'), '/x', 'name is case-insensitive');
	});

	it("reads from Harper's runtime `.asObject` headers wrapper", () => {
		const wrapper = { asObject: { cookie: 'a=1', authorization: 'Bearer t' } };
		assert.equal(getRequestHeader(wrapper, 'cookie'), 'a=1');
		assert.equal(getRequestHeader(wrapper, 'authorization'), 'Bearer t');
	});

	it('reads from a Web `Headers` object via .get()', () => {
		const headers = new Headers({ cookie: 'a=1' });
		assert.equal(getRequestHeader(headers, 'cookie'), 'a=1');
	});

	it('returns the first value when a header is multi-valued', () => {
		assert.equal(getRequestHeader({ 'x-forwarded-for': ['1.1.1.1', '2.2.2.2'] }, 'x-forwarded-for'), '1.1.1.1');
	});

	it('returns undefined for missing headers or missing container', () => {
		assert.equal(getRequestHeader(undefined, 'cookie'), undefined);
		assert.equal(getRequestHeader(null, 'cookie'), undefined);
		assert.equal(getRequestHeader({}, 'cookie'), undefined);
		assert.equal(getRequestHeader({ asObject: {} }, 'cookie'), undefined);
	});
});
