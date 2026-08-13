/**
 * Tests for allowsGrant's legacy-default semantics: an absent grant_types
 * field means exactly ['authorization_code', 'refresh_token'] — not "any
 * grant" (gemini review finding on #200).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { allowsGrant } from '../../../dist/lib/mcp/clientValidator.js';

describe('allowsGrant legacy default', () => {
	it('absent grant_types allows exactly the legacy default set', () => {
		assert.equal(allowsGrant({}, 'authorization_code'), true);
		assert.equal(allowsGrant({}, 'refresh_token'), true);
	});

	it('absent grant_types does NOT allow grants outside the default set', () => {
		assert.equal(allowsGrant({}, 'client_credentials'), false);
		assert.equal(allowsGrant({}, 'urn:ietf:params:oauth:grant-type:jwt-bearer'), false);
	});

	it('explicit empty array allows nothing', () => {
		assert.equal(allowsGrant({ grant_types: [] }, 'authorization_code'), false);
		assert.equal(allowsGrant({ grant_types: [] }, 'refresh_token'), false);
	});
});
