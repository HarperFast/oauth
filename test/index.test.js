/**
 * Tests for main OAuth plugin exports
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Mock Harper's Resource class for testing
global.Resource = class {
	constructor() {}
	static loadAsInstance = true;
};

import { handleApplication } from '../dist/index.js';

describe('OAuth Plugin Main Exports', () => {
	describe('Module exports', () => {
		it('should export handleApplication function', () => {
			assert.ok(handleApplication);
			assert.equal(typeof handleApplication, 'function');
			assert.equal(handleApplication.name, 'handleApplication');
		});
	});

	describe('handleApplication', () => {
		it('should be an async function', () => {
			// Check that handleApplication returns a promise
			assert.equal(handleApplication.constructor.name, 'AsyncFunction');
		});
	});
});
