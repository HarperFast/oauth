/**
 * Cross-runtime mock function helper (Node.js and Bun)
 *
 * In Node.js, uses mock.fn() from 'node:test'
 * In Bun, uses mock() directly from 'bun:test'
 */

import { mock as nodeMock } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Cache for the runtime-specific mock function
let mockFn;

/**
 * Creates a mock function that works in both Node.js and Bun test environments
 *
 * @param {Function} [implementation] - Optional function implementation
 * @returns {Function} Mock function with .mock property for call tracking
 */
export function createMockFn(implementation) {
	if (!mockFn) {
		// Check if we're in Node.js (has mock.fn)
		if (typeof nodeMock?.fn === 'function') {
			mockFn = nodeMock.fn.bind(nodeMock);
		} else {
			// Must be Bun - use bun:test and wrap to match Node.js API
			const { mock: bunMock } = require('bun:test');
			mockFn = (impl) => {
				const bunFn = bunMock(impl);
				// Wrap to convert Bun's call structure to Node's structure
				const wrappedFn = function (...args) {
					return bunFn(...args);
				};
				Object.defineProperty(wrappedFn, 'mock', {
					get() {
						const bunMockData = bunFn.mock;
						return {
							calls: bunMockData.calls.map((args) => ({ arguments: args })),
							callCount: bunMockData.calls.length,
						};
					},
				});
				return wrappedFn;
			};
		}
	}

	return mockFn(implementation);
}

/**
 * Creates a mock logger with trackable methods
 */
export function createMockLogger() {
	return {
		debug: createMockFn(),
		error: createMockFn(),
		info: createMockFn(),
		warn: createMockFn(),
	};
}
