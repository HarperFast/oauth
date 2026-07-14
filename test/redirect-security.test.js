/**
 * Tests for redirect parameter security and sanitization
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { sanitizeRedirect, resolveHookRedirect } from '../dist/lib/handlers.js';

describe('Redirect Parameter Security', () => {
	it('should sanitize absolute URLs to relative paths', () => {
		const testCases = [
			{
				input: 'https://evil.com/phishing',
				expected: '/phishing',
				description: 'absolute HTTPS URL',
			},
			{
				input: 'http://attacker.com/steal?token=abc',
				expected: '/steal?token=abc',
				description: 'absolute HTTP URL with query',
			},
			{
				input: '//evil.com/phishing',
				expected: '/phishing',
				description: 'protocol-relative URL',
			},
		];

		for (const { input, expected, description } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(
				sanitized,
				expected,
				`Failed to sanitize ${description}: ${input} -> ${sanitized} (expected ${expected})`
			);
		}
	});

	it('should preserve relative paths unchanged', () => {
		const testCases = ['/dashboard', '/app/settings', '/users/123', '/'];

		for (const input of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, input, `Relative path should be preserved: ${input}`);
		}
	});

	it('should preserve query parameters in relative paths', () => {
		const testCases = [
			{
				input: '/dashboard?view=analytics',
				expected: '/dashboard?view=analytics',
			},
			{
				input: '/search?q=test&page=2',
				expected: '/search?q=test&page=2',
			},
		];

		for (const { input, expected } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, expected, `Query params should be preserved: ${input}`);
		}
	});

	it('should preserve URL fragments (hashes) in relative paths', () => {
		const testCases = [
			{
				input: '/app#dashboard',
				expected: '/app#dashboard',
			},
			{
				input: '/docs#section-2',
				expected: '/docs#section-2',
			},
			{
				input: '/#welcome',
				expected: '/#welcome',
			},
		];

		for (const { input, expected } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, expected, `URL fragment should be preserved: ${input}`);
		}
	});

	it('should preserve query params and fragments together', () => {
		const testCases = [
			{
				input: '/app?user=123#settings',
				expected: '/app?user=123#settings',
			},
			{
				input: '/search?q=test#results',
				expected: '/search?q=test#results',
			},
		];

		for (const { input, expected } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, expected, `Query and fragment should be preserved: ${input}`);
		}
	});

	it('should strip protocol and host from absolute URLs', () => {
		const testCases = [
			{
				input: 'https://evil.com/phishing#steal',
				expected: '/phishing#steal',
				description: 'strips protocol and host but keeps path and fragment',
			},
			{
				input: 'http://attacker.com:8080/steal?token=abc#hash',
				expected: '/steal?token=abc#hash',
				description: 'strips protocol, host, and port but keeps path, query, and fragment',
			},
		];

		for (const { input, expected, description } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, expected, description);
		}
	});

	it('should handle encoded characters in redirect paths', () => {
		const testCases = [
			{
				input: '/app%23dashboard',
				expected: '/app%23dashboard', // URL constructor preserves % encoding in pathname
			},
			{
				input: '/search?q=hello%20world',
				expected: '/search?q=hello%20world', // Query params preserve encoding
			},
			{
				input: '/path with spaces',
				expected: '/path%20with%20spaces', // Spaces get encoded
			},
		];

		for (const { input, expected } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, expected, `Encoded characters: ${input}`);
		}
	});

	it('should handle edge cases safely', () => {
		const testCases = [
			{
				input: '',
				expected: '/',
				description: 'empty string',
			},
			{
				input: '/',
				expected: '/',
				description: 'root path',
			},
			{
				input: '#fragment',
				expected: '/#fragment',
				description: 'fragment only',
			},
			{
				input: '?query=1',
				expected: '/?query=1',
				description: 'query only',
			},
		];

		for (const { input, expected, description } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, expected, description);
		}
	});

	it('should handle dangerous protocol injections', () => {
		const testCases = [
			{
				input: 'javascript:alert(1)',
				expected: '/',
				description: 'javascript: protocol should be blocked',
			},
			{
				input: 'data:text/html,<script>alert(1)</script>',
				expected: '/',
				description: 'data: URI should be blocked',
			},
			{
				input: 'vbscript:msgbox(1)',
				expected: '/',
				description: 'vbscript: protocol should be blocked',
			},
			{
				input: 'file:///etc/passwd',
				expected: '/',
				description: 'file: protocol should be blocked',
			},
		];

		for (const { input, expected, description } of testCases) {
			const sanitized = sanitizeRedirect(input);

			assert.strictEqual(sanitized, expected, description);
		}
	});
});

describe('Hook Redirect Resolution (#174)', () => {
	it('should pass through absolute http(s) URLs (hook is trusted app code)', () => {
		assert.strictEqual(
			resolveHookRedirect('https://accounts.example.com/onboard?step=1'),
			'https://accounts.example.com/onboard?step=1'
		);
		assert.strictEqual(resolveHookRedirect('http://localhost:9926/finish'), 'http://localhost:9926/finish');
	});

	it('should keep relative paths', () => {
		assert.strictEqual(resolveHookRedirect('/denied'), '/denied');
		assert.strictEqual(resolveHookRedirect('/onboard?step=1#top'), '/onboard?step=1#top');
	});

	it('should block dangerous protocols', () => {
		const testCases = [
			'javascript:alert(1)',
			'data:text/html,<script>alert(1)</script>',
			'vbscript:msgbox(1)',
			'file:///etc/passwd',
		];
		for (const input of testCases) {
			assert.strictEqual(resolveHookRedirect(input), '/', input);
		}
	});

	it('should reduce protocol-relative URLs to their path', () => {
		assert.strictEqual(resolveHookRedirect('//evil.com/phish'), '/phish');
	});

	it('should root bare relative paths and fall back to / for unparseable input', () => {
		assert.strictEqual(resolveHookRedirect('finish/setup'), '/finish/setup');
		assert.strictEqual(resolveHookRedirect('http://'), '/');
	});

	it('should strip embedded CR/LF via WHATWG normalization (no header injection)', () => {
		assert.strictEqual(
			resolveHookRedirect('https://accounts.example.com/a\r\nSet-Cookie: x=y'),
			'https://accounts.example.com/aSet-Cookie:%20x=y'
		);
		assert.ok(!resolveHookRedirect('https://x.example.com/a\r\nb').includes('\r'));
		assert.ok(!resolveHookRedirect('https://x.example.com/a\r\nb').includes('\n'));
	});

	it('should neutralize scheme/host obfuscations (pinning WHATWG parser behavior)', () => {
		// Backslash treated as slash by the parser → protocol-relative → path-only
		assert.strictEqual(resolveHookRedirect('/\\evil.com/phish'), '/phish');
		// Leading whitespace is stripped before scheme detection
		assert.strictEqual(resolveHookRedirect(' javascript:alert(1)'), '/');
	});
});
