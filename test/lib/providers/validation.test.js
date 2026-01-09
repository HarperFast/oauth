/**
 * Comprehensive Security Tests for Validation Module
 *
 * Tests all security validation functions to ensure SSRF, XSS, and injection
 * attacks are properly blocked.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	validateDomainSafety,
	validateDomainAllowlist,
	validateEmailDomain,
	validateTenantId,
	sanitizeTenantName,
	validateAzureTenantId,
} from '../../../dist/lib/providers/validation.js';

describe('validateDomainSafety - SSRF Protection', () => {
	describe('Private IP blocking', () => {
		it('blocks 10.x.x.x (private class A)', () => {
			assert.throws(() => validateDomainSafety('10.0.0.1', 'Test'), /private IP/);
			assert.throws(() => validateDomainSafety('10.255.255.255', 'Test'), /private IP/);
		});

		it('blocks 192.168.x.x (private class C)', () => {
			assert.throws(() => validateDomainSafety('192.168.0.1', 'Test'), /private IP/);
			assert.throws(() => validateDomainSafety('192.168.255.255', 'Test'), /private IP/);
		});

		it('blocks 172.16-31.x.x (private class B)', () => {
			assert.throws(() => validateDomainSafety('172.16.0.1', 'Test'), /private IP/);
			assert.throws(() => validateDomainSafety('172.31.255.255', 'Test'), /private IP/);
		});

		it('blocks 127.x.x.x (loopback)', () => {
			assert.throws(() => validateDomainSafety('127.0.0.1', 'Test'), /private IP/);
			assert.throws(() => validateDomainSafety('127.0.0.255', 'Test'), /private IP/);
		});

		it('allows 172.15.x.x and 172.32.x.x (not in private range)', () => {
			// These are outside the 172.16-31 private range
			const result1 = validateDomainSafety('172.15.0.1', 'Test');
			const result2 = validateDomainSafety('172.32.0.1', 'Test');
			assert.ok(result1);
			assert.ok(result2);
		});
	});

	describe('AWS metadata endpoint blocking', () => {
		it('blocks 169.254.169.254 (AWS metadata)', () => {
			assert.throws(() => validateDomainSafety('169.254.169.254', 'Test'), /private IP/);
		});

		it('blocks all 169.254.x.x addresses', () => {
			assert.throws(() => validateDomainSafety('169.254.0.1', 'Test'), /private IP/);
			assert.throws(() => validateDomainSafety('169.254.255.255', 'Test'), /private IP/);
		});
	});

	describe('Localhost blocking', () => {
		it('blocks localhost', () => {
			assert.throws(() => validateDomainSafety('localhost', 'Test'), /localhost/);
		});

		it('blocks localhost with protocol', () => {
			assert.throws(() => validateDomainSafety('http://localhost', 'Test'), /localhost/);
		});
	});

	describe('IPv6 private address blocking', () => {
		it('blocks ::1 (IPv6 loopback)', () => {
			assert.throws(() => validateDomainSafety('::1', 'Test'), /private IP/);
		});

		it('blocks fe80:: (IPv6 link-local)', () => {
			assert.throws(() => validateDomainSafety('fe80::1', 'Test'), /private IP/);
			assert.throws(() => validateDomainSafety('FE80::1', 'Test'), /private IP/); // Case insensitive
		});
	});

	describe('Protocol validation', () => {
		it('blocks file:// protocol', () => {
			assert.throws(() => validateDomainSafety('file:///etc/passwd', 'Test'), /Protocol must be/);
		});

		it('blocks ftp:// protocol', () => {
			assert.throws(() => validateDomainSafety('ftp://example.com', 'Test'), /Protocol must be/);
		});

		it('blocks javascript: protocol', () => {
			assert.throws(() => validateDomainSafety('javascript:alert(1)', 'Test'), /Expected format/);
		});

		it('blocks data: protocol', () => {
			assert.throws(() => validateDomainSafety('data:text/html,<script>alert(1)</script>', 'Test'), /Expected format/);
		});

		it('allows http://', () => {
			const result = validateDomainSafety('http://example.com', 'Test');
			assert.equal(result, 'example.com');
		});

		it('allows https://', () => {
			const result = validateDomainSafety('https://example.com', 'Test');
			assert.equal(result, 'example.com');
		});

		it('allows domain without protocol (defaults to https)', () => {
			const result = validateDomainSafety('example.com', 'Test');
			assert.equal(result, 'example.com');
		});
	});

	describe('Valid domains', () => {
		it('accepts valid public domains', () => {
			assert.equal(validateDomainSafety('example.okta.com', 'Test'), 'example.okta.com');
			assert.equal(validateDomainSafety('tenant.auth0.com', 'Test'), 'tenant.auth0.com');
			assert.equal(validateDomainSafety('login.microsoftonline.com', 'Test'), 'login.microsoftonline.com');
		});

		it('accepts domains with ports', () => {
			const result = validateDomainSafety('example.com:8080', 'Test');
			assert.equal(result, 'example.com');
		});

		it('accepts subdomains', () => {
			assert.equal(validateDomainSafety('dev.example.okta.com', 'Test'), 'dev.example.okta.com');
		});
	});

	describe('Error handling', () => {
		it('throws on empty string', () => {
			assert.throws(() => validateDomainSafety('', 'Test'), /requires domain/);
		});

		it('throws on malformed URL', () => {
			assert.throws(() => validateDomainSafety('not a url!@#$', 'Test'), /Invalid.*domain/);
		});

		it('includes provider name in error messages', () => {
			try {
				validateDomainSafety('', 'Okta');
				assert.fail('Should have thrown');
			} catch (error) {
				assert.match(error.message, /Okta/);
			}
		});
	});
});

describe('validateDomainAllowlist', () => {
	it('accepts domain matching allowlist', () => {
		assert.doesNotThrow(() => validateDomainAllowlist('example.okta.com', ['.okta.com'], 'Okta'));
	});

	it('accepts domain with exact match (without leading dot)', () => {
		assert.doesNotThrow(() => validateDomainAllowlist('okta.com', ['.okta.com'], 'Okta'));
	});

	it('rejects domain not in allowlist', () => {
		assert.throws(() => validateDomainAllowlist('example.auth0.com', ['.okta.com'], 'Okta'), /Must be one of/);
	});

	it('checks multiple allowed suffixes', () => {
		const allowed = ['.okta.com', '.okta-emea.com', '.oktapreview.com'];
		assert.doesNotThrow(() => validateDomainAllowlist('dev.okta-emea.com', allowed, 'Okta'));
		assert.doesNotThrow(() => validateDomainAllowlist('test.oktapreview.com', allowed, 'Okta'));
	});

	it('rejects subdomain that looks similar but is not in allowlist', () => {
		// example.okta.com.evil.com should NOT match .okta.com
		assert.throws(() => validateDomainAllowlist('okta.com.evil.com', ['.okta.com'], 'Okta'), /Must be one of/);
	});
});

describe('validateEmailDomain', () => {
	describe('Injection attack prevention', () => {
		it('blocks CRLF injection (\\r\\n)', () => {
			assert.throws(() => validateEmailDomain('example.com\r\n'), /invalid characters/);
			assert.throws(() => validateEmailDomain('exam\rple.com'), /invalid characters/);
			assert.throws(() => validateEmailDomain('exam\nple.com'), /invalid characters/);
		});

		it('blocks null byte injection', () => {
			assert.throws(() => validateEmailDomain('example.com\0'), /invalid characters/);
		});

		it('blocks control characters', () => {
			assert.throws(() => validateEmailDomain('example\x00.com'), /invalid characters/);
			assert.throws(() => validateEmailDomain('example\x1F.com'), /invalid characters/);
			assert.throws(() => validateEmailDomain('example\x7F.com'), /invalid characters/);
		});
	});

	describe('Format validation', () => {
		it('accepts valid domains', () => {
			assert.doesNotThrow(() => validateEmailDomain('example.com'));
			assert.doesNotThrow(() => validateEmailDomain('subdomain.example.com'));
			assert.doesNotThrow(() => validateEmailDomain('my-company.co.uk'));
		});

		it('rejects domains without TLD', () => {
			assert.throws(() => validateEmailDomain('example'), /valid domain format/);
		});

		it('rejects domains with double dots', () => {
			assert.throws(() => validateEmailDomain('example..com'), /invalid dot patterns/);
		});

		it('rejects domains starting with dot', () => {
			assert.throws(() => validateEmailDomain('.example.com'), /invalid dot patterns/);
		});

		it('rejects domains ending with dot', () => {
			assert.throws(() => validateEmailDomain('example.com.'), /invalid dot patterns/);
		});

		it('accepts domains with hyphens', () => {
			assert.doesNotThrow(() => validateEmailDomain('my-company.com'));
		});

		it('accepts domains with numbers', () => {
			assert.doesNotThrow(() => validateEmailDomain('company123.com'));
			assert.doesNotThrow(() => validateEmailDomain('123company.com'));
		});
	});

	describe('Error handling', () => {
		it('throws on empty string', () => {
			assert.throws(() => validateEmailDomain(''), /non-empty string/);
		});

		it('throws on non-string input', () => {
			assert.throws(() => validateEmailDomain(null), /non-empty string/);
			assert.throws(() => validateEmailDomain(undefined), /non-empty string/);
		});
	});
});

describe('validateTenantId', () => {
	describe('Length validation', () => {
		it('rejects IDs shorter than 3 characters', () => {
			assert.throws(() => validateTenantId('ab'), /3-64 characters/);
			assert.throws(() => validateTenantId('a'), /3-64 characters/);
		});

		it('rejects IDs longer than 64 characters', () => {
			const longId = 'a'.repeat(65);
			assert.throws(() => validateTenantId(longId), /3-64 characters/);
		});

		it('accepts IDs within valid length range', () => {
			assert.doesNotThrow(() => validateTenantId('abc')); // Min: 3
			assert.doesNotThrow(() => validateTenantId('a'.repeat(64))); // Max: 64
			assert.doesNotThrow(() => validateTenantId('acme-corp')); // Typical
		});
	});

	describe('Character validation', () => {
		it('accepts alphanumeric characters', () => {
			assert.doesNotThrow(() => validateTenantId('abc123'));
			assert.doesNotThrow(() => validateTenantId('ABC123'));
		});

		it('accepts hyphens', () => {
			assert.doesNotThrow(() => validateTenantId('acme-corp'));
			assert.doesNotThrow(() => validateTenantId('my-company-name'));
		});

		it('accepts underscores', () => {
			assert.doesNotThrow(() => validateTenantId('acme_corp'));
			assert.doesNotThrow(() => validateTenantId('my_company_name'));
		});

		it('rejects spaces', () => {
			assert.throws(() => validateTenantId('acme corp'), /alphanumeric/);
		});

		it('rejects special characters', () => {
			assert.throws(() => validateTenantId('acme@corp'), /alphanumeric/);
			assert.throws(() => validateTenantId('acme.corp'), /alphanumeric/);
			assert.throws(() => validateTenantId('acme/corp'), /alphanumeric/);
			assert.throws(() => validateTenantId('acme\\corp'), /alphanumeric/);
		});
	});

	describe('Error handling', () => {
		it('throws on empty string', () => {
			assert.throws(() => validateTenantId(''), /non-empty string/);
		});

		it('throws on non-string input', () => {
			assert.throws(() => validateTenantId(null), /non-empty string/);
			assert.throws(() => validateTenantId(undefined), /non-empty string/);
		});
	});
});

describe('sanitizeTenantName - XSS Protection', () => {
	it('escapes HTML tags', () => {
		const result = sanitizeTenantName('<script>alert(1)</script>');
		assert.equal(result, '&lt;script&gt;alert(1)&lt;&#x2F;script&gt;');
	});

	it('escapes ampersands', () => {
		const result = sanitizeTenantName('Acme & Co');
		assert.equal(result, 'Acme &amp; Co');
	});

	it('escapes quotes', () => {
		const result = sanitizeTenantName('"quoted"');
		assert.equal(result, '&quot;quoted&quot;');
	});

	it('escapes single quotes', () => {
		const result = sanitizeTenantName("O'Reilly");
		assert.equal(result, 'O&#x27;Reilly');
	});

	it('escapes slashes', () => {
		const result = sanitizeTenantName('Acme/Corp');
		assert.equal(result, 'Acme&#x2F;Corp');
	});

	it('handles multiple special characters', () => {
		const result = sanitizeTenantName('<a href="javascript:alert(1)">Click</a>');
		assert.equal(result, '&lt;a href=&quot;javascript:alert(1)&quot;&gt;Click&lt;&#x2F;a&gt;');
	});

	it('returns safe normal text unchanged (content-wise)', () => {
		const result = sanitizeTenantName('Acme Corporation');
		assert.equal(result, 'Acme Corporation');
	});

	it('returns empty string for null', () => {
		assert.equal(sanitizeTenantName(null), '');
	});

	it('returns empty string for undefined', () => {
		assert.equal(sanitizeTenantName(undefined), '');
	});

	it('returns empty string for empty string', () => {
		assert.equal(sanitizeTenantName(''), '');
	});
});

describe('validateAzureTenantId', () => {
	describe('GUID validation', () => {
		it('accepts valid GUIDs', () => {
			assert.doesNotThrow(() => validateAzureTenantId('12345678-1234-1234-1234-123456789abc'));
			assert.doesNotThrow(() => validateAzureTenantId('abcdef01-2345-6789-abcd-ef0123456789'));
		});

		it('accepts GUIDs with uppercase', () => {
			assert.doesNotThrow(() => validateAzureTenantId('12345678-1234-1234-1234-123456789ABC'));
		});

		it('rejects malformed GUIDs', () => {
			assert.throws(() => validateAzureTenantId('12345678-1234-1234-1234'), /Invalid Azure tenant/);
			assert.throws(() => validateAzureTenantId('not-a-guid'), /Invalid Azure tenant/);
			assert.throws(() => validateAzureTenantId('12345678123412341234123456789abc'), /Invalid Azure tenant/); // Missing hyphens
		});
	});

	describe('Special tenant IDs', () => {
		it('accepts "common"', () => {
			assert.doesNotThrow(() => validateAzureTenantId('common'));
		});

		it('accepts "organizations"', () => {
			assert.doesNotThrow(() => validateAzureTenantId('organizations'));
		});

		it('accepts "consumers"', () => {
			assert.doesNotThrow(() => validateAzureTenantId('consumers'));
		});

		it('accepts special IDs case-insensitively', () => {
			assert.doesNotThrow(() => validateAzureTenantId('COMMON'));
			assert.doesNotThrow(() => validateAzureTenantId('Organizations'));
			assert.doesNotThrow(() => validateAzureTenantId('CONSUMERS'));
		});
	});

	describe('Error handling', () => {
		it('throws on empty string', () => {
			assert.throws(() => validateAzureTenantId(''), /requires tenantId/);
		});

		it('throws on invalid values', () => {
			assert.throws(() => validateAzureTenantId('invalid'), /Invalid Azure tenant/);
			assert.throws(() => validateAzureTenantId('admin'), /Invalid Azure tenant/);
		});
	});
});

// Integration tests - combining multiple validations
describe('Integration Tests', () => {
	it('Okta domain validation flow', () => {
		// Step 1: Validate domain safety
		const hostname = validateDomainSafety('acme-corp.okta.com', 'Okta');
		assert.equal(hostname, 'acme-corp.okta.com');

		// Step 2: Validate against Okta allowlist
		const allowlist = ['.okta.com', '.okta-emea.com', '.oktapreview.com'];
		assert.doesNotThrow(() => validateDomainAllowlist(hostname, allowlist, 'Okta'));
	});

	it('Complete tenant registration validation', () => {
		// Validate tenant ID
		const tenantId = 'acme-corp';
		assert.doesNotThrow(() => validateTenantId(tenantId));

		// Validate email domains
		const emailDomains = ['acme.com', 'acmecorp.com'];
		emailDomains.forEach((domain) => {
			assert.doesNotThrow(() => validateEmailDomain(domain));
		});

		// Validate provider domain
		const domain = 'acme-corp.okta.com';
		const hostname = validateDomainSafety(domain, 'Okta');
		validateDomainAllowlist(hostname, ['.okta.com'], 'Okta');

		// Sanitize tenant name for display
		const safeName = sanitizeTenantName('Acme Corp');
		assert.ok(safeName);
	});
});
