/**
 * Shared validation utilities for OAuth providers
 *
 * Security-first validation helpers to prevent SSRF, injection attacks,
 * and other common OAuth configuration vulnerabilities.
 */

/**
 * Validates that a domain string is safe from common attacks
 *
 * Prevents SSRF attacks by blocking private IPs, localhost, cloud metadata endpoints,
 * and non-HTTP protocols.
 *
 * @param domain - Domain string to validate (e.g., 'example.okta.com' or 'https://example.okta.com')
 * @param providerName - Name of provider for error messages
 * @returns Validated hostname (without protocol)
 * @throws Error if domain is invalid or unsafe
 */
export function validateDomainSafety(domain: string, providerName: string): string {
	if (!domain) {
		throw new Error(`${providerName} provider requires domain configuration`);
	}

	// Block non-HTTP protocols (file://, ftp://, etc.)
	if (domain.includes('://') && !domain.startsWith('http://') && !domain.startsWith('https://')) {
		throw new Error(`Invalid ${providerName} domain: ${domain}. Protocol must be http:// or https://`);
	}

	// Check for IPv6 addresses directly (before URL parsing)
	// This catches some forms before normalization
	const ipv6Loopback = /^(::1|0:0:0:0:0:0:0:1)$/i;
	const ipv6LinkLocal = /^fe80:/i;
	if (ipv6Loopback.test(domain) || ipv6LinkLocal.test(domain)) {
		throw new Error(`${providerName} domain cannot be a private IP address or localhost`);
	}

	// Parse domain to extract hostname
	let url: URL;
	try {
		url = new URL(domain.startsWith('http') ? domain : `https://${domain}`);
	} catch (error) {
		throw new Error(
			`Invalid ${providerName} domain: ${domain}. Expected format: 'example.com' or 'https://example.com'`
		);
	}

	const hostname = url.hostname;

	// Block private IPs, localhost, and cloud metadata endpoints
	// 169.254.169.254 is used by AWS, GCP, Azure, DigitalOcean for instance metadata
	const isPrivateIP = /^(10|127|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\./.test(hostname);
	const isLinkLocal = /^169\.254\./.test(hostname);
	// IPv6: Check after URL parsing for defense-in-depth (URL normalizes various IPv6 forms)
	// This catches ::1 (loopback) and fe80:: (link-local) in any normalized representation
	const isIPv6Private = /^::1$|^fe80:/i.test(hostname);

	if (isPrivateIP || hostname === 'localhost' || isLinkLocal || isIPv6Private) {
		throw new Error(`${providerName} domain cannot be a private IP address or localhost`);
	}

	return hostname;
}

/**
 * Validates that a domain matches an allowlist of permitted suffixes
 *
 * Use after validateDomainSafety() to ensure domains match expected patterns
 * (e.g., *.okta.com, *.auth0.com)
 *
 * @param hostname - Validated hostname (from validateDomainSafety)
 * @param allowedSuffixes - Array of allowed domain suffixes (e.g., ['.okta.com', '.okta-emea.com'])
 * @param providerName - Name of provider for error messages
 * @throws Error if hostname doesn't match any allowed suffix
 */
export function validateDomainAllowlist(hostname: string, allowedSuffixes: string[], providerName: string): void {
	const isAllowed = allowedSuffixes.some((suffix) => hostname.endsWith(suffix) || hostname === suffix.slice(1));

	if (!isAllowed) {
		const allowedDomains = allowedSuffixes.map((s) => `*${s}`).join(', ');
		throw new Error(`Invalid ${providerName} domain: ${hostname}. Must be one of: ${allowedDomains}`);
	}
}

/**
 * Validates email domain format
 *
 * Prevents injection attacks by blocking CRLF, null bytes, and control characters.
 *
 * @param emailDomain - Email domain to validate (e.g., 'example.com')
 * @throws Error if domain contains dangerous characters
 */
export function validateEmailDomain(emailDomain: string): void {
	if (!emailDomain || typeof emailDomain !== 'string') {
		throw new Error('Email domain must be a non-empty string');
	}

	// Block CRLF, null bytes, and control characters
	if (/[\r\n\0\x00-\x1F\x7F]/.test(emailDomain)) {
		throw new Error('Email domain contains invalid characters');
	}

	// Block malicious dot patterns (check before format validation)
	if (emailDomain.includes('..') || emailDomain.startsWith('.') || emailDomain.endsWith('.')) {
		throw new Error('Email domain contains invalid dot patterns');
	}

	// Basic format validation (permissive to avoid blocking legitimate domains)
	if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(emailDomain)) {
		throw new Error('Email domain must be a valid domain format (e.g., example.com)');
	}
}

/**
 * Validates tenant ID format
 *
 * Ensures tenant IDs are safe for URLs and file paths. Enforces length limits
 * and character restrictions.
 *
 * @param tenantId - Tenant ID to validate
 * @throws Error if tenant ID is invalid or unsafe
 */
export function validateTenantId(tenantId: string): void {
	if (!tenantId || typeof tenantId !== 'string') {
		throw new Error('Tenant ID must be a non-empty string');
	}

	// Enforce length limits (3-64 characters)
	if (tenantId.length < 3 || tenantId.length > 64) {
		throw new Error('Tenant ID must be 3-64 characters long');
	}

	// Allow only alphanumeric characters, hyphens, and underscores
	if (!/^[a-zA-Z0-9_-]+$/.test(tenantId)) {
		throw new Error('Tenant ID must contain only alphanumeric characters, hyphens, and underscores');
	}
}

/**
 * Sanitizes tenant name for safe HTML output
 *
 * Prevents XSS attacks by HTML-escaping special characters.
 *
 * @param name - Tenant name to sanitize
 * @returns HTML-escaped tenant name
 */
export function sanitizeTenantName(name: string): string {
	if (!name || typeof name !== 'string') {
		return '';
	}

	return name
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#x27;')
		.replace(/\//g, '&#x2F;');
}

/**
 * Validates Azure tenant ID format
 *
 * Valid formats: GUID, 'common', 'organizations', or 'consumers'
 *
 * @param tenantId - Azure tenant ID to validate
 * @throws Error if tenant ID is invalid
 */
export function validateAzureTenantId(tenantId: string): void {
	if (!tenantId) {
		throw new Error('Azure AD provider requires tenantId configuration');
	}

	const validTenantId =
		/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|common|organizations|consumers)$/i;

	if (!validTenantId.test(tenantId)) {
		throw new Error(`Invalid Azure tenant ID: ${tenantId}. Must be a GUID or one of: common, organizations, consumers`);
	}
}
