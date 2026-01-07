/**
 * Tests for TenantManager
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { TenantManager } from '../../dist/lib/tenantManager.js';

describe('TenantManager', () => {
	describe('Okta tenant registration', () => {
		it('should register Okta tenant with domain', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
				emailDomains: ['acme.com'],
			});

			const tenant = manager.getTenant('acme-corp');
			assert.ok(tenant);
			assert.equal(tenant.config.tenantId, 'acme-corp');
			assert.equal(tenant.config.name, 'Acme Corporation');
			assert.equal(tenant.providerConfig.provider, 'okta');
			assert.equal(tenant.providerConfig.clientId, 'okta-client-id');
			assert.equal(tenant.providerConfig.clientSecret, 'okta-secret');
			assert.ok(tenant.providerConfig.authorizationUrl?.includes('acme.okta.com'));
		});

		it('should throw error for Okta tenant without domain', () => {
			const manager = new TenantManager();

			assert.throws(
				() => {
					manager.registerTenant({
						tenantId: 'acme-corp',
						name: 'Acme Corporation',
						provider: 'okta',
						clientId: 'okta-client-id',
						clientSecret: 'okta-secret',
					});
				},
				{ message: /okta provider requires domain configuration/i }
			);
		});
	});

	describe('Azure AD tenant registration', () => {
		it('should register Azure tenant with azureTenantId', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'globex-corp',
				name: 'Globex Corporation',
				provider: 'azure',
				azureTenantId: '12345678-1234-1234-1234-123456789abc',
				clientId: 'azure-client-id',
				clientSecret: 'azure-secret',
				emailDomains: ['globex.com'],
			});

			const tenant = manager.getTenant('globex-corp');
			assert.ok(tenant);
			assert.equal(tenant.config.provider, 'azure');
			assert.ok(tenant.providerConfig.authorizationUrl?.includes('12345678-1234-1234-1234-123456789abc'));
		});

		it('should throw error for Azure tenant without azureTenantId', () => {
			const manager = new TenantManager();

			assert.throws(
				() => {
					manager.registerTenant({
						tenantId: 'globex-corp',
						name: 'Globex Corporation',
						provider: 'azure',
						clientId: 'azure-client-id',
						clientSecret: 'azure-secret',
					});
				},
				{ message: /Azure AD provider requires azureTenantId/i }
			);
		});

		it('should support microsoft alias for Azure', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'initech',
				name: 'Initech',
				provider: 'microsoft',
				azureTenantId: 'common',
				clientId: 'ms-client-id',
				clientSecret: 'ms-secret',
			});

			const tenant = manager.getTenant('initech');
			assert.ok(tenant);
			assert.equal(tenant.config.provider, 'microsoft');
		});
	});

	describe('Auth0 tenant registration', () => {
		it('should register Auth0 tenant with domain', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'umbrella-corp',
				name: 'Umbrella Corporation',
				provider: 'auth0',
				domain: 'umbrella.us.auth0.com',
				clientId: 'auth0-client-id',
				clientSecret: 'auth0-secret',
				emailDomains: ['umbrella.com'],
			});

			const tenant = manager.getTenant('umbrella-corp');
			assert.ok(tenant);
			assert.equal(tenant.config.provider, 'auth0');
			assert.ok(tenant.providerConfig.authorizationUrl?.includes('umbrella.us.auth0.com'));
		});

		it('should throw error for Auth0 tenant without domain', () => {
			const manager = new TenantManager();

			assert.throws(
				() => {
					manager.registerTenant({
						tenantId: 'umbrella-corp',
						name: 'Umbrella Corporation',
						provider: 'auth0',
						clientId: 'auth0-client-id',
						clientSecret: 'auth0-secret',
					});
				},
				{ message: /auth0 provider requires domain configuration/i }
			);
		});
	});

	describe('Email domain mapping', () => {
		it('should map email domains to tenants', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
				emailDomains: ['acme.com', 'acme.io'],
			});

			const tenant1 = manager.getTenantByEmail('user@acme.com');
			assert.ok(tenant1);
			assert.equal(tenant1.config.tenantId, 'acme-corp');

			const tenant2 = manager.getTenantByEmail('user@acme.io');
			assert.ok(tenant2);
			assert.equal(tenant2.config.tenantId, 'acme-corp');
		});

		it('should handle case-insensitive email domains', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
				emailDomains: ['ACME.COM'],
			});

			const tenant = manager.getTenantByEmail('user@acme.com');
			assert.ok(tenant);
			assert.equal(tenant.config.tenantId, 'acme-corp');
		});

		it('should return undefined for unknown email domain', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
				emailDomains: ['acme.com'],
			});

			const tenant = manager.getTenantByEmail('user@unknown.com');
			assert.equal(tenant, undefined);
		});

		it('should return undefined for invalid email format', () => {
			const manager = new TenantManager();

			const tenant = manager.getTenantByEmail('not-an-email');
			assert.equal(tenant, undefined);
		});
	});

	describe('Custom configuration', () => {
		it('should support custom scope', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
				scope: 'openid profile email custom:scope',
			});

			const tenant = manager.getTenant('acme-corp');
			assert.equal(tenant?.providerConfig.scope, 'openid profile email custom:scope');
		});

		it('should support postLoginRedirect', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
				postLoginRedirect: '/dashboard',
			});

			const tenant = manager.getTenant('acme-corp');
			assert.equal(tenant?.providerConfig.postLoginRedirect, '/dashboard');
		});

		it('should support additionalConfig', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
				additionalConfig: {
					customField: 'customValue',
					anotherField: 123,
				},
			});

			const tenant = manager.getTenant('acme-corp');
			assert.equal(tenant?.providerConfig.customField, 'customValue');
			assert.equal(tenant?.providerConfig.anotherField, 123);
		});
	});

	describe('Validation', () => {
		it('should validate tenant ID format', () => {
			const manager = new TenantManager();

			assert.throws(
				() => {
					manager.registerTenant({
						tenantId: 'ab', // Too short
						name: 'Test',
						provider: 'okta',
						domain: 'test.okta.com',
						clientId: 'client-id',
						clientSecret: 'secret',
					});
				},
				{ message: /Tenant ID must be 3-64 characters/i }
			);
		});

		it('should validate email domain format', () => {
			const manager = new TenantManager();

			assert.throws(
				() => {
					manager.registerTenant({
						tenantId: 'test-tenant',
						name: 'Test',
						provider: 'okta',
						domain: 'test.okta.com',
						clientId: 'client-id',
						clientSecret: 'secret',
						emailDomains: ['invalid..domain.com'], // Double dots
					});
				},
				{ message: /Email domain contains invalid dot patterns/i }
			);
		});

		it('should throw error for unknown provider', () => {
			const manager = new TenantManager();

			assert.throws(
				() => {
					manager.registerTenant({
						tenantId: 'test-tenant',
						name: 'Test',
						provider: 'unknown-provider',
						clientId: 'client-id',
						clientSecret: 'secret',
					});
				},
				{ message: /Unknown provider type: unknown-provider/i }
			);
		});
	});

	describe('Bulk operations', () => {
		it('should register multiple tenants', () => {
			const manager = new TenantManager();

			manager.registerTenants([
				{
					tenantId: 'acme-corp',
					name: 'Acme Corporation',
					provider: 'okta',
					domain: 'acme.okta.com',
					clientId: 'okta-client-id-1',
					clientSecret: 'okta-secret-1',
				},
				{
					tenantId: 'globex-corp',
					name: 'Globex Corporation',
					provider: 'azure',
					azureTenantId: 'common',
					clientId: 'azure-client-id',
					clientSecret: 'azure-secret',
				},
			]);

			assert.ok(manager.getTenant('acme-corp'));
			assert.ok(manager.getTenant('globex-corp'));
		});

		it('should get all registered tenants', () => {
			const manager = new TenantManager();

			manager.registerTenants([
				{
					tenantId: 'acme-corp',
					name: 'Acme Corporation',
					provider: 'okta',
					domain: 'acme.okta.com',
					clientId: 'okta-client-id-1',
					clientSecret: 'okta-secret-1',
				},
				{
					tenantId: 'globex-corp',
					name: 'Globex Corporation',
					provider: 'azure',
					azureTenantId: 'common',
					clientId: 'azure-client-id',
					clientSecret: 'azure-secret',
				},
			]);

			const allTenants = manager.getAllTenants();
			assert.equal(allTenants.length, 2);
			assert.ok(allTenants.find((t) => t.tenantId === 'acme-corp'));
			assert.ok(allTenants.find((t) => t.tenantId === 'globex-corp'));
		});

		it('should redact clientSecret in getAllTenants() for security', () => {
			const manager = new TenantManager();
			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'super-secret-value',
			});

			const allTenants = manager.getAllTenants();
			assert.equal(allTenants.length, 1);

			const tenant = allTenants[0];
			assert.equal(tenant.tenantId, 'acme-corp');
			assert.equal(tenant.clientId, 'okta-client-id');
			assert.equal(tenant.clientSecret, undefined); // Secret should be redacted
		});
	});

	describe('Static factory methods', () => {
		it('should create TenantManager from config', () => {
			const manager = TenantManager.fromConfig({
				tenants: [
					{
						tenantId: 'acme-corp',
						name: 'Acme Corporation',
						provider: 'okta',
						domain: 'acme.okta.com',
						clientId: 'okta-client-id',
						clientSecret: 'okta-secret',
					},
				],
			});

			assert.ok(manager.getTenant('acme-corp'));
		});

		it('should create empty TenantManager from config without tenants', () => {
			const manager = TenantManager.fromConfig({});

			assert.equal(manager.getAllTenants().length, 0);
		});
	});

	describe('Provider registry conversion', () => {
		it('should convert to provider registry format', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'acme-corp',
				name: 'Acme Corporation',
				provider: 'okta',
				domain: 'acme.okta.com',
				clientId: 'okta-client-id',
				clientSecret: 'okta-secret',
			});

			const registry = manager.toProviderRegistry();
			assert.ok(registry['acme-corp']);
			assert.equal(registry['acme-corp'].config.provider, 'okta');
			assert.equal(registry['acme-corp'].config.clientId, 'okta-client-id');
		});
	});

	describe('Generic provider support', () => {
		it('should support generic provider with domain', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'custom-tenant',
				name: 'Custom Tenant',
				provider: 'generic',
				domain: 'custom.example.com',
				clientId: 'custom-client-id',
				clientSecret: 'custom-secret',
			});

			const tenant = manager.getTenant('custom-tenant');
			assert.ok(tenant);
			assert.equal(tenant.config.provider, 'generic');
		});

		it('should support generic provider without domain', () => {
			const manager = new TenantManager();

			manager.registerTenant({
				tenantId: 'custom-tenant',
				name: 'Custom Tenant',
				provider: 'generic',
				clientId: 'custom-client-id',
				clientSecret: 'custom-secret',
			});

			const tenant = manager.getTenant('custom-tenant');
			assert.ok(tenant);
		});

		it('should support GitHub provider with domain (custom provider with configure)', () => {
			const manager = new TenantManager();

			// GitHub has a configure function but is not okta/auth0/azure
			manager.registerTenant({
				tenantId: 'github-tenant',
				name: 'GitHub Tenant',
				provider: 'github',
				domain: 'github.com',
				clientId: 'github-client-id',
				clientSecret: 'github-secret',
			});

			const tenant = manager.getTenant('github-tenant');
			assert.ok(tenant);
			assert.equal(tenant.config.provider, 'github');
		});
	});
});
