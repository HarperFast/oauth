/**
 * Tests for mounting the OAuth endpoints as HTTP middleware (httpRoutes).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { registerOAuthHttpRoutes, DEFAULT_HTTP_ROUTES_MOUNT_PATH } from '../../dist/lib/httpRoutes.js';
import { OAuthResource } from '../../dist/lib/resource.js';

/** Captures what the plugin registers with `server.http()`. */
function makeServer() {
	const registrations = [];
	return {
		registrations,
		http(handler, options) {
			registrations.push({ handler, options });
		},
	};
}

function makeRequest(overrides = {}) {
	return {
		method: 'GET',
		// `urlPath` matching passes the path relative to the mount.
		pathname: '/azure/login',
		headers: { asObject: {} },
		...overrides,
	};
}

const passThrough = Symbol('next');
const next = () => passThrough;

describe('registerOAuthHttpRoutes', () => {
	it('mounts at the default path, after authentication', () => {
		const server = makeServer();
		registerOAuthHttpRoutes(server, () => ({ enabled: true }));

		assert.equal(server.registrations.length, 1);
		assert.equal(server.registrations[0].options.urlPath, DEFAULT_HTTP_ROUTES_MOUNT_PATH);
		assert.equal(server.registrations[0].options.after, 'authentication');
	});

	it('honours a configured mount path', () => {
		const server = makeServer();
		registerOAuthHttpRoutes(server, () => ({ enabled: true, mountPath: '/auth/oauth' }));

		assert.equal(server.registrations[0].options.urlPath, '/auth/oauth');
	});

	it('registers nothing when server.http is unavailable', () => {
		let warned = false;
		assert.doesNotThrow(() =>
			registerOAuthHttpRoutes({}, () => ({ enabled: true }), {
				warn: () => {
					warned = true;
				},
			})
		);
		assert.ok(warned);
	});

	it('passes through when the option is disabled, and is read per request', async () => {
		const server = makeServer();
		let enabled = false;
		registerOAuthHttpRoutes(server, () => ({ enabled }));
		const { handler } = server.registrations[0];

		assert.equal(await handler(makeRequest(), next), passThrough);

		// Flipping the option takes effect without re-registering.
		enabled = true;
		assert.notEqual(await handler(makeRequest(), next), passThrough);
	});

	it('passes non-GET through: POST endpoints stay on the REST resource', async () => {
		const server = makeServer();
		registerOAuthHttpRoutes(server, () => ({ enabled: true }));
		const { handler } = server.registrations[0];

		assert.equal(await handler(makeRequest({ method: 'POST', pathname: '/logout' }), next), passThrough);
	});

	it('routes the relative path to the resource as its id', async () => {
		const server = makeServer();
		registerOAuthHttpRoutes(server, () => ({ enabled: true }));
		const { handler } = server.registrations[0];

		const seen = [];
		const originalGet = OAuthResource.prototype.get;
		OAuthResource.prototype.get = async function (target) {
			seen.push(target.id);
			return { status: 200, body: 'ok' };
		};

		try {
			const response = await handler(makeRequest({ pathname: '/azure/callback' }), next);

			assert.equal(response.status, 200);
			assert.deepEqual(seen, ['azure/callback']);
		} finally {
			OAuthResource.prototype.get = originalGet;
		}
	});
});
