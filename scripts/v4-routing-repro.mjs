#!/usr/bin/env node
/**
 * v4-routing-repro.mjs — lightweight repro for the symptom Dawson reported
 * on 2026-05-22 (CM/Studio Okta SSO):
 *
 *   "providerName is 'oauth', not the {configId} described, that isn't passed"
 *
 * Counterpart of integrationTests/path-segment-routing.test.ts on `main`
 * (Harper v5), built for the v1.x line where CM consumes us against
 * harperdb ^4.7.28.
 *
 * Spawns harperdb v4 against a temp fixture that configures two providers —
 * one literally named "oauth" (decoy) and one named "oac-tenant-acme" with
 * a distinctive client_id — then fires /oauth/oac-tenant-acme/login and
 * inspects the resulting redirect.
 *
 * Expected outcomes once boot works:
 *   - Redirect to tenant.test/authorize with the tenant client_id → parseRoute
 *     correctly extracted the URL path segment. Dawson's diagnosis would not
 *     reproduce on this stack.
 *   - Redirect to decoy.test/authorize → parseRoute extracted the literal
 *     "oauth" prefix as providerName. Bug confirmed on this stack.
 *
 * STATUS — WIP, does NOT currently boot harperdb v4.
 *
 *   harperdb v4 reads its root path from ~/.harperdb/hdb_boot_properties.file
 *   (written by `harperdb install`). The CLI doesn't accept ROOTPATH /
 *   HDB_ROOT env vars to override it, and any non-default install would
 *   overwrite Nathan's existing /Users/nathan/harper pointer. Need either:
 *   (a) scripted `harperdb install` to a temp dir + atomic save/restore of
 *       the boot-properties file, OR
 *   (b) find the correct env var(s) harperdb v4 honors (likely
 *       HARPER_<SECTION>_<KEY> like Harper v5's HARPER_SET_CONFIG; not yet
 *       verified for v4)
 *
 * Run manually (once it works):
 *   npm run build && node scripts/v4-routing-repro.mjs
 *
 * Set KEEP_TEMP=1 to preserve the temp dir for inspection.
 */
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const harperBin = join(repoRoot, 'node_modules', '.bin', 'harperdb');

const TENANT_CLIENT_ID = 'tenant-acme-client-id';
const DECOY_CLIENT_ID = 'decoy-oauth-client-id';

const CONFIG_YAML = `
rest: true

'@harperfast/oauth':
  package: '@harperfast/oauth'
  providers:
    oauth:
      provider: generic
      clientId: ${DECOY_CLIENT_ID}
      clientSecret: decoy-secret
      authorizationUrl: 'http://decoy.test/authorize'
      tokenUrl: 'http://decoy.test/token'
      userInfoUrl: 'http://decoy.test/userinfo'
    oac-tenant-acme:
      provider: generic
      clientId: ${TENANT_CLIENT_ID}
      clientSecret: tenant-secret
      authorizationUrl: 'http://tenant.test/authorize'
      tokenUrl: 'http://tenant.test/token'
      userInfoUrl: 'http://tenant.test/userinfo'
`.trimStart();

const PACKAGE_JSON = JSON.stringify(
	{
		name: 'oauth-v4-routing-repro',
		private: true,
		type: 'module',
	},
	null,
	2
);

function run(cmd, args, opts = {}) {
	const result = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
	if (result.status !== 0) {
		throw new Error(`${cmd} ${args.join(' ')} exited ${result.status}`);
	}
}

function log(...args) {
	console.log('[v4-repro]', ...args);
}

async function waitForReady(harperProc, timeoutMs) {
	const deadline = Date.now() + timeoutMs;
	return new Promise((resolve, reject) => {
		let buf = '';
		const onData = (chunk) => {
			const s = String(chunk);
			buf += s;
			process.stdout.write(s);
			if (/successfully started/i.test(buf)) {
				cleanup();
				resolve();
			}
		};
		const onExit = (code) => {
			cleanup();
			reject(new Error(`harperdb exited prematurely with code ${code}`));
		};
		const onTimeout = () => {
			cleanup();
			reject(new Error(`harperdb did not become ready within ${timeoutMs}ms`));
		};
		const timer = setTimeout(onTimeout, deadline - Date.now());
		const cleanup = () => {
			clearTimeout(timer);
			harperProc.stdout?.off('data', onData);
			harperProc.stderr?.off('data', onData);
			harperProc.off('exit', onExit);
		};
		harperProc.stdout?.on('data', onData);
		harperProc.stderr?.on('data', onData);
		harperProc.once('exit', onExit);
	});
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), 'oauth-v4-repro-'));
	const fixtureDir = join(tempRoot, 'app');
	const hdbRoot = join(tempRoot, 'hdb-root');
	log(`temp root: ${tempRoot}`);

	let harperProc = null;
	let exitCode = 1;

	try {
		// 1. Build the plugin (so dist/ is current)
		log('building plugin...');
		run('npm', ['run', 'build'], { cwd: repoRoot });

		// 2. npm pack the local plugin into the temp dir
		log('packing local plugin...');
		const packResult = spawnSync('npm', ['pack', '--pack-destination', tempRoot, '--json'], {
			cwd: repoRoot,
			encoding: 'utf8',
		});
		if (packResult.status !== 0) {
			console.error(packResult.stderr);
			throw new Error(`npm pack failed (exit ${packResult.status})`);
		}
		const tarballName = JSON.parse(packResult.stdout)[0].filename;
		const tarballPath = join(tempRoot, tarballName);

		// 3. Set up the fixture
		log(`writing fixture to ${fixtureDir}...`);
		spawnSync('mkdir', ['-p', fixtureDir], { stdio: 'inherit' });
		writeFileSync(join(fixtureDir, 'config.yaml'), CONFIG_YAML);
		writeFileSync(join(fixtureDir, 'package.json'), PACKAGE_JSON);

		log('installing plugin into fixture...');
		run('npm', ['install', '--no-save', '--no-audit', '--no-fund', tarballPath], { cwd: fixtureDir });

		// 4. Spawn harperdb dev <fixtureDir>
		// Using HDB_ROOT to direct harperdb's data dir to a temp location so we
		// don't touch ~/hdb. Plain HTTP on 9926 by default (securePort overrides
		// but dev mode usually serves plain HTTP for ease of testing).
		log(`spawning: ${harperBin} dev ${fixtureDir}`);
		harperProc = spawn(harperBin, ['dev', fixtureDir], {
			env: {
				...process.env,
				HDB_ROOT: hdbRoot,
				ROOTPATH: hdbRoot,
			},
		});

		log('waiting for ready...');
		await waitForReady(harperProc, 60_000);

		// 5. Fire the request and check the redirect
		// Try plain HTTP on 9926 first; harperdb dev usually exposes it.
		const url = 'http://localhost:9926/oauth/oac-tenant-acme/login';
		log(`fetching ${url}`);
		const response = await fetch(url, { redirect: 'manual' });
		log(`status: ${response.status}`);
		const location = response.headers.get('location');
		log(`location: ${location}`);

		if (response.status !== 302 || !location) {
			throw new Error(`expected 302 redirect, got ${response.status} (location: ${location})`);
		}

		const redirectUrl = new URL(location);
		const target = redirectUrl.origin + redirectUrl.pathname;
		const clientId = redirectUrl.searchParams.get('client_id');

		log(`redirect target: ${target}`);
		log(`client_id: ${clientId}`);

		if (target === 'http://tenant.test/authorize' && clientId === TENANT_CLIENT_ID) {
			log('PASS: routed to tenant provider — parseRoute extracted the URL path segment');
			exitCode = 0;
		} else if (target === 'http://decoy.test/authorize' && clientId === DECOY_CLIENT_ID) {
			log('FAIL: routed to DECOY provider — parseRoute extracted literal "oauth" segment (bug confirmed on this stack)');
			exitCode = 1;
		} else {
			log(`UNEXPECTED: target=${target} client_id=${clientId}`);
			exitCode = 1;
		}
	} catch (err) {
		log('error:', err.message);
		exitCode = 1;
	} finally {
		if (harperProc && harperProc.exitCode === null) {
			log('killing harperdb...');
			harperProc.kill('SIGINT');
			await new Promise((r) => setTimeout(r, 1000));
			if (harperProc.exitCode === null) harperProc.kill('SIGKILL');
		}
		if (!process.env.KEEP_TEMP) {
			log(`cleaning up ${tempRoot}`);
			rmSync(tempRoot, { recursive: true, force: true });
		} else {
			log(`KEEP_TEMP set; leaving ${tempRoot}`);
		}
	}

	process.exit(exitCode);
}

main().catch((err) => {
	console.error('[v4-repro] fatal:', err);
	process.exit(1);
});
