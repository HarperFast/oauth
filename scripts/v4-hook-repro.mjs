#!/usr/bin/env node
/**
 * v4-hook-repro.mjs — does an onResolveProvider hook registered from a
 * sibling resources.js (the CM pattern) actually fire on harperdb v4?
 *
 * Background. CM's resources.js does:
 *
 *   import { registerHooks } from '@harperfast/oauth';
 *   import { hooks } from './src/lib/oauthHooks.js';
 *   registerHooks(hooks);
 *
 * at module top level, then the hooks fire when /oauth/{configId}/login
 * runs. We tried mirroring that pattern in an oauth v5 integration test
 * (HarperFast/oauth `dynamic-provider-app` fixture, see PR #102 history)
 * and the hook never got invoked — strong evidence of module isolation
 * between resources.js' import of @harperfast/oauth and the plugin's
 * own pluginModule load.
 *
 * But CM clearly works in production (the user hits the resolver path
 * and sometimes gets a 500 from inside the hook — a 500 only fires if
 * the hook was registered AND threw). So either:
 *   (a) harperdb v4's component loader doesn't isolate modules between
 *       sub-component loads, while harper v5's does
 *   (b) CM's setup is subtly different from the v5 fixture in a way
 *       that bridges the isolation
 *   (c) Something else
 *
 * This script tests (a) directly: boot harperdb v4 with a fixture
 * that mirrors CM's resources.js pattern, then GET /oauth/{oac-id}/login
 * and inspect the response.
 *
 *   - 302 to http://hook-resolved.test/authorize with the hook's
 *     declared client_id → hook fires. Consistent with CM working;
 *     v4 doesn't have the isolation that v5 does.
 *   - 404 "OAuth provider not found" → hook isn't registered in the
 *     plugin's running instance. Would mean CM should also be broken
 *     — investigate what we're missing.
 *   - 500 "Failed to resolve OAuth provider" → hook fires AND throws.
 *     Not the path we're testing here (our hook returns cleanly), but
 *     a useful surface to know is available.
 *
 * Sibling: scripts/v4-routing-repro.mjs (static-provider routing).
 *
 * Run manually:
 *   node scripts/v4-hook-repro.mjs
 *
 * Set KEEP_TEMP=1 to preserve the temp dir for inspection.
 */
import { mkdtempSync, writeFileSync, rmSync, existsSync, copyFileSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

const BOOT_PROPS_PATH = join(homedir(), '.harperdb', 'hdb_boot_properties.file');

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const harperBin = join(repoRoot, 'node_modules', '.bin', 'harperdb');
const tscBin = join(repoRoot, 'node_modules', '.bin', 'tsc');

// Pin the fixture's harperdb peer to the exact version we're spawning so
// `npm install` doesn't resolve a drifted version from the registry.
const HARPERDB_PIN = '4.7.19'; // SOURCE-OF-TRUTH: node_modules/harperdb/package.json

// The hook returns this client_id; the test asserts it round-tripped
// through to the authorize URL the plugin emits.
const HOOK_CLIENT_ID = 'hook-resolved-client-id-42';

// Static provider — needed only to keep the OAuth plugin from registering
// its no-providers stub resource. Naming it 'oauth' here ALSO doubles as
// a decoy: if a future routing regression returns the literal "oauth"
// prefix as providerName, requests would route here instead of into the
// hook, and we'd see the static-stub authorize URL in the redirect.
const STATIC_DECOY_CLIENT_ID = 'static-decoy-client-id';

const CONFIG_YAML = `
rest: true

# Auto-load resources.js (CM does this too).
jsResource:
  files: resources.js

'@harperfast/oauth':
  package: '@harperfast/oauth'
  providers:
    oauth:
      provider: generic
      clientId: ${STATIC_DECOY_CLIENT_ID}
      clientSecret: decoy-secret
      authorizationUrl: 'http://static.test/authorize'
      tokenUrl: 'http://static.test/token'
      userInfoUrl: 'http://static.test/userinfo'
`.trimStart();

// resources.js mirrors CM's pattern: top-level registerHooks call, hook
// returns a provider config for oac-prefixed IDs.
const RESOURCES_JS = `
import { registerHooks } from '@harperfast/oauth';

registerHooks({
	async onResolveProvider(providerName, logger) {
		// Visible in stdout so we can tell empirically whether the hook fires.
		console.log('[hook-repro] onResolveProvider called with: ' + providerName);
		if (providerName.startsWith('oac-')) {
			return {
				provider: 'generic',
				clientId: ${JSON.stringify(HOOK_CLIENT_ID)},
				clientSecret: 'hook-resolved-secret',
				authorizationUrl: 'http://hook-resolved.test/authorize',
				tokenUrl: 'http://hook-resolved.test/token',
				userInfoUrl: 'http://hook-resolved.test/userinfo',
				scope: 'openid profile email',
			};
		}
		return null;
	},
});

console.log('[hook-repro] resources.js: registerHooks invoked');
`.trimStart();

const PACKAGE_JSON = JSON.stringify(
	{
		name: 'oauth-v4-hook-repro',
		private: true,
		type: 'module',
		devDependencies: { harperdb: HARPERDB_PIN },
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
	console.log('[v4-hook-repro]', ...args);
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
		const onError = (err) => {
			cleanup();
			reject(new Error(`harperdb spawn error: ${err.message}`));
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
			harperProc.off('error', onError);
		};
		harperProc.stdout?.on('data', onData);
		harperProc.stderr?.on('data', onData);
		harperProc.once('exit', onExit);
		harperProc.once('error', onError);
	});
}

const cleanupState = {
	bootBackupPath: null,
	bootState: 'pending',
	tempRoot: null,
	harperProc: null,
	cleaned: false,
};

function backupBootProps() {
	if (existsSync(cleanupState.bootBackupPath)) {
		log(`WARNING: backup at ${cleanupState.bootBackupPath} already exists; treating as authoritative`);
		cleanupState.bootState = 'existed';
		return;
	}
	if (existsSync(BOOT_PROPS_PATH)) {
		copyFileSync(BOOT_PROPS_PATH, cleanupState.bootBackupPath);
		log(`saved boot props to ${cleanupState.bootBackupPath}`);
		cleanupState.bootState = 'existed';
		return;
	}
	log('no existing boot props file to back up');
	cleanupState.bootState = 'absent';
}

function restoreBootProps() {
	const { bootBackupPath, bootState } = cleanupState;
	try {
		if (bootState === 'existed') {
			if (bootBackupPath && existsSync(bootBackupPath)) {
				copyFileSync(bootBackupPath, BOOT_PROPS_PATH);
				log(`restored boot props from backup`);
			} else {
				log(`WARNING: backup at ${bootBackupPath} missing — leaving boot props as-is`);
			}
		} else if (bootState === 'absent') {
			rmSync(BOOT_PROPS_PATH, { force: true });
			log(`removed boot props (none existed before)`);
		}
	} catch (err) {
		log(`WARNING: failed to restore boot props: ${err.message}. Backup may be at ${bootBackupPath}`);
	}
}

function cleanup() {
	if (cleanupState.cleaned) return;
	cleanupState.cleaned = true;
	const { harperProc, tempRoot } = cleanupState;
	if (harperProc && harperProc.exitCode === null) {
		log('killing harperdb...');
		try {
			harperProc.kill('SIGINT');
		} catch {
			// Already exited.
		}
		setTimeout(() => {
			if (harperProc.exitCode === null) {
				try {
					harperProc.kill('SIGKILL');
				} catch {
					// Already exited.
				}
			}
		}, 1000);
	}
	restoreBootProps();
	if (tempRoot && !process.env.KEEP_TEMP) {
		log(`cleaning up ${tempRoot}`);
		try {
			rmSync(tempRoot, { recursive: true, force: true });
		} catch (err) {
			log(`WARNING: failed to remove ${tempRoot}: ${err.message}`);
		}
	} else if (tempRoot) {
		log(`KEEP_TEMP set; leaving ${tempRoot}`);
	}
}

async function main() {
	if (!existsSync(harperBin)) {
		throw new Error(`harperdb binary not found at ${harperBin}. Run "npm install" in the repo root first.`);
	}
	if (!existsSync(tscBin)) {
		throw new Error(`tsc binary not found at ${tscBin}. Run "npm install" in the repo root first.`);
	}

	cleanupState.tempRoot = mkdtempSync(join(tmpdir(), 'oauth-v4-hook-repro-'));
	cleanupState.bootBackupPath = join(cleanupState.tempRoot, 'hdb_boot_properties.file.bak');
	const componentsRoot = join(cleanupState.tempRoot, 'components');
	const componentAppDir = join(componentsRoot, 'app');
	const hdbRoot = join(cleanupState.tempRoot, 'hdb-root');
	log(`temp root: ${cleanupState.tempRoot}`);

	backupBootProps();

	let exitCode = 1;

	try {
		log('rebuilding plugin (strict)...');
		rmSync(join(repoRoot, 'dist'), { recursive: true, force: true });
		run(tscBin, [], { cwd: repoRoot });
		const distEntry = join(repoRoot, 'dist', 'index.js');
		if (!existsSync(distEntry)) {
			throw new Error(`build did not emit ${distEntry}`);
		}

		log('packing local plugin...');
		const packResult = spawnSync('npm', ['pack', '--pack-destination', cleanupState.tempRoot, '--json'], {
			cwd: repoRoot,
			encoding: 'utf8',
		});
		if (packResult.status !== 0) {
			console.error(packResult.stderr);
			throw new Error(`npm pack failed (exit ${packResult.status})`);
		}
		const tarballName = JSON.parse(packResult.stdout)[0].filename;
		const tarballPath = join(cleanupState.tempRoot, tarballName);

		log(`writing fixture to ${componentAppDir}...`);
		run('mkdir', ['-p', componentAppDir]);
		writeFileSync(join(componentAppDir, 'config.yaml'), CONFIG_YAML);
		writeFileSync(join(componentAppDir, 'package.json'), PACKAGE_JSON);
		writeFileSync(join(componentAppDir, 'resources.js'), RESOURCES_JS);

		log('installing plugin into fixture component dir...');
		run('npm', ['install', '--no-save', '--no-audit', '--no-fund', tarballPath], { cwd: componentAppDir });

		const httpPort = 19926;
		const opsPort = 19925;
		const hostname = '127.0.0.1';
		const args = [
			`--ROOTPATH=${hdbRoot}`,
			`--TC_AGREEMENT=yes`,
			`--HDB_ADMIN_USERNAME=admin`,
			`--HDB_ADMIN_PASSWORD=Abc1234!`,
			`--DEFAULTS_MODE=dev`,
			`--REPLICATION_HOSTNAME=localhost`,
			`--HTTP_PORT=${hostname}:${httpPort}`,
			`--OPERATIONSAPI_NETWORK_PORT=${hostname}:${opsPort}`,
			`--NODE_HOSTNAME=${hostname}`,
			`--THREADS_COUNT=1`,
			`--LOGGING_LEVEL=debug`,
			`--LOGGING_STDSTREAMS=true`,
			`--CLUSTERING_ENABLED=false`,
			`--COMPONENTSROOT=${componentsRoot}`,
		];

		log(`spawning: ${harperBin} ${args.join(' ')}`);
		cleanupState.harperProc = spawn(harperBin, args);

		log('waiting for ready...');
		await waitForReady(cleanupState.harperProc, 60_000);

		// Hit a configId that is NOT in the static registry. If the hook
		// fires we get a 302 to hook-resolved.test/authorize with the
		// hook's client_id. If the hook doesn't fire we get 404.
		const url = `http://${hostname}:${httpPort}/oauth/oac-test-config/login`;
		log(`fetching ${url}`);
		const response = await fetch(url, { redirect: 'manual' });
		log(`status: ${response.status}`);
		const location = response.headers.get('location');
		log(`location: ${location}`);

		if (response.status === 404) {
			log('FAIL: 404 — hook did not fire (likely module isolation; CM would be broken too?)');
			exitCode = 1;
		} else if (response.status !== 302 || !location) {
			const body = await response.text().catch(() => '<unreadable>');
			log(`FAIL: expected 302, got ${response.status}: ${body}`);
			exitCode = 1;
		} else {
			const redirectUrl = new URL(location);
			const target = redirectUrl.origin + redirectUrl.pathname;
			const clientId = redirectUrl.searchParams.get('client_id');
			log(`redirect target: ${target}`);
			log(`client_id: ${clientId}`);

			if (target === 'http://hook-resolved.test/authorize' && clientId === HOOK_CLIENT_ID) {
				log('PASS: hook fired and returned config; the plugin built the authorize URL from it');
				exitCode = 0;
			} else if (target === 'http://static.test/authorize' && clientId === STATIC_DECOY_CLIENT_ID) {
				log('FAIL: routed to the static decoy provider — parseRoute regression returned literal "oauth"');
				exitCode = 1;
			} else {
				log(`UNEXPECTED: target=${target} client_id=${clientId}`);
				exitCode = 1;
			}
		}
	} catch (err) {
		log('error:', err.message);
		exitCode = 1;
	} finally {
		cleanup();
		await new Promise((r) => setTimeout(r, 1100));
	}

	process.exit(exitCode);
}

for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT']) {
	process.on(sig, () => {
		cleanup();
		const code = sig === 'SIGINT' ? 130 : sig === 'SIGTERM' ? 143 : sig === 'SIGHUP' ? 129 : 131;
		setTimeout(() => process.exit(code), 1100).unref();
	});
}

main().catch((err) => {
	console.error('[v4-hook-repro] fatal:', err);
	cleanup();
	process.exit(1);
});
