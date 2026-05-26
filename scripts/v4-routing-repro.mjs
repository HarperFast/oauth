#!/usr/bin/env node
/**
 * v4-routing-repro.mjs — regression guard for the symptom Dawson reported
 * on 2026-05-22 (CM/Studio Okta SSO):
 *
 *   "providerName is 'oauth', not the {configId} described, that isn't passed"
 *
 * Counterpart of integrationTests/path-segment-routing.test.ts on `main`
 * (Harper v5), built for the v1.x line where CM consumes us against
 * harperdb ^4.7.28.
 *
 * Spawns harperdb v4 against a temp fixture that configures two providers —
 * one literally named "oauth" (decoy) and one named "oac-oauth-tenant" (the
 * substring "oauth" inside this name also guards against an over-aggressive
 * stripping regression, not just the prefix-extraction case). Fires
 * /oauth/oac-oauth-tenant/login and inspects the resulting redirect.
 *
 * Outcomes:
 *   - Redirect to tenant.test/authorize with the tenant client_id → parseRoute
 *     correctly extracted the URL path segment. This is the current behavior
 *     on harperdb 4.7.19 + the in-tree plugin source — Dawson's diagnosis
 *     does not reproduce on this stack.
 *   - Anything else (404, decoy redirect, malformed URL) → the assertion
 *     fails; investigate parseRoute / the resource dispatch path.
 *
 * Side effects — harperdb's installer rewrites ~/.harperdb/hdb_boot_properties.file
 * to point at the temp ROOTPATH. The script backs that file up (into the
 * run's tempRoot) before launch and restores it in a single cleanup path
 * shared by the normal `finally` block and the signal/exit handlers, so an
 * existing local `harperdb` install is left intact across runs. If the
 * script is SIGKILL'd between backup and the harperdb install actually
 * touching the file, the backup is collocated with tempRoot and may be
 * left orphaned in $TMPDIR until OS cleanup; check there for recovery.
 *
 * Not wired into CI. Run manually:
 *   node scripts/v4-routing-repro.mjs
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
// Sourced from node_modules/harperdb/package.json at script-write time;
// kept in sync via the SOURCE-OF-TRUTH comment so a Renovate / manual bump
// of the repo's harperdb dep has a single human-readable place to update.
const HARPERDB_PIN = '4.7.19'; // SOURCE-OF-TRUTH: node_modules/harperdb/package.json

const TENANT_CLIENT_ID = 'oauth-tenant-client-id';
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
    oac-oauth-tenant:
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
		// Pin to the exact harperdb being spawned by this script so the
		// fixture's npm install can't resolve a drifted registry version
		// of the >=4.6.0 peer range.
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

// Single cleanup state — populated as we go, consulted by both the
// finally block and the signal handlers so they don't redundantly try
// to restore boot props or kill harperdb.
const cleanupState = {
	bootBackupPath: null, // set once tempRoot exists
	bootState: 'pending', // 'pending' | 'existed' | 'absent'
	tempRoot: null,
	harperProc: null,
	cleaned: false,
};

function backupBootProps() {
	// If a backup file already exists at this run's path it means tempRoot
	// is being reused (impossible — mkdtemp is fresh each run), so existsSync
	// here should always be false on a healthy invocation. The check is a
	// belt-and-suspenders guard.
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
			// harperdb's installer creates the file even if it wasn't there
			// before. Remove it to restore the original "no boot props" state.
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
			// Already exited between the check and the kill — fine.
		}
		// Best-effort follow-up SIGKILL; we can't await an async timer from
		// a synchronous signal handler, so accept the brief inconsistency.
		setTimeout(() => {
			if (harperProc.exitCode === null) {
				try {
					harperProc.kill('SIGKILL');
				} catch {
					// Already exited; nothing to do.
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

	cleanupState.tempRoot = mkdtempSync(join(tmpdir(), 'oauth-v4-repro-'));
	cleanupState.bootBackupPath = join(cleanupState.tempRoot, 'hdb_boot_properties.file.bak');
	const componentsRoot = join(cleanupState.tempRoot, 'components');
	const componentAppDir = join(componentsRoot, 'app');
	const hdbRoot = join(cleanupState.tempRoot, 'hdb-root');
	log(`temp root: ${cleanupState.tempRoot}`);

	// Save the current boot props before harperdb's installer rewrites them.
	// Done outside the try so the backup is in place if anything below throws
	// before harperdb spawns.
	backupBootProps();

	let exitCode = 1;

	try {
		// 1. Build the plugin with a stricter invocation than `npm run build`
		// (which is `tsc || true` — silent failures can leave stale dist/).
		// Clear dist/ first so a TS emission failure is visible by the
		// missing dist/index.js after.
		log('rebuilding plugin (strict)...');
		rmSync(join(repoRoot, 'dist'), { recursive: true, force: true });
		run(tscBin, [], { cwd: repoRoot });
		const distEntry = join(repoRoot, 'dist', 'index.js');
		if (!existsSync(distEntry)) {
			throw new Error(`build did not emit ${distEntry}`);
		}

		// 2. npm pack the local plugin into the temp dir
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

		// 3. Set up the fixture component directly under components/app
		// (avoids a wasteful cp -r of node_modules later).
		log(`writing fixture to ${componentAppDir}...`);
		run('mkdir', ['-p', componentAppDir]);
		writeFileSync(join(componentAppDir, 'config.yaml'), CONFIG_YAML);
		writeFileSync(join(componentAppDir, 'package.json'), PACKAGE_JSON);

		log('installing plugin into fixture component dir...');
		run('npm', ['install', '--no-save', '--no-audit', '--no-fund', tarballPath], { cwd: componentAppDir });

		// 4. Spawn harperdb with CLI-arg config — modeled on
		// @harperfast/integration-testing@0.3.0 (v5). Same argument names
		// exist in v4's bundled binary (ROOTPATH, HDB_ADMIN_*, HTTP_PORT,
		// OPERATIONSAPI_*, etc.).
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

		// 5. Fire the request and check the redirect.
		const url = `http://${hostname}:${httpPort}/oauth/oac-oauth-tenant/login`;
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
			log(
				'FAIL: routed to DECOY provider — parseRoute extracted literal "oauth" segment (bug confirmed on this stack)'
			);
			exitCode = 1;
		} else {
			log(`UNEXPECTED: target=${target} client_id=${clientId}`);
			exitCode = 1;
		}
	} catch (err) {
		log('error:', err.message);
		exitCode = 1;
	} finally {
		cleanup();
		// Give the post-cleanup SIGKILL timer a moment to land before exiting.
		await new Promise((r) => setTimeout(r, 1100));
	}

	process.exit(exitCode);
}

// Route signal exits through the shared cleanup path so harperdb is killed,
// tempRoot is removed, and boot props are restored before we leave.
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT']) {
	process.on(sig, () => {
		cleanup();
		const code = sig === 'SIGINT' ? 130 : sig === 'SIGTERM' ? 143 : sig === 'SIGHUP' ? 129 : 131;
		// Brief delay so the cleanup's async timer can fire if needed.
		setTimeout(() => process.exit(code), 1100).unref();
	});
}

main().catch((err) => {
	console.error('[v4-repro] fatal:', err);
	cleanup();
	process.exit(1);
});
