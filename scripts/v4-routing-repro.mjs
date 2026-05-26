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
 * one literally named "oauth" (decoy) and one named "oac-tenant-acme" with
 * a distinctive client_id — then fires /oauth/oac-tenant-acme/login and
 * inspects the resulting redirect.
 *
 * Outcomes:
 *   - Redirect to tenant.test/authorize with the tenant client_id → parseRoute
 *     correctly extracted the URL path segment. This is the current behavior
 *     on Harper v4.7.19 + v1.4.0 plugin source — Dawson's diagnosis does not
 *     reproduce on this stack.
 *   - Redirect to decoy.test/authorize → parseRoute extracted the literal
 *     "oauth" prefix as providerName. Bug confirmed (regression).
 *
 * Side effects — harperdb's installer rewrites ~/.harperdb/hdb_boot_properties.file
 * to point at the temp ROOTPATH. The script saves the original contents (if any)
 * before launch and restores them in a finally block, so an existing local
 * `harperdb` install is left intact across runs. If the script is killed
 * uncleanly, manually restore the file from ${BOOT_BACKUP_PATH}.
 *
 * Not wired into CI. Run manually:
 *   npm run build && node scripts/v4-routing-repro.mjs
 *
 * Set KEEP_TEMP=1 to preserve the temp dir for inspection.
 */
import { mkdtempSync, writeFileSync, rmSync, existsSync, copyFileSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

const BOOT_PROPS_PATH = join(homedir(), '.harperdb', 'hdb_boot_properties.file');
const BOOT_BACKUP_PATH = join(tmpdir(), 'oauth-v4-repro-hdb_boot_properties.file.bak');

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

function backupBootProps() {
	if (existsSync(BOOT_PROPS_PATH)) {
		copyFileSync(BOOT_PROPS_PATH, BOOT_BACKUP_PATH);
		log(`saved boot props to ${BOOT_BACKUP_PATH}`);
		return 'existed';
	}
	log('no existing boot props file to back up');
	return 'absent';
}

function restoreBootProps(state) {
	try {
		if (state === 'existed') {
			if (existsSync(BOOT_BACKUP_PATH)) {
				copyFileSync(BOOT_BACKUP_PATH, BOOT_PROPS_PATH);
				rmSync(BOOT_BACKUP_PATH, { force: true });
				log(`restored boot props from backup`);
			} else {
				log(`WARNING: backup at ${BOOT_BACKUP_PATH} missing — leaving boot props as-is`);
			}
		} else if (state === 'absent') {
			rmSync(BOOT_PROPS_PATH, { force: true });
			log(`removed boot props (none existed before)`);
		}
	} catch (err) {
		log(`WARNING: failed to restore boot props: ${err.message}. Original backup at ${BOOT_BACKUP_PATH}`);
	}
}

async function main() {
	const tempRoot = mkdtempSync(join(tmpdir(), 'oauth-v4-repro-'));
	const fixtureDir = join(tempRoot, 'app');
	const hdbRoot = join(tempRoot, 'hdb-root');
	log(`temp root: ${tempRoot}`);

	// Save the current boot props before harperdb's installer rewrites them.
	// Done outside the try so the backup is in place if anything below throws
	// before harperdb spawns.
	const bootState = backupBootProps();

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

		// 4. Spawn harperdb with CLI-arg config — modeled on
		// @harperfast/integration-testing@0.3.0 (v5). Same argument names
		// exist in v4's bundled binary (ROOTPATH, HDB_ADMIN_*, HTTP_PORT,
		// OPERATIONSAPI_*, etc.).
		//
		// Also point Harper at the fixture directory as its componentsRoot
		// so the OAuth plugin loads from there (the fixture has the plugin
		// installed via npm pack above).
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
			`--COMPONENTSROOT=${tempRoot}/components`,
		];

		// Move the fixture into a `components/` subdir so harperdb finds it
		// as a component by directory name.
		run('mkdir', ['-p', join(tempRoot, 'components')]);
		run('cp', ['-r', fixtureDir, join(tempRoot, 'components', 'app')]);

		log(`spawning: ${harperBin} ${args.join(' ')}`);
		harperProc = spawn(harperBin, args);

		log('waiting for ready...');
		await waitForReady(harperProc, 60_000);

		// 5. Fire the request and check the redirect.
		const url = `http://${hostname}:${httpPort}/oauth/oac-tenant-acme/login`;
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
		if (harperProc && harperProc.exitCode === null) {
			log('killing harperdb...');
			harperProc.kill('SIGINT');
			await new Promise((r) => setTimeout(r, 1000));
			if (harperProc.exitCode === null) harperProc.kill('SIGKILL');
		}
		restoreBootProps(bootState);
		if (!process.env.KEEP_TEMP) {
			log(`cleaning up ${tempRoot}`);
			rmSync(tempRoot, { recursive: true, force: true });
		} else {
			log(`KEEP_TEMP set; leaving ${tempRoot}`);
		}
	}

	process.exit(exitCode);
}

// Restore boot props on unclean exits too — Ctrl+C, kill, uncaught exceptions.
let signaled = false;
function emergencyRestore() {
	if (signaled) return;
	signaled = true;
	try {
		if (existsSync(BOOT_BACKUP_PATH)) {
			copyFileSync(BOOT_BACKUP_PATH, BOOT_PROPS_PATH);
			rmSync(BOOT_BACKUP_PATH, { force: true });
			console.log(`[v4-repro] emergency: restored boot props from ${BOOT_BACKUP_PATH}`);
		}
	} catch (err) {
		console.error(`[v4-repro] emergency restore failed: ${err.message}`);
	}
}
process.on('SIGINT', () => {
	emergencyRestore();
	process.exit(130);
});
process.on('SIGTERM', () => {
	emergencyRestore();
	process.exit(143);
});

main().catch((err) => {
	console.error('[v4-repro] fatal:', err);
	process.exit(1);
});
