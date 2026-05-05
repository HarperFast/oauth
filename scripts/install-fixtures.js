#!/usr/bin/env node
/**
 * Installs each fixture under integrationTests/fixtures/ with a real
 * (non-symlinked) copy of the @harperfast/oauth plugin so Harper's default
 * VM sandbox accepts the dist/ files at the fixture's allowed path.
 *
 * Pipeline: build the plugin, npm pack it into a tarball, then `npm install`
 * the tarball into each fixture. Avoids the file:../../../ symlink pattern,
 * which Harper rejects with "Can not load module outside of allowed path".
 */
import { mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixturesDir = join(repoRoot, 'integrationTests', 'fixtures');

function run(cmd, args, cwd) {
	const result = spawnSync(cmd, args, { cwd, stdio: 'inherit' });
	if (result.status !== 0) {
		throw new Error(`${cmd} ${args.join(' ')} failed in ${cwd} (exit ${result.status})`);
	}
}

console.log('Building plugin...');
run('npm', ['run', 'build'], repoRoot);

const packDir = mkdtempSync(join(tmpdir(), 'oauth-fixture-pack-'));
try {
	console.log(`Packing plugin into ${packDir}...`);
	const packResult = spawnSync('npm', ['pack', '--pack-destination', packDir, '--json'], {
		cwd: repoRoot,
		encoding: 'utf8',
	});
	if (packResult.status !== 0) {
		console.error(packResult.stderr);
		throw new Error(`npm pack failed (exit ${packResult.status})`);
	}
	const tarballPath = join(packDir, JSON.parse(packResult.stdout)[0].filename);

	const fixtures = readdirSync(fixturesDir, { withFileTypes: true })
		.filter((entry) => entry.isDirectory() && !entry.name.startsWith('_'))
		.map((entry) => entry.name);

	for (const fixture of fixtures) {
		console.log(`Installing ${fixture} dependencies...`);
		const fixturePath = join(fixturesDir, fixture);
		rmSync(join(fixturePath, 'node_modules'), { recursive: true, force: true });
		rmSync(join(fixturePath, 'package-lock.json'), { force: true });
		run('npm', ['install', '--no-save', tarballPath], fixturePath);
		console.log('');
	}
} finally {
	rmSync(packDir, { recursive: true, force: true });
}
