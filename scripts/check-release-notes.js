// Renders release notes with .releaserc.json's own commit-analyzer and release-notes-generator
// settings, so a preset the installed changelog writer cannot render fails a PR check instead
// of the release run on main.
import { readFile } from 'node:fs/promises';
import { analyzeCommits } from '@semantic-release/commit-analyzer';
import { generateNotes } from '@semantic-release/release-notes-generator';

const { plugins } = JSON.parse(await readFile(new URL('../.releaserc.json', import.meta.url), 'utf8'));

function pluginConfig(name) {
	const entry = plugins.find((plugin) => (Array.isArray(plugin) ? plugin[0] : plugin) === name);
	if (!entry) throw new Error(`.releaserc.json does not list ${name}`);
	return Array.isArray(entry) ? (entry[1] ?? {}) : {};
}

const subject = 'release notes render check';
const context = {
	cwd: process.cwd(),
	env: process.env,
	logger: { log() {}, success() {}, warn: console.warn, error: console.error },
	options: { repositoryUrl: 'https://github.com/HarperFast/oauth.git' },
	lastRelease: { gitTag: 'v1.0.0', version: '1.0.0' },
	nextRelease: { gitTag: 'v1.1.0', version: '1.1.0' },
	commits: [{ hash: 'a'.repeat(40), message: `feat: ${subject}` }],
};

const releaseType = await analyzeCommits(pluginConfig('@semantic-release/commit-analyzer'), context);
if (releaseType !== 'minor') throw new Error(`Expected a feat commit to be a minor release, got ${releaseType}`);

const notes = await generateNotes(pluginConfig('@semantic-release/release-notes-generator'), context);
if (!notes.includes(subject)) throw new Error(`The release notes leave out the commit:\n${notes}`);

console.log('Release notes render with .releaserc.json');
