/**
 * mcp.sessionLogin fixture app: a password sign-in that establishes a Harper
 * cookie session (the host application's own login), and a /mcp route guarded
 * by withMCPAuth that echoes who the bearer token belongs to.
 */
import { server } from 'harper';
import { withMCPAuth } from '@harperfast/oauth';

export class SignIn extends Resource {
	allowCreate() {
		return true;
	}

	async post(data) {
		await this.getContext().login(data.username, data.password);
		return { ok: true };
	}
}

server.http(
	withMCPAuth((request) => ({
		status: 200,
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ sub: request.mcp?.sub ?? null, user: request.user?.username ?? null }),
	})),
	{ urlPath: '/mcp' }
);
