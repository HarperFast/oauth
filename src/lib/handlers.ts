/**
 * OAuth Endpoint Handlers
 *
 * Handler functions for OAuth authentication endpoints
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RequestTarget } from 'harper';
import type {
	Request,
	Logger,
	IOAuthProvider,
	MCPAuthorizeState,
	MCPConfig,
	OAuthProviderConfig,
	OnLoginResult,
	OnLoginResultDenied,
	OnLoginResultNeedsConfirmation,
	AuthTrust,
	EmailProvenance,
	OAuthAuthEvidence,
} from '../types.ts';
import {
	browserSecretMatches,
	buildBrowserSecretCookie,
	generateBrowserSecret,
	hashBrowserSecret,
	readBrowserSecret,
} from './mcp/consentBinding.ts';
import { makeQuarantinePrincipal, isQuarantinePrincipal } from './quarantinePrincipal.ts';
import { handleMCPCallback } from './mcp/index.ts';
import { resolveIssuer } from './mcp/wellKnown.ts';
import { getRequestHeader } from './requestHeaders.ts';
import type { HookManager } from './hookManager.ts';

/**
 * Sanitize a redirect parameter to prevent open redirect attacks
 *
 * Takes a user-provided redirect URL and extracts only the path portion,
 * stripping any protocol, domain, or port information.
 *
 * Blocks dangerous protocols like javascript:, data:, vbscript:, and file:
 * to prevent XSS and other injection attacks.
 *
 * @param redirectParam - User-provided redirect URL (may be absolute, relative, or protocol-relative)
 * @returns Safe relative path (pathname + search + hash), or '/' if invalid
 *
 * @example
 * sanitizeRedirect('https://evil.com/phish')  // '/phish'
 * sanitizeRedirect('//evil.com/phish')        // '/phish'
 * sanitizeRedirect('/dashboard')              // '/dashboard'
 * sanitizeRedirect('javascript:alert(1)')     // '/'
 * sanitizeRedirect('invalid')                 // '/'
 */
export function sanitizeRedirect(redirectParam: string): string {
	try {
		const url = new URL(redirectParam, 'http://localhost');

		// Block dangerous protocols
		// These protocols can be used for XSS, file access, or other attacks
		const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
		if (dangerousProtocols.some((proto) => url.protocol === proto)) {
			return '/';
		}

		const sanitized = url.pathname + url.search + url.hash;

		// Additional validation: result must start with /
		if (!sanitized.startsWith('/')) {
			return '/';
		}

		return sanitized;
	} catch (error) {
		// Invalid URL - return safe default
		return '/';
	}
}

/**
 * Build a safe error redirect URL
 *
 * Sanitizes the redirect path, then appends error query params using the URL API
 * so params are always placed before any hash fragment.
 */
function buildErrorRedirect(rawUrl: string, params: Record<string, string>): string {
	const safePath = sanitizeRedirect(rawUrl);
	const url = new URL(safePath, 'http://localhost');
	for (const [key, value] of Object.entries(params)) {
		url.searchParams.set(key, value);
	}
	return url.pathname + url.search + url.hash;
}

/**
 * Resolve a redirect provided by the onLogin hook (trusted app code, not user
 * input). Unlike sanitizeRedirect, absolute http(s) URLs pass through — an app
 * may legitimately send the user to another host (e.g. a central onboarding
 * page). Anything else falls back to sanitizeRedirect's path-only handling,
 * which also neutralizes javascript:/data: schemes and protocol-relative URLs.
 */
export function resolveHookRedirect(redirect: string): string {
	try {
		const url = new URL(redirect);
		// Return the parsed href, not the raw input: WHATWG normalization
		// strips embedded control characters (e.g. CR/LF) before the value
		// reaches a Location header.
		return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : '/';
	} catch {
		return sanitizeRedirect(redirect);
	}
}

/**
 * onLogin outcomes that gate the login (#174): no session, no MCP auth code.
 */
function isGatedLoginOutcome(
	hookData: OnLoginResult | void
): hookData is OnLoginResultDenied | OnLoginResultNeedsConfirmation {
	return !!hookData && (hookData.status === 'denied' || hookData.status === 'needs_confirmation');
}

/**
 * Handle OAuth login initiation
 */
export async function handleLogin(
	request: Request,
	target: RequestTarget,
	provider: IOAuthProvider,
	config: OAuthProviderConfig,
	providerName: string,
	logger?: Logger
): Promise<any> {
	// Determine redirect URL: query param > referer header > config default
	let redirectParam = target.get?.('redirect');

	// Sanitize redirect parameter to prevent open redirect attacks
	if (redirectParam) {
		redirectParam = sanitizeRedirect(redirectParam);
	}

	// getRequestHeader, not request.headers.referer: the live Harper runtime
	// wraps headers behind `.asObject`, so direct property access is undefined.
	const refererHeader = getRequestHeader(request.headers, 'referer');
	const referer = refererHeader ? sanitizeRedirect(refererHeader) : undefined;
	const originalUrl = redirectParam || referer || config.postLoginRedirect || '/';

	// Browser binding: session binding only covers flows initiated while logged
	// in — Harper mints no anonymous session id, so the logged-out login flow
	// needs the browser secret cookie to prove the callback arrived in the
	// initiating browser (login-CSRF: attacker-minted state+code fed to a
	// victim silently logs them in as the attacker).
	// One stable `__Host-oauth_browser` cookie per browser; reused across flows;
	// Max-Age refreshed here so active browsers never hit silent expiry.
	const existingSecret = readBrowserSecret(request);
	const browserSecret = existingSecret ?? generateBrowserSecret();

	// Generate CSRF token with metadata
	// Bind token to provider to prevent cross-provider CSRF attacks
	const csrfToken = await provider.generateCSRFToken({
		originalUrl,
		sessionId: request.session?.id,
		providerName, // Bind state token to this provider
		browserNonceHash: hashBrowserSecret(browserSecret),
	});

	// Build authorization URL with CSRF token as state parameter
	const authUrl = provider.getAuthorizationUrl(csrfToken, config.redirectUri || '');

	logger?.info?.(`OAuth login initiated for session: ${request.session?.id}`);

	return {
		status: 302,
		headers: {
			'Location': authUrl,
			'Set-Cookie': buildBrowserSecretCookie(browserSecret),
		},
	};
}

/**
 * Handle OAuth callback from provider
 */
/**
 * Look up whether a Harper `hdb_user` with this exact name exists.
 * Returns true when found, false when not found, null when the lookup
 * cannot be completed (system DB unavailable or error). Callers treat
 * null as fail-closed (same as true) so errors never silently bypass
 * the account-adoption gate.
 */
async function checkHarperUserExists(name: string): Promise<boolean | null> {
	try {
		const db = (globalThis as any).databases?.system?.hdb_user;
		if (!db) return null;
		const record = await db.get(name);
		return record != null;
	} catch {
		return null;
	}
}

export async function handleCallback(
	request: Request,
	target: RequestTarget,
	provider: IOAuthProvider,
	config: OAuthProviderConfig,
	hookManager: HookManager,
	providerName: string,
	opts?: { mcpConfig?: MCPConfig; logger?: Logger; allowUnverifiedClaimInheritance?: boolean }
): Promise<any> {
	const { mcpConfig, logger, allowUnverifiedClaimInheritance = false } = opts ?? {};
	// Get query parameters from target
	const code = target.get?.('code');
	const state = target.get?.('state');
	const error = target.get?.('error');
	const errorDescription = target.get?.('error_description');

	// Helper: build an MCP-aware error redirect to the MCP client's redirect_uri.
	// Only used in MCP branches — the human path keeps its existing
	// buildErrorRedirect shape (error code only, optionally with reason) to
	// avoid changing observable behavior on the human OAuth flow.
	// RFC 9207: include `iss` on all authorization responses, including errors.
	const mcpErrorRedirect = (mcp: MCPAuthorizeState, errorCode: string, description: string) => {
		const url = new URL(mcp.redirectUri);
		url.searchParams.set('error', errorCode);
		url.searchParams.set('error_description', description);
		if (mcp.clientState) url.searchParams.set('state', mcp.clientState);
		url.searchParams.set('iss', resolveIssuer(request as any, mcpConfig ?? {}));
		return { status: 302, headers: { Location: url.toString() } };
	};

	// Validate state presence — we use it both to route errors (via mcp
	// payload, when present) AND to defend against CSRF.
	if (!state) {
		// Without state, we can't be in an MCP flow (MCP always sets state).
		// Preserve the legacy human-OAuth error UX: if the IdP sent an error,
		// echo it to postLoginRedirect with the original reason. Otherwise,
		// generic invalid_request.
		if (error) {
			// JSON.stringify: error/error_description are attacker-controlled
			// query params, reachable pre-auth — encode CR/LF so a crafted value
			// can't forge log lines (CWE-117; same treatment as the DCR handler).
			logger?.error?.(`OAuth error (no state): ${JSON.stringify(error)} - ${JSON.stringify(errorDescription)}`);
			const errorUrl = buildErrorRedirect(config.postLoginRedirect || '/', {
				error: 'oauth_failed',
				reason: error,
			});
			return { status: 302, headers: { Location: errorUrl } };
		}
		logger?.warn?.('Missing state parameter in OAuth callback');
		const errorUrl = buildErrorRedirect(config.postLoginRedirect || '/', { error: 'invalid_request' });
		return { status: 302, headers: { Location: errorUrl } };
	}

	// Verify CSRF token FIRST — before checking the upstream error param.
	// This is what lets MCP-initiated errors route back to the MCP client's
	// redirect_uri instead of the Harper app's default path. The token is
	// single-use; consuming it on error is fine because OAuth callbacks
	// aren't retried with the same state.
	const tokenData = await provider.verifyCSRFToken(state);
	if (!tokenData) {
		logger?.warn?.('Invalid or expired CSRF token');
		// We can't know if this was an MCP flow (state didn't decode), so
		// fall back to a generic redirect — same behavior as pre-fix.
		const loginUrl = `/oauth/${providerName}/login?error=session_expired`;
		return { status: 302, headers: { Location: loginUrl } };
	}

	// Token purpose enforcement: a CIMD confirm token (minted for POST
	// /oauth/mcp/confirm) also carries `mcp` + `providerName` and would
	// otherwise be accepted here as upstream state — letting a malicious
	// client skip the consent interstitial entirely by feeding its confirm
	// token to the IdP as `state`. Treat it exactly like an invalid token
	// (same generic response; nothing in a mis-purposed token is trusted,
	// including its mcp redirect_uri).
	if (tokenData._confirm) {
		logger?.warn?.('CIMD confirm token presented as upstream OAuth state; rejecting');
		const loginUrl = `/oauth/${providerName}/login?error=session_expired`;
		return { status: 302, headers: { Location: loginUrl } };
	}

	const mcpState = tokenData.mcp as MCPAuthorizeState | undefined;

	// Verify state token was issued for THIS provider (prevents cross-provider attacks).
	if (tokenData.providerName !== providerName) {
		logger?.warn?.(
			`State token provider mismatch: token issued for '${tokenData.providerName}', callback for '${providerName}'`
		);
		if (mcpState) {
			return mcpErrorRedirect(mcpState, 'invalid_request', 'cross-provider state mismatch');
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'auth_failed',
			reason: 'csrf',
		});
		return { status: 302, headers: { Location: errorUrl } };
	}

	// State↔session binding (RFC 6749 §10.12 / OAuth Security BCP): the state
	// token records the session that initiated the flow; a callback arriving in
	// a different session is CSRF-shaped — an attacker-minted state delivered
	// into a victim's browser (e.g. to bind the attacker's provider identity to
	// the victim's account in a linking flow). Rejected before the code
	// exchange: no upstream calls, no session write. Enforced whenever the
	// initiating session id is present; sessions are updated in place (never
	// id-rotated), so the id is stable across initiate → IdP → callback.
	if (tokenData.sessionId && tokenData.sessionId !== request.session?.id) {
		logger?.warn?.(`State token session mismatch: flow initiated in a different session (provider '${providerName}')`);
		if (mcpState) {
			return mcpErrorRedirect(
				mcpState,
				'access_denied',
				'Authorization must complete in the session that initiated it'
			);
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'auth_failed',
			reason: 'csrf',
		});
		return { status: 302, headers: { Location: errorUrl } };
	}

	// Login browser binding — the human-flow counterpart of the MCP check below.
	// handleLogin stores hash(browser_secret) in the state; a callback arriving
	// without the matching stable cookie is a state delivered into a different
	// browser — the login-CSRF shape that session binding can't catch when the
	// flow starts logged out (no session id to record).
	// Enforced whenever the token carries the hash, so pre-upgrade in-flight
	// tokens (without browserNonceHash) still complete; MCP states never carry a
	// top-level hash (their binding is checked below).
	if (tokenData.browserNonceHash && !mcpState) {
		if (!browserSecretMatches(readBrowserSecret(request), tokenData.browserNonceHash)) {
			logger?.warn?.(`OAuth callback: login browser binding mismatch (provider '${providerName}')`);
			const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
				error: 'auth_failed',
				reason: 'csrf',
			});
			return { status: 302, headers: { Location: errorUrl } };
		}
	}

	// MCP browser binding — every /oauth/mcp/authorize flow (the CIMD interstitial
	// AND the direct DCR/stored path) reads or generates a stable per-browser
	// secret cookie and carries its hash in the upstream state, so the callback
	// can prove the flow completes in the browser that initiated it. Checked
	// BEFORE the upstream code exchange and the onLogin hook so a mismatched (or
	// unbound) flow triggers no upstream exchange, no userinfo fetch, and no
	// provisioning side-effects. Fail closed: an MCP state without a binding is
	// a forged or pre-upgrade state — reject rather than mint an auth code for an
	// unbound flow (authorization-code injection). SameSite=Lax sends the stable
	// cookie on the top-level redirect back from the upstream IdP.
	if (mcpState) {
		if (!mcpState.browserNonceHash || !browserSecretMatches(readBrowserSecret(request), mcpState.browserNonceHash)) {
			logger?.warn?.(`MCP callback: browser binding mismatch for client=${mcpState.clientId}`);
			return mcpErrorRedirect(
				mcpState,
				'access_denied',
				'Authorization must complete in the browser that initiated it'
			);
		}
	}

	// Now that we know the flow context, handle upstream IdP errors.
	if (error) {
		// JSON.stringify: CRLF-safe logging of browser-controlled params (CWE-117).
		logger?.error?.(`OAuth error: ${JSON.stringify(error)} - ${JSON.stringify(errorDescription)}`);
		if (mcpState) {
			return mcpErrorRedirect(mcpState, error, errorDescription || error);
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'oauth_failed',
			reason: error,
		});
		return { status: 302, headers: { Location: errorUrl } };
	}

	// Validate code presence — needed regardless of flow.
	if (!code) {
		logger?.warn?.('Missing authorization code in OAuth callback');
		if (mcpState) {
			return mcpErrorRedirect(mcpState, 'invalid_request', 'Missing authorization code');
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'invalid_request',
		});
		return { status: 302, headers: { Location: errorUrl } };
	}

	try {
		// Exchange code for tokens
		const tokenResponse = await provider.exchangeCodeForToken(code, config.redirectUri || '');

		// Verify ID token if present (OIDC flow)
		let idTokenClaims = null;
		let idTokenSignatureVerified = false;
		let idTokenIssuerValidated = false;
		if (tokenResponse.id_token) {
			try {
				if (provider.verifyIdToken) {
					const result = await provider.verifyIdToken(tokenResponse.id_token);
					idTokenClaims = result.claims;
					idTokenSignatureVerified = result.signatureVerified;
					idTokenIssuerValidated = result.issuerValidated;
				}
				if (idTokenSignatureVerified && idTokenIssuerValidated) {
					logger?.info?.('ID token signature and issuer verified');
				} else {
					logger?.info?.('ID token decoded (unverified — no JWKS or no configured issuer)');
				}
			} catch (error) {
				// Log verification failure but continue with userinfo endpoint
				logger?.warn?.(
					'ID token verification failed, falling back to userinfo endpoint:',
					error instanceof Error ? error.message : String(error)
				);
			}
		}

		// Get user info (will use ID token claims if available and verified).
		// getUserInfo also sets _emailProvenance on the returned object.
		const userInfo = await provider.getUserInfo(tokenResponse.access_token, idTokenClaims);
		// Extract provenance before mapUserToHarper discards the meta-field.
		const emailProvenance: string =
			typeof userInfo?._emailProvenance === 'string' ? userInfo._emailProvenance : 'unauthenticated';

		// Map to Harper user
		const user = provider.mapUserToHarper(userInfo);

		// Expose authenticated-source evidence to onLogin only (non-enumerable, so it is
		// not persisted into the session). Normalize provenance: 'signed-oidc' requires a
		// verified signature AND validated issuer — getUserInfo labels even a decoded-only
		// token 'signed-oidc', which must not be exported as trusted.
		if (hookManager.hasHook('onLogin')) {
			const provenance: EmailProvenance =
				emailProvenance === 'signed-oidc' && idTokenSignatureVerified && idTokenIssuerValidated
					? 'signed-oidc'
					: emailProvenance === 'github-authenticated' && config.provider === 'github'
						? 'github-authenticated'
						: 'unauthenticated';
			const idTokenVerified = idTokenSignatureVerified && idTokenIssuerValidated;
			const toIdString = (v: unknown): string | undefined =>
				typeof v === 'string' ? v : typeof v === 'number' ? String(v) : undefined;
			const authEvidence: OAuthAuthEvidence = Object.freeze({
				emailProvenance: provenance,
				signatureVerified: idTokenSignatureVerified,
				issuerValidated: idTokenIssuerValidated,
				emailVerified: user.emailVerified,
				// Attests a usable email from an authenticated source — never the username,
				// which may be a reassignable handle.
				emailAuthenticated:
					typeof user.email === 'string' &&
					user.email !== '' &&
					user.emailVerified === true &&
					provenance !== 'unauthenticated',
				email: user.email,
				idTokenIssuer: idTokenVerified ? toIdString(idTokenClaims?.iss) : undefined,
				idTokenSubject: idTokenVerified ? toIdString(idTokenClaims?.sub) : undefined,
			});
			Object.defineProperty(user, 'authEvidence', {
				value: authEvidence,
				enumerable: false,
				writable: false,
				configurable: false,
			});
		}

		// Call onLogin hook before storing session
		// This allows user provisioning plugins to create/update user records
		// Pass providerName (registry key) not config.provider (provider type) for multi-tenant support
		const hookData = await hookManager.callOnLogin(user, tokenResponse, request.session, request, providerName);

		// Structured outcome (#174): the hook can deny the login outright or
		// defer it pending a confirmation step. Either way no session is
		// created (and no MCP auth code is minted). Plain objects and
		// undefined keep the legacy enrich-only behavior.
		if (isGatedLoginOutcome(hookData)) {
			const denied = hookData.status === 'denied';
			const reason = denied ? hookData.error : undefined;
			logger?.info?.(
				`OAuth login ${denied ? 'denied' : 'deferred'} by onLogin hook for user: ${JSON.stringify(user.username)}`
			);
			if (mcpState) {
				// An MCP client can't follow an interactive confirmation step —
				// fail the authorization cleanly; the user completes the step in
				// the app and the client retries.
				return mcpErrorRedirect(
					mcpState,
					'access_denied',
					reason || (denied ? 'login denied by application' : 'confirmation required')
				);
			}
			if (hookData.redirect) {
				return { status: 302, headers: { Location: resolveHookRedirect(hookData.redirect) } };
			}
			const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
				error: 'access_denied',
				reason: reason || (denied ? 'denied' : 'confirmation_required'),
			});
			return { status: 302, headers: { Location: errorUrl } };
		}

		// Legacy behavior treats any other status value as session data, which
		// would silently un-gate a typo'd 'denied', so surface it.
		if (typeof hookData?.status === 'string' && hookData.status !== 'ok') {
			logger?.warn?.(
				`onLogin returned unrecognized status '${hookData.status}' — treated as session data (legacy behavior); use 'denied' or 'needs_confirmation' to gate the login`
			);
		}

		// Unify resolved identity from hook override or OAuth claim (one value for
		// both the MCP and session sinks); a hook-supplied empty string is preserved
		// for the non-empty guard below.
		const resolvedUser = hookData?.user ?? user.username;
		if (!resolvedUser || typeof resolvedUser !== 'string') {
			logger?.warn?.('OAuth: resolved identity is empty after login; denying');
			if (mcpState) return mcpErrorRedirect(mcpState, 'server_error', 'identity_resolution');
			return {
				status: 302,
				headers: {
					Location: buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
						error: 'auth_failed',
						reason: 'identity_resolution',
					}),
				},
			};
		}

		// Account-adoption gate: when no onLogin hook supplied the identity (i.e.
		// the username came directly from the IdP claim), verify the claim is
		// trustworthy before letting the login inherit an existing Harper account.
		//
		// A claim is trusted when ALL of the following hold:
		//   1. The resolved username IS the email claim value (not a reassignable
		//      claim like GitHub `login` or Okta `preferred_username`).
		//   2. The provider attests the email is verified (email_verified === true).
		//      For custom emailClaim values, emailVerified is always undefined (untrusted).
		//   3. The email came from one of exactly two AUTHENTICATED SOURCES:
		//      a. A JWKS-signature-verified OIDC id token whose issuer was validated
		//         against the provider's expected issuer ('signed-oidc'). Providers
		//         without a known issuer (Azure /common, issuer-less generic) are not
		//         trusted for adoption.
		//      b. GitHub's provider-authenticated /user/emails fetch, only when that
		//         fetch actually succeeded ('github-authenticated').
		//
		// Trust classification of the OAuth claim, hoisted so it can both gate
		// adoption and be stamped onto the session (its provenance must survive
		// refresh). Only meaningful when the identity came from the IdP claim.
		const claimIsTrusted =
			!hookData?.user &&
			typeof user.email === 'string' &&
			user.email === resolvedUser &&
			user.emailVerified === true &&
			((emailProvenance === 'signed-oidc' && idTokenSignatureVerified && idTokenIssuerValidated) ||
				(emailProvenance === 'github-authenticated' && config.provider === 'github'));
		let adoptedViaEscapeHatch = false;

		if (!hookData?.user) {
			const userExists = await checkHarperUserExists(resolvedUser);
			if (userExists !== false) {
				// A resolved account — or a lookup error, treated fail-closed — requires a
				// trusted claim to adopt.
				if (!claimIsTrusted) {
					if (allowUnverifiedClaimInheritance) {
						adoptedViaEscapeHatch = true;
						logger?.warn?.(
							`OAuth: adopting existing account ${JSON.stringify(resolvedUser)} via unverified claim ` +
								`(allowUnverifiedClaimInheritance is enabled — disable this setting to deny this login)`
						);
					} else {
						logger?.warn?.(
							`OAuth: login denied — claim for ${JSON.stringify(resolvedUser)} is not from an authenticated source; ` +
								`a verified email from a JWKS-signed token with a validated issuer, or ` +
								`GitHub's authenticated email fetch is required to adopt an existing account`
						);
						if (mcpState) {
							return mcpErrorRedirect(mcpState, 'access_denied', 'login_denied');
						}
						return {
							status: 302,
							headers: {
								Location: buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
									error: 'access_denied',
									reason: 'login_denied',
								}),
							},
						};
					}
				}
			} else if (!claimIsTrusted) {
				// No existing account and the claim is not from an authenticated source.
				// Persist an unpredictable, non-resolvable quarantine principal: because a
				// later hdb_user cannot be created to match the random suffix, this login
				// can never adopt a privileged account of the claim's name. The session is
				// roleless (the principal resolves to no hdb_user), and `oauthUser` — incl.
				// any app-level role claim — is preserved for the application's own authz.
				const quarantinePrincipal = makeQuarantinePrincipal(resolvedUser);
				logger?.warn?.(
					`OAuth: no existing account for ${JSON.stringify(resolvedUser)} and the claim is not from an ` +
						`authenticated source — establishing a roleless, non-adoptable session`
				);
				if (mcpState) {
					return handleMCPCallback(request, mcpState, quarantinePrincipal, mcpConfig ?? {}, logger);
				}
				if (request.session) {
					const now = Date.now();
					let expiresAt: number | undefined;
					let refreshThreshold: number | undefined;
					if (tokenResponse.expires_in) {
						const expiresIn = tokenResponse.expires_in;
						expiresAt = now + expiresIn * 1000;
						refreshThreshold = now + expiresIn * 800;
					}
					const sessionData: any = {
						user: quarantinePrincipal,
						oauthUser: user,
						oauth: {
							provider: providerName,
							providerConfigId: providerName,
							providerType: config.provider,
							accessToken: tokenResponse.access_token,
							refreshToken: tokenResponse.refresh_token,
							expiresAt,
							refreshThreshold,
							scope: tokenResponse.scope,
							tokenType: tokenResponse.token_type || 'Bearer',
							lastRefreshed: now,
							authTrust: 'untrusted',
						},
					};
					if (hookData) {
						const { user: _u, ...remainingHookData } = hookData;
						if (remainingHookData.status === 'ok') delete remainingHookData.status;
						// Plugin-owned session fields must not be overwritten by hook enrichment.
						delete remainingHookData.oauth;
						delete remainingHookData.oauthUser;
						Object.assign(sessionData, remainingHookData);
					}
					if (typeof request.session.update === 'function') {
						await request.session.update(sessionData);
					} else {
						Object.assign(request.session, sessionData);
					}
					logger?.info?.(`OAuth: login successful (roleless, non-adoptable) for ${JSON.stringify(resolvedUser)}`);
				}
				return {
					status: 302,
					headers: {
						Location: sanitizeRedirect(tokenData.originalUrl || config.postLoginRedirect || '/'),
					},
				};
			}
		}

		// MCP branch: if the CSRF state was minted by /oauth/mcp/authorize, the
		// upstream callback's job is to mint an MCP authorization code, NOT to
		// create a Harper session. Independent lifecycle per #86 resolved
		// decision. The upstream IdP token never reaches the MCP client.
		// Pass the resolved username so the issued auth code (and the JWT
		// exchanged for it in Stage 4) is bound to the correct identity.
		if (mcpState) {
			// Browser binding already verified above, before the code exchange.
			return handleMCPCallback(request, mcpState, resolvedUser, mcpConfig ?? {}, logger);
		}

		// Store in session if available
		if (request.session) {
			// Calculate token expiration and refresh thresholds
			// For providers that don't return expires_in (like GitHub), tokens don't expire
			// so we don't set expiration/refresh thresholds to avoid premature session cleanup
			const now = Date.now();
			let expiresAt: number | undefined;
			let refreshThreshold: number | undefined;

			if (tokenResponse.expires_in) {
				// Token has expiration - calculate thresholds
				const expiresIn = tokenResponse.expires_in;
				expiresAt = now + expiresIn * 1000;
				refreshThreshold = now + expiresIn * 800; // Refresh at 80% of lifetime
			}
			// else: No expires_in means token doesn't expire (e.g., GitHub)
			// Leave expiresAt and refreshThreshold undefined so middleware doesn't try to refresh

			// Provenance of this established identity. Reaching here (non-quarantine)
			// means a hook supplied the user, an authenticated claim was trusted, or an
			// unverified claim adopted an account via the operator escape hatch.
			const authTrust: AuthTrust = hookData?.user ? 'hook' : adoptedViaEscapeHatch ? 'operator-override' : 'verified';

			// Prepare session data
			const sessionData: any = {
				user: resolvedUser, // Hook-supplied override or OAuth claim (unified above)
				oauthUser: user, // Store full OAuth user object separately
				oauth: {
					provider: providerName, // Config key (backwards compatible - e.g., 'my-custom-github', 'production-okta')
					providerConfigId: providerName, // Config key/ID (clearer naming for new code)
					providerType: config.provider, // Provider type (e.g., 'github', 'okta')
					accessToken: tokenResponse.access_token,
					refreshToken: tokenResponse.refresh_token,
					expiresAt,
					refreshThreshold,
					scope: tokenResponse.scope,
					tokenType: tokenResponse.token_type || 'Bearer',
					lastRefreshed: now,
					authTrust,
				},
			};

			// Merge remaining hook data into session if provided (excluding 'user' since we already used it)
			if (hookData) {
				// eslint-disable-next-line @typescript-eslint/no-unused-vars, sonarjs/no-unused-vars
				const { user, ...remainingHookData } = hookData;
				// `status: 'ok'` is flow control (#174), not session data; any
				// other status value is passed through as before.
				if (remainingHookData.status === 'ok') delete remainingHookData.status;
				// Plugin-owned session fields must not be overwritten by hook enrichment.
				delete remainingHookData.oauth;
				delete remainingHookData.oauthUser;
				Object.assign(sessionData, remainingHookData);
			}

			// Store user info and OAuth metadata in session
			if (typeof request.session.update === 'function') {
				await request.session.update(sessionData);
			} else {
				Object.assign(request.session, sessionData);
			}

			logger?.info?.(
				`OAuth login successful for user: ${JSON.stringify(user.username)}${tokenResponse.expires_in ? `, token expires in ${tokenResponse.expires_in}s` : ', token does not expire'}`
			);
		} else {
			logger?.warn?.('No session available for OAuth user');
		}

		// Redirect to original URL or default (sanitize to prevent open redirect)
		return {
			status: 302,
			headers: {
				Location: sanitizeRedirect(tokenData.originalUrl || config.postLoginRedirect || '/'),
			},
		};
	} catch (error) {
		logger?.error?.('OAuth callback error:', error);
		// Use a safe, generic reason code — details are in the server log
		const message = error instanceof Error ? error.message : String(error);
		let reason = 'unknown';
		if (message.startsWith('Token exchange failed')) reason = 'token_exchange';
		else if (message.includes('claim')) reason = 'user_mapping';
		else if (message.includes('user info') || message.includes('userinfo')) reason = 'user_info';
		else if (message.includes('hook') || message.includes('onLogin')) reason = 'login_hook';
		if (mcpState) {
			return mcpErrorRedirect(mcpState, 'server_error', reason);
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'auth_failed',
			reason,
		});
		return { status: 302, headers: { Location: errorUrl } };
	}
}

/**
 * Clear OAuth session data and log out (explicit logout and token-expiry logout).
 * Harper 5's request.session is a shallow copy with only `.update` (a full-replace put) and
 * no `.delete`; in-memory mutation never persists — so invalidate by persisting `{ user: null }`,
 * mirroring Harper's own logout().
 */
export async function clearOAuthSession(session: any, logger?: Logger): Promise<void> {
	if (!session) return;

	// Persist only for an existing session: `.update` on an anonymous request would mint a
	// fresh, non-expiring hdb_session row.
	if (session.id && typeof session.update === 'function') {
		await session.update({ user: null });
	}
	// Clear in memory too so the current request sees no identity.
	session.user = null;
	delete session.oauth;
	delete session.oauthUser;

	logger?.info?.('OAuth session cleared');
}

/**
 * Handle user logout
 */
export async function handleLogout(request: Request, hookManager: HookManager, logger?: Logger): Promise<any> {
	// Call onLogout hook before clearing session
	await hookManager.callOnLogout(request.session, request);

	// Clear the OAuth session
	await clearOAuthSession(request.session, logger);

	return {
		status: 200,
		body: { message: 'Logged out successfully' },
	};
}

/**
 * Get current user info
 */
export async function handleUserInfo(request: Request, tokenRefreshed = false): Promise<any> {
	// Add debug logging
	if (!request) {
		return {
			status: 500,
			body: { error: 'Request object not provided' },
		};
	}

	// Check for OAuth user in session first, then Harper user
	const oauthUser = request?.session?.oauthUser;
	const oauthMetadata = request?.session?.oauth;
	const sessionUser = request?.session?.user;
	const username = request?.user || sessionUser;

	if (!username && !oauthUser) {
		return {
			status: 401,
			body: {
				authenticated: false,
				message: 'Not authenticated',
			},
		};
	}

	// A roleless, untrusted session carries a non-resolvable quarantine principal
	// (authTrust === 'untrusted'). Report role: null and the IdP-derived identity
	// rather than leaking the opaque principal. Trust the stamp first; only fall
	// back to the principal's shape for a legacy session with no stamp, so a
	// verified/hook account that happens to be named like a quarantine principal is
	// not misreported as roleless.
	const trust = oauthMetadata?.authTrust;
	const isUntrusted = trust === 'untrusted' || (trust == null && isQuarantinePrincipal(sessionUser));

	if (isUntrusted) {
		return {
			status: 200,
			body: {
				authenticated: true,
				username: oauthUser?.username ?? oauthUser?.email ?? null,
				role: null,
				email: oauthUser?.email ?? null,
				name: oauthUser?.name ?? null,
				provider: oauthUser?.provider ?? oauthMetadata?.providerType ?? null,
				oauth: oauthMetadata
					? {
							provider: oauthMetadata.provider,
							providerConfigId: oauthMetadata.providerConfigId,
							providerType: oauthMetadata.providerType,
							expiresAt: oauthMetadata.expiresAt,
							refreshThreshold: oauthMetadata.refreshThreshold,
							lastRefreshed: oauthMetadata.lastRefreshed,
							hasRefreshToken: !!oauthMetadata.refreshToken,
							tokenRefreshed,
						}
					: undefined,
			},
		};
	}

	// If we have OAuth user details, use those (for trusted/normal sessions only)
	if (oauthUser && !isUntrusted) {
		return {
			status: 200,
			body: {
				authenticated: true,
				username: oauthUser.username,
				role: oauthUser.role,
				email: oauthUser.email,
				name: oauthUser.name,
				provider: oauthUser.provider,
				// Include OAuth token status in debug mode
				oauth: oauthMetadata
					? {
							provider: oauthMetadata.provider,
							providerConfigId: oauthMetadata.providerConfigId,
							providerType: oauthMetadata.providerType,
							expiresAt: oauthMetadata.expiresAt,
							refreshThreshold: oauthMetadata.refreshThreshold,
							lastRefreshed: oauthMetadata.lastRefreshed,
							hasRefreshToken: !!oauthMetadata.refreshToken,
							tokenRefreshed,
						}
					: undefined,
			},
		};
	}

	// Fall back to Harper user - extract just the username string and role name
	const usernameString = typeof username === 'string' ? username : (username as any)?.username;
	const roleData = typeof username === 'object' ? (username as any)?.role : (request as any)?.user?.role;

	// Extract role name - Harper roles can be objects with id/name or just strings
	const roleName = typeof roleData === 'string' ? roleData : roleData?.id || roleData?.name || 'user';

	return {
		status: 200,
		body: {
			authenticated: true,
			username: usernameString,
			role: roleName,
			email: null,
			name: null,
			provider: 'harper',
		},
	};
}

/**
 * Serve OAuth test page
 */
export async function handleTestPage(logger?: Logger): Promise<any> {
	try {
		const __dirname = dirname(fileURLToPath(import.meta.url));
		const testHtml = await readFile(join(__dirname, '..', '..', 'assets', 'test.html'), 'utf8');

		return {
			status: 200,
			headers: {
				'Content-Type': 'text/html',
			},
			body: testHtml,
		};
	} catch (error) {
		logger?.error?.('Failed to load test page:', error);
		return {
			status: 500,
			body: { error: 'Failed to load test page' },
		};
	}
}
