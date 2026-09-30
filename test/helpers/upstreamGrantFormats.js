/**
 * What a node running @harperfast/oauth 2.7.0 (the release before the
 * client-authentication binding) writes and reads, for migration tests.
 *
 * The encoders and the provenance reader are copied from 2.7.0's
 * `refreshTokenStore.ts` and `authCodeStore.ts`; the refresh decision follows
 * the order of 2.7.0's `handleRefreshTokenGrant`. Two facts matter here:
 *
 * - Its encoders write the whole record from a fixed field list that has no
 *   `client_auth_method`, so any family it rotates, or code it writes, loses
 *   the binding.
 * - Its provenance reader accepts only `p1-` family ids and retires every
 *   other id, `p2-` included. 2.6.0 has no provenance reader: it rotates a
 *   live family on a token-hash match whatever its id, and its family
 *   encoder is the same.
 *
 * It authenticated interactive CIMD clients as public clients (`none`),
 * without reading any assertion parameters, and stored clients by their
 * registered method; it never read a binding.
 */

/** 2.7.0 `refreshTokenStore.ts` encodeRecord. */
export function upstreamEncodeFamily(record) {
	return {
		family_id: record.family_id,
		current_token_hash: record.current_token_hash,
		revoked: record.revoked,
		client_id: record.client_id,
		user: record.user,
		resource: record.resource,
		scope: record.scope,
		expires_at: record.expires_at,
	};
}

/** 2.7.0 `authCodeStore.ts` encodeRecord. */
export function upstreamEncodeCode(record) {
	return {
		code: record.code,
		client_id: record.client_id,
		user: record.user,
		resource: record.resource,
		code_challenge: record.code_challenge,
		code_challenge_method: record.code_challenge_method,
		redirect_uri: record.redirect_uri,
		scope: record.scope,
	};
}

/** 2.7.0 `FAMILY_ID_PREFIX`. */
export const UPSTREAM_FAMILY_ID_PREFIX = 'p1-';

/** 2.7.0 `isProvenancedFamilyId`. */
export function upstreamIsProvenancedFamilyId(id) {
	return id.startsWith(UPSTREAM_FAMILY_ID_PREFIX);
}

/**
 * How 2.6.0 and 2.7.0 treat an interactive CIMD document's authentication:
 * a singular `token_endpoint_auth_method` other than `none` rejects the
 * document (null here); otherwise the client is public (`none`), whatever
 * `token_endpoint_auth_methods_supported` lists.
 */
export function upstreamInteractiveDocumentMethod(doc) {
	const authMethod = typeof doc.token_endpoint_auth_method === 'string' ? doc.token_endpoint_auth_method : 'none';
	return authMethod === 'none' ? 'none' : null;
}

/**
 * 2.7.0's refresh outcome for a family whose client already authenticated,
 * in its order: missing, revoked or expired → 'reject'; another client →
 * 'reject'; a superseded token → 'revoke'; a non-`p1-` id → 'retire'; else
 * 'rotate'. With `provenanceReader: false`, a 2.6.0 node, which has no
 * retirement step. `client_auth_method` is never read.
 */
export function upstreamRefreshOutcome(
	family,
	{ clientId, presentedHash, nowSeconds = Math.floor(Date.now() / 1000), provenanceReader = true }
) {
	if (!family || family.revoked || family.expires_at <= nowSeconds) return 'reject';
	if (family.client_id !== clientId) return 'reject';
	if (presentedHash !== family.current_token_hash) return 'revoke';
	if (provenanceReader && !upstreamIsProvenancedFamilyId(family.family_id)) return 'retire';
	return 'rotate';
}

/**
 * 2.7.0's code-exchange checks after client authentication: the code exists,
 * belongs to the client and matches the redirect URI; PKCE is checked by the
 * caller. `client_auth_method` is never read.
 */
export function upstreamCodeRedeemable(record, { clientId, redirectUri }) {
	return Boolean(record) && record.client_id === clientId && record.redirect_uri === redirectUri;
}
