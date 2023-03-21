import { nanoid } from "nanoid";

const STATE_PARAM_KEY = "lit-state-param";

/**
 * Redirect user to the Google authorization page
 */
export function signInWithGoogle(redirectUri: string): void {
	// Get login url
	const loginUrl = prepareLoginUrl(redirectUri);
	// Redirect to login url
	window.location.assign(loginUrl);
}

/**
 * Parse the redirect url and return the Google ID token
 */
export function handleSignInRedirect(redirectUri: string): string | null {
	// Check if current url matches redirect uri
	if (!window.location.href.startsWith(redirectUri)) {
		throw new Error(
			`Current url "${window.location.href}" does not match provided redirect uri "${redirectUri}"`
		);
	}

	// Check url for params
	const { provider, idToken, state, error } = parseLoginParams(
		window.document.location.search
	);

	// Check if there's an error
	if (error) {
		throw new Error(error);
	}

	// Check if provider exists and is supported
	if (provider !== "google") {
		throw new Error(
			`Invalid OAuth provider "${provider}" passed in redirect callback URL`
		);
	}

	// Check if state param matches
	if (!state || decode(decodeURIComponent(state)) !== getStateParam()) {
		throw new Error(
			`Invalid state parameter "${state}" passed in redirect callback URL`
		);
	}
	removeStateParam();

	// Clear params from url
	window.history.replaceState({}, document.title, redirectUri);

	// Return Google ID token
	return idToken;
}

/**
 * Check if current url is redirect uri to determine if app was redirected back from external login page
 */
export function isSignInRedirect(redirectUri: string): boolean {
	// Check if current url matches redirect uri
	const isRedirectUri = window.location.href.startsWith(redirectUri);
	if (!isRedirectUri) {
		return false;
	}
	// Check url for redirect params
	const { provider, accessToken, idToken, state, error } = parseLoginParams(
		window.document.location.search
	);
	// Check if current url is redirect uri and has redirect params
	if (
		isRedirectUri &&
		(provider || accessToken || idToken || state || error)
	) {
		return true;
	}
	return false;
}

// --- Utils

/**
 * Create login url using the parameters provided as arguments when initializing the client
 */
function prepareLoginUrl(redirectUri: string): string {
	const baseUrl = "https://lit-login-server.herokuapp.com/auth/google";
	const state = encode(setStateParam());
	const authParams = {
		app_redirect: redirectUri,
	};
	const queryAuthParams = createQueryParams(authParams);
	return `${baseUrl}?${queryAuthParams}&state=${state}`;
}

/**
 * Create query params string from given object
 *
 * @param params {any} - Object of query params
 *
 * @returns {string} - Query string
 */
function createQueryParams(params: any) {
	// Strip undefined values from params
	const filteredParams = Object.keys(params)
		.filter(k => typeof params[k] !== "undefined")
		.reduce((acc, key) => ({ ...acc, [key]: params[key] }), {});
	// Create query string
	return new URLSearchParams(filteredParams).toString();
}

/**
 * Parse out login parameters from the query string
 *
 * @param {string} search - Query string
 *
 * @returns {LoginUrlParams} - Login url params
 */
function parseLoginParams(search: string): LoginUrlParams {
	const searchParams = new URLSearchParams(search);
	const provider = searchParams.get("provider");
	const accessToken = searchParams.get("access_token");
	const idToken = searchParams.get("id_token");
	const state = searchParams.get("state");
	const error = searchParams.get("error");

	return {
		provider,
		accessToken,
		idToken,
		state,
		error,
	};
}

/**
 * Get OAuth 2.0 state param from session storage
 *
 * @returns {string} - State param
 */
function getStateParam(): string | null {
	return sessionStorage.getItem(STATE_PARAM_KEY);
}

/**
 * Create OAuth 2.0 state param and store it in session storage
 *
 * @returns {string} - State param
 */
function setStateParam(): string {
	const state = nanoid(15);
	sessionStorage.setItem(STATE_PARAM_KEY, state);
	return state;
}

/**
 * Remove OAuth 2.0 state param from session storage
 *
 * @returns {void}
 */
function removeStateParam(): void {
	return sessionStorage.removeItem(STATE_PARAM_KEY);
}

/**
 * Encode a string with base64
 *
 * @param value {string} - String to encode
 *
 * @returns {string} - Encoded string
 */
function encode(value: string): string {
	return window.btoa(value);
}

/**
 * Decode a string with base64
 *
 * @param value {string} - String to decode
 *
 * @returns {string} - Decoded string
 */
function decode(value: string): string {
	return window.atob(value);
}

// --- Types

interface LoginUrlParams {
	/**
	 * Auth method name
	 */
	provider: string | null;
	/**
	 * Access token
	 */
	accessToken: string | null;
	/**
	 * ID token
	 */
	idToken: string | null;
	/**
	 * OAuth state param
	 */
	state: string | null;
	/**
	 * Error codes from Lit's auth server
	 */
	error: string | null;
}
