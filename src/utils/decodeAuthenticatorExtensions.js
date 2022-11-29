// copy-🍝 from https://github.com/MasterKale/SimpleWebAuthn/blob/33528afe001d4aca62052dce204c0398c3127ffd/packages/server/src/helpers/decodeAuthenticatorExtensions.ts

/**
 * Convert authenticator extension data buffer to a proper object
 *
 * @param extensionData Authenticator Extension Data buffer
 */
export function decodeAuthenticatorExtensions(cbor, extensionData) {
	let toCBOR;
	try {
		toCBOR = cbor.decodeAllSync(extensionData)[0];
	} catch (err) {
		const _err = err;
		throw new Error(
			`Error decoding authenticator extensions: ${_err.message}`
		);
	}
	return toCBOR;
}
