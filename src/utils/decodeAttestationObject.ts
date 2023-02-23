// copy-🍝 from https://github.com/MasterKale/SimpleWebAuthn/blob/33528afe001d4aca62052dce204c0398c3127ffd/packages/server/src/helpers/decodeAttestationObject.ts#L8

/**
 * Convert an AttestationObject buffer to a proper object
 *
 * @param base64AttestationObject Attestation Object buffer
 */
export function decodeAttestationObject(
	cbor: any,
	attestationObject: Buffer
): AttestationObject {
	const toCBOR: AttestationObject = cbor.decodeAllSync(attestationObject)[0];
	return toCBOR;
}

export type AttestationFormat =
	| "fido-u2f"
	| "packed"
	| "android-safetynet"
	| "android-key"
	| "tpm"
	| "apple"
	| "none";

export type AttestationObject = {
	fmt: AttestationFormat;
	attStmt: AttestationStatement;
	authData: Buffer;
};

export type AttestationStatement = {
	sig?: Buffer;
	x5c?: Buffer[];
	response?: Buffer;
	alg?: number;
	ver?: string;
	certInfo?: Buffer;
	pubArea?: Buffer;
};
