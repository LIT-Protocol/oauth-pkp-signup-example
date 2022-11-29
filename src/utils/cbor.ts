// copy-🍝 from https://github.com/MasterKale/SimpleWebAuthn/blob/33528afe001d4aca62052dce204c0398c3127ffd/packages/server/src/helpers/decodeCbor.ts

export function decodeCborFirst(
	cbor: any,
	input:
		| string
		| Buffer
		| ArrayBuffer
		| Uint8Array
		| Uint8ClampedArray
		| DataView
): any {
	try {
		// throws if there are extra bytes
		return cbor.decodeFirstSync(input);
	} catch (err) {
		const _err = err as CborDecoderError;
		// if the error was due to extra bytes, return the unpacked value
		if (_err.value) {
			return _err.value;
		}
		throw err;
	}
}

/**
 * Intuited from a quick scan of `cbor.decodeFirstSync()` here:
 *
 * https://github.com/hildjj/node-cbor/blob/v5.1.0/lib/decoder.js#L189
 */
class CborDecoderError extends Error {
	value: any;
}
