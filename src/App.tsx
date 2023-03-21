import * as LitJsSdk_accessControlConditions from "@lit-protocol/access-control-conditions";
import * as LitJsSdk_blsSdk from "@lit-protocol/bls-sdk";
import { AccsDefaultParams } from "@lit-protocol/constants";
import * as LitJsSdk from "@lit-protocol/lit-node-client";
import { Button, ButtonGroup } from "@mui/material";
// import { GoogleLogin } from "@react-oauth/google";
import {
	startAuthentication,
	startRegistration,
} from "@simplewebauthn/browser";
import base64url from "base64url";
import { utils } from "ethers";
import { hexlify } from "ethers/lib/utils";
import { useEffect, useState } from "react";
import "./App.css";
import { decodeAttestationObject } from "./utils/decodeAttestationObject";
import { parseAuthenticatorData } from "./utils/parseAuthenticatorData";
import {
	signInWithGoogle,
	handleSignInRedirect,
	isSignInRedirect,
} from "./utils/google";

type CredentialResponse = any;

declare global {
	interface Window {
		cbor: any;
	}
}

const RELAY_API_URL =
	process.env.REACT_APP_RELAY_API_URL || "http://localhost:3001";
const RELAY_API_KEY =
	process.env.REACT_APP_RELAY_API_KEY || "test-relay-api-key";
const REDIRECT_URI =
	process.env.REACT_APP_REDIRECT_URI || "http://localhost:3000";

function App() {
	const [pkpEthAddress, setPkpEthAddress] = useState<string>("");
	const [
		googleCredentialResponse,
		setGoogleCredentialResponse,
	] = useState<CredentialResponse | null>(null);
	const [pkpPublicKey, setPkpPublicKey] = useState<string>("");
	const [status, setStatus] = useState("");
	const [selectedAuthMethod, setSelectedAuthMethod] = useState(6);
	const [
		webAuthnCredentialPublicKey,
		setWebAuthnCredentialPublicKey,
	] = useState<string>("");
	const [webAuthnSignature, setWebAuthnSignature] = useState<string>("");
	const [webAuthnSignatureBase, setWebAuthnSignatureBase] = useState<string>(
		""
	);

	const handleLoggedInToGoogle = async (
		credentialResponse: CredentialResponse
	) => {
		setStatus("Logged in to Google");
		console.log("Got response from google sign in: ", {
			credentialResponse,
		});
		setGoogleCredentialResponse(credentialResponse);
		const requestId = await mintPkpUsingRelayerGoogleAuthVerificationEndpoint(
			credentialResponse,
			setStatus
		);
		await pollRequestUntilTerminalState(
			requestId,
			setStatus,
			({ pkpEthAddress, pkpPublicKey }) => {
				setPkpEthAddress(pkpEthAddress);
				setPkpPublicKey(pkpPublicKey);
			}
		);
	};

	useEffect(() => {
		if (isSignInRedirect(REDIRECT_URI)) {
			const idToken = handleSignInRedirect(REDIRECT_URI);
			if (idToken) {
				try {
					handleLoggedInToGoogle({
						credential: idToken,
					});
				} catch (err) {
					console.error(err);
					setStatus(
						"Uh oh, something went wrong. Check the console for error logs."
					);
				}
			}
		}
	}, []);

	return (
		<div className="App">
			<div style={{ height: 80 }} />
			<h1>Welcome To The PKP Demo!</h1>
			<div style={{ height: 24 }} />
			<h3>Choose an authentication method to begin:</h3>
			<ButtonGroup variant="outlined">
				<Button
					variant={
						selectedAuthMethod === 6 ? "contained" : "outlined"
					}
					onClick={() => setSelectedAuthMethod(6)}
				>
					Google
				</Button>
				<Button
					variant={
						selectedAuthMethod === 3 ? "contained" : "outlined"
					}
					onClick={() => setSelectedAuthMethod(3)}
				>
					WebAuthn
				</Button>
			</ButtonGroup>
			<div style={{ height: 24 }} />
			<h1>{status}</h1>
			<div style={{ height: 24 }} />
			{selectedAuthMethod === 6 && (
				<>
					<h3>
						Step 1: log in with Google. Upon OAuth success, we will
						mint a PKP on your behalf.
					</h3>
					{/* <GoogleLogin
						onSuccess={handleLoggedInToGoogle}
						onError={() => {
							console.log("Login Failed");
						}}
						useOneTap
					/> */}
					<Button
						variant="contained"
						onClick={() => {
							signInWithGoogle(REDIRECT_URI);
						}}
					>
						Sign in with Google
					</Button>

					{pkpEthAddress && (
						<div>PKP Eth Address: {pkpEthAddress}</div>
					)}
					<h3>
						<s>
							Step 2: Use Lit Network to obtain a session sig and
							then store an encryption condition.
						</s>
						(Session Sigs do not work currently.)
					</h3>
					<button
						onClick={() =>
							handleStoreEncryptionCondition(
								setStatus,
								selectedAuthMethod,
								googleCredentialResponse,
								{
									signature: "dummy",
									signatureBase: "dummy",
									credentialPublicKey: "dummy",
								},
								pkpEthAddress,
								pkpPublicKey
							)
						}
					>
						Encrypt with Lit
					</button>
				</>
			)}
			{selectedAuthMethod === 3 && (
				<>
					<h3>Step 1: Register using WebAuthn.</h3>
					<Button
						variant="contained"
						onClick={async () => {
							await handleWebAuthnRegister(
								setStatus,
								({ attResp }) => {
									const attestationObject = base64url.toBuffer(
										attResp.response.attestationObject
									);

									const {
										authData,
									} = decodeAttestationObject(
										window.cbor,
										attestationObject
									);

									const parsedAuthData = parseAuthenticatorData(
										window.cbor,
										authData
									);

									console.log(
										"storing credential public key in browser",
										{
											credentialPublicKey:
												parsedAuthData.credentialPublicKey,
										}
									);

									// set in local state
									setWebAuthnCredentialPublicKey(
										hexlify(
											parsedAuthData.credentialPublicKey!
										)
									);
								}
							);
						}}
					>
						Register
					</Button>
					<h3>Step 2: Authenticate using WebAuthn to mint PKP.</h3>
					<Button
						variant="contained"
						onClick={async () => {
							await handleWebAuthnAuthenticate(
								setStatus,
								webAuthnCredentialPublicKey,
								({ pkpEthAddress, pkpPublicKey }) => {
									setPkpEthAddress(pkpEthAddress);
									setPkpPublicKey(pkpPublicKey);
								},
								setWebAuthnSignature,
								setWebAuthnSignatureBase
							);
						}}
					>
						Authenticate
					</Button>
					<h3>
						<s>
							Step 3: Use Lit Network to obtain a session sig and
							then store an encryption condition.
						</s>
						(Session Sigs do not work currently.)
					</h3>
					<Button
						variant="contained"
						onClick={() =>
							handleStoreEncryptionCondition(
								setStatus,
								selectedAuthMethod,
								googleCredentialResponse,
								{
									signature: webAuthnSignature,
									signatureBase: webAuthnSignatureBase,
									credentialPublicKey: webAuthnCredentialPublicKey,
								},
								pkpEthAddress,
								pkpPublicKey
							)
						}
					>
						Encrypt With Lit
					</Button>
				</>
			)}
		</div>
	);
}

export default App;

async function mintPkpUsingRelayerGoogleAuthVerificationEndpoint(
	credentialResponse: any,
	setStatusFn: (status: string) => void
) {
	setStatusFn("Minting PKP with relayer...");

	const mintRes = await fetch(`${RELAY_API_URL}/auth/google`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"api-key": RELAY_API_KEY,
		},
		body: JSON.stringify({
			idToken: credentialResponse.credential,
		}),
	});

	if (mintRes.status < 200 || mintRes.status >= 400) {
		console.warn("Something wrong with the API call", await mintRes.json());
		setStatusFn("Uh oh, something's not quite right.");
		return null;
	} else {
		const resBody = await mintRes.json();
		console.log("Response OK", { body: resBody });
		setStatusFn("Successfully initiated minting PKP with relayer.");
		return resBody.requestId;
	}
}

async function mintPkpUsingRelayerWebAuthnVerificationEndpoint(
	signature: string,
	signatureBase: string,
	credentialPublicKey: string,
	setStatusFn: (status: string) => void
) {
	setStatusFn("Minting PKP with relayer...");

	const mintRes = await fetch(`${RELAY_API_URL}/auth/webauthn`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"api-key": RELAY_API_KEY,
		},
		body: JSON.stringify({
			signature,
			signatureBase,
			credentialPublicKey,
		}),
	});

	if (mintRes.status < 200 || mintRes.status >= 400) {
		console.warn("Something wrong with the API call", await mintRes.json());
		setStatusFn("Uh oh, something's not quite right.");
		return null;
	} else {
		const resBody = await mintRes.json();
		console.log("Response OK", { body: resBody });
		setStatusFn("Successfully initiated minting PKP with relayer.");
		return resBody.requestId;
	}
}

async function pollRequestUntilTerminalState(
	requestId: string,
	setStatusFn: (status: string) => void,
	onSuccess: ({
		pkpEthAddress,
		pkpPublicKey,
	}: {
		pkpEthAddress: string;
		pkpPublicKey: string;
	}) => void
) {
	if (!requestId) {
		return;
	}

	const maxPollCount = 20;
	for (let i = 0; i < maxPollCount; i++) {
		setStatusFn(`Waiting for auth completion (poll #${i + 1})`);
		const getAuthStatusRes = await fetch(
			`${RELAY_API_URL}/auth/status/${requestId}`,
			{
				method: "GET",
				headers: {
					"api-key": RELAY_API_KEY,
				},
			}
		);

		if (getAuthStatusRes.status < 200 || getAuthStatusRes.status >= 400) {
			console.warn(
				"Something wrong with the API call",
				await getAuthStatusRes.json()
			);
			setStatusFn("Uh oh, something's not quite right.");
			return;
		}

		const resBody = await getAuthStatusRes.json();
		console.log("Response OK", { body: resBody });

		if (resBody.error) {
			// exit loop since error
			console.warn("Something wrong with the API call", {
				error: resBody.error,
			});
			setStatusFn("Uh oh, something's not quite right.");
			return;
		} else if (resBody.status === "Succeeded") {
			// exit loop since success
			console.info("Successfully authed", { ...resBody });
			setStatusFn("Successfully authed and minted PKP!");
			onSuccess({
				pkpEthAddress: resBody.pkpEthAddress,
				pkpPublicKey: resBody.pkpPublicKey,
			});
			return;
		}

		// otherwise, sleep then continue polling
		await new Promise(r => setTimeout(r, 15000));
	}

	// at this point, polling ended and still no success, set failure status
	setStatusFn(`Hmm this is taking longer than expected...`);
}

async function handleStoreEncryptionCondition(
	setStatusFn: (status: string) => void,
	selectedAuthMethod: number,
	googleCredentialResponse: any,
	webAuthnVerificationMaterial: {
		signature: string;
		signatureBase: string;
		credentialPublicKey: string;
	},
	pkpEthAddress: string,
	pkpPublicKey: string
) {
	setStatusFn("Storing encryption condition...");
	var unifiedAccessControlConditions: AccsDefaultParams[] = [
		{
			conditionType: "evmBasic",
			contractAddress: "",
			standardContractType: "",
			chain: "mumbai",
			method: "",
			parameters: [":userAddress"],
			returnValueTest: {
				comparator: "=",
				value: pkpEthAddress,
			},
		},
	];

	// this will be fired if auth is needed. we can use this to prompt the user to sign in
	const authNeededCallback = async ({
		chain,
		resources,
		expiration,
		uri,
		litNodeClient,
	}: any) => {
		console.log("authNeededCallback fired");
		const authMethods =
			selectedAuthMethod === 6
				? [
						{
							authMethodType: 6,
							accessToken: googleCredentialResponse.credential,
						},
				  ]
				: [
						{
							authMethodType: 3,
							accessToken: JSON.stringify(
								webAuthnVerificationMaterial
							),
						},
				  ];
		const sessionSig = await litNodeClient.signSessionKey({
			sessionKey: uri,
			authMethods,
			pkpPublicKey,
			expiration,
			resources,
			chain,
		});
		console.log("got session sig from node and PKP: ", sessionSig);
		return sessionSig;
	};

	// get the user a session with it
	const litNodeClient = new LitJsSdk.LitNodeClient({
		litNetwork: "serrano",
	});
	await litNodeClient.connect();

	const sessionSigs = await litNodeClient.getSessionSigs({
		expiration: new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(), // 24 hours
		chain: "ethereum",
		resources: [`litEncryptionCondition://*`],
		switchChain: false,
		authNeededCallback,
	});
	console.log("sessionSigs before saving encryption key: ", sessionSigs);

	const { encryptedZip, symmetricKey } = await LitJsSdk.zipAndEncryptString(
		"this is a secret message"
	);

	// value parameter - hash unified conditions
	const hashedAccessControlConditions = await LitJsSdk_accessControlConditions.hashUnifiedAccessControlConditions(
		unifiedAccessControlConditions
	);
	console.log("hashedAccessControlConditions", {
		hashedAccessControlConditions,
	});
	const hashedAccessControlConditionsStr = LitJsSdk.uint8arrayToString(
		new Uint8Array(hashedAccessControlConditions),
		"base16"
	);

	// key parameter - encrypt symmetric key then hash it
	const encryptedSymmetricKey = LitJsSdk_blsSdk.wasmBlsSdkHelpers.encrypt(
		LitJsSdk.uint8arrayFromString(litNodeClient.subnetPubKey, "base16"),
		symmetricKey
	);
	const hashedEncryptedSymmetricKeyStr = await hashBytes({
		bytes: new Uint8Array(encryptedSymmetricKey),
	});

	// securityHash parameter - encrypt symmetric key, concat with creator address
	const pkpEthAddressBytes = utils.arrayify(pkpEthAddress);
	const securityHashPreimage = new Uint8Array([
		...encryptedSymmetricKey,
		...pkpEthAddressBytes,
	]);

	const securityHashStr = await hashBytes({
		bytes: securityHashPreimage,
	});

	console.log("Storing encryption condition with relay", {
		hashedEncryptedSymmetricKeyStr,
		hashedAccessControlConditionsStr,
		securityHashStr,
		sessionSig: sessionSigs["https://serrano.litgateway.com:7370"],
	});

	// call centralized conditions relayer to write encryption conditions to chain.
	const storeRes = await fetch(`${RELAY_API_URL}/store-condition`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"api-key": RELAY_API_KEY,
		},
		body: JSON.stringify({
			key: hashedEncryptedSymmetricKeyStr,
			value: hashedAccessControlConditionsStr,
			securityHash: securityHashStr,
			chainId: "1",
			permanent: false,
			capabilityProtocolPrefix: "litEncryptionCondition",
			// just choose any one session signature that is generated.
			sessionSig: sessionSigs["https://serrano.litgateway.com:7370"],
		}),
	});

	if (storeRes.status < 200 || storeRes.status >= 400) {
		console.warn(
			"Something wrong with the API call",
			await storeRes.json()
		);
		setStatusFn("Uh oh, something's not quite right");
	} else {
		setStatusFn("Successfully stored encryption condition with relayer!");
	}
}

async function hashBytes({ bytes }: { bytes: Uint8Array }): Promise<string> {
	const hashOfBytes = await crypto.subtle.digest("SHA-256", bytes);
	const hashOfBytesStr = LitJsSdk.uint8arrayToString(
		new Uint8Array(hashOfBytes),
		"base16"
	);
	return hashOfBytesStr;
}

// async function handleEncryptThenDecrypt(
// 	setStatusFn,
// 	googleCredentialResponse,
// 	pkpEthAddress,
// 	pkpPublicKey
// ) {
// 	setStatusFn("Encrypting then decrypting...");
// 	var unifiedAccessControlConditions = [
// 		{
// 			conditionType: "evmBasic",
// 			contractAddress: "",
// 			standardContractType: "",
// 			chain: "mumbai",
// 			method: "",
// 			parameters: [":userAddress"],
// 			returnValueTest: {
// 				comparator: "=",
// 				value: pkpEthAddress,
// 			},
// 		},
// 	];

// 	// this will be fired if auth is needed. we can use this to prompt the user to sign in
// 	const authNeededCallback = async ({
// 		chain,
// 		resources,
// 		expiration,
// 		uri,
// 		litNodeClient,
// 	}) => {
// 		console.log("authNeededCallback fired");
// 		const sessionSig = await litNodeClient.signSessionKey({
// 			sessionKey: uri,
// 			authMethods: [
// 				{
// 					authMethodType: 6,
// 					accessToken: googleCredentialResponse.credential,
// 				},
// 			],
// 			pkpPublicKey,
// 			expiration,
// 			resources,
// 			chain,
// 		});
// 		console.log("got session sig from node and PKP: ", sessionSig);
// 		return sessionSig;
// 	};

// 	// get the user a session with it
// 	const litNodeClient = new LitJsSdk.LitNodeClient({
// 		litNetwork: "serrano",
// 	});
// 	await litNodeClient.connect();

// 	const sessionSigs = await litNodeClient.getSessionSigs({
// 		expiration: new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(), // 24 hours
// 		chain: "ethereum",
// 		resources: [`litEncryptionCondition://*`],
// 		switchChain: false,
// 		authNeededCallback,
// 	});
// 	console.log("sessionSigs before saving encryption key: ", sessionSigs);

// 	const { encryptedZip, symmetricKey } = await LitJsSdk.zipAndEncryptString(
// 		"this is a secret message"
// 	);

// 	const encryptedSymmetricKey = await litNodeClient.saveEncryptionKey({
// 		unifiedAccessControlConditions,
// 		symmetricKey,
// 		sessionSigs,
// 	});

// 	const hashOfKey = await LitJsSdk.hashEncryptionKey({
// 		encryptedSymmetricKey,
// 	});

// 	console.log("encrypted symmetric key", encryptedSymmetricKey);

// 	const retrievedSymmKey = await litNodeClient.getEncryptionKey({
// 		unifiedAccessControlConditions,
// 		toDecrypt: LitJsSdk.uint8arrayToString(encryptedSymmetricKey, "base16"),
// 		sessionSigs,
// 	});

// 	const decryptedFiles = await LitJsSdk.decryptZip(
// 		encryptedZip,
// 		retrievedSymmKey
// 	);
// 	const decryptedString = await decryptedFiles["string.txt"].async("text");
// 	console.log("decrypted string", decryptedString);

// 	setStatusFn("Success!");
// }

async function handleWebAuthnRegister(
	setStatusFn: (status: string) => void,
	onSuccess: ({ attResp }: { attResp: any }) => void
) {
	const resp = await fetch(`${RELAY_API_URL}/generate-registration-options`, {
		method: "GET",
		headers: {
			"api-key": RELAY_API_KEY,
		},
	});

	let attResp;
	try {
		const opts = await resp.json();

		// Require a resident key for this demo
		opts.authenticatorSelection.residentKey = "required";
		opts.authenticatorSelection.requireResidentKey = true;
		opts.extensions = {
			credProps: true,
		};

		attResp = await startRegistration(opts);
	} catch (error) {
		// TODO: Handle error
		throw error;
	}

	console.log("attResp", { attResp });

	const verificationResp = await fetch(
		`${RELAY_API_URL}/verify-registration`,
		{
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"api-key": RELAY_API_KEY,
			},
			body: JSON.stringify(attResp),
		}
	);

	const verificationJSON = await verificationResp.json();

	if (verificationJSON && verificationJSON.verified) {
		setStatusFn("Successfully registered using WebAuthn!");
		onSuccess({ attResp });
	} else {
		setStatusFn(
			"Oh no, something went wrong during WebAuthn registration."
		);
		console.error("Error during WebAuthn registration", {
			err: JSON.stringify(verificationJSON),
		});
	}
}

async function handleWebAuthnAuthenticate(
	setStatusFn: (status: string) => void,
	webAuthnCredentialPublicKey: string,
	onSuccess: (resp: any) => void,
	setWebAuthnSignatureFn: (signature: string) => void,
	setWebAuthnSignatureBaseFn: (signatureBase: string) => void
) {
	const resp = await fetch(
		`${RELAY_API_URL}/generate-authentication-options`,
		{
			method: "GET",
			headers: {
				"api-key": RELAY_API_KEY,
			},
		}
	);

	let asseResp;
	try {
		const opts = await resp.json();

		asseResp = await startAuthentication(opts);
	} catch (error) {
		// TODO: handle error
		throw error;
	}

	const verificationResp = await fetch(
		`${RELAY_API_URL}/verify-authentication`,
		{
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"api-key": RELAY_API_KEY,
			},
			body: JSON.stringify(asseResp),
		}
	);

	const verificationJSON = await verificationResp.json();

	if (verificationJSON && verificationJSON.verified) {
		setStatusFn("Successfully authenticated using WebAuthn!");
	} else {
		setStatusFn(
			"Oh no, something went wrong during WebAuthn authentication."
		);
		console.error("Error during WebAuthn authentication", {
			err: JSON.stringify(verificationJSON),
		});
	}

	const clientDataHash = await crypto.subtle.digest(
		"SHA-256",
		base64url.toBuffer(asseResp.response.clientDataJSON)
	);

	const authDataBuffer = base64url.toBuffer(
		asseResp.response.authenticatorData
	);

	const signatureBase = Buffer.concat([
		authDataBuffer,
		Buffer.from(clientDataHash),
	]);

	const signature = base64url.toBuffer(asseResp.response.signature);

	// mint PKP using Relayer
	console.log("Minting PKP using Relayer...", {
		signature: hexlify(signature),
		signatureBase: hexlify(signatureBase),
		webAuthnCredentialPublicKey,
	});
	const requestId = await mintPkpUsingRelayerWebAuthnVerificationEndpoint(
		hexlify(signature),
		hexlify(signatureBase),
		webAuthnCredentialPublicKey,
		setStatusFn
	);

	// Poll until success
	await pollRequestUntilTerminalState(requestId, setStatusFn, onSuccess);

	// Update state
	setWebAuthnSignatureFn(hexlify(signature));
	setWebAuthnSignatureBaseFn(hexlify(signatureBase));
}
