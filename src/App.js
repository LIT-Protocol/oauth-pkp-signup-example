import { GoogleLogin } from "@react-oauth/google";
import { ethers, utils } from "ethers";
import LitJsSdk from "lit-js-sdk";
import { useState } from "react";
import "./App.css";
import { ButtonGroup, Button } from "@mui/material";
import base64url from "base64url";
import {
	startRegistration,
	startAuthentication,
} from "@simplewebauthn/browser";
import { parseAuthenticatorData } from "./utils/parseAuthenticatorData";
import { decodeAttestationObject } from "./utils/decodeAttestationObject";
import { hexlify } from "ethers/lib/utils";

window.LitJsSdk = LitJsSdk;
window.ethers = ethers;

const RELAY_API_URL =
	process.env.REACT_APP_RELAY_API_URL || "http://localhost:3001";

function App() {
	const [pkpEthAddress, setPkpEthAddress] = useState(null);
	const [googleCredentialResponse, setGoogleCredentialResponse] = useState(
		null
	);
	const [pkpPublicKey, setPkpPublicKey] = useState(null);
	const [status, setStatus] = useState("");
	const [selectedAuthMethod, setSelectedAuthMethod] = useState(6);
	const [
		webAuthnCredentialPublicKey,
		setWebAuthnCredentialPublicKey,
	] = useState();
	const [webAuthnSignature, setWebAuthnSignature] = useState();
	const [webAuthnSignatureBase, setWebAuthnSignatureBase] = useState();

	const handleLoggedInToGoogle = async credentialResponse => {
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

	return (
		<div className="App">
			<div style={{ height: 80 }} />
			<h1>Welcome To The OAuth PKP Demo!</h1>
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
					<GoogleLogin
						onSuccess={handleLoggedInToGoogle}
						onError={() => {
							console.log("Login Failed");
						}}
						useOneTap
					/>
					{pkpEthAddress && (
						<div>PKP Eth Address: {pkpEthAddress}</div>
					)}
					<h3>
						Step 2: Use Lit Network to obtain a session sig and then
						store an encryption condition.
					</h3>
					<button
						onClick={() =>
							handleStoreEncryptionCondition(
								setStatus,
								selectedAuthMethod,
								googleCredentialResponse,
								{},
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
											parsedAuthData.credentialPublicKey
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
						Step 3: Use Lit Network to obtain a session sig and then
						store an encryption condition. (TODO)
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
	credentialResponse,
	setStatusFn
) {
	setStatusFn("Minting PKP with relayer...");

	const mintRes = await fetch(`${RELAY_API_URL}/auth/google`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
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
	signature,
	signatureBase,
	credentialPublicKey,
	setStatusFn
) {
	setStatusFn("Minting PKP with relayer...");

	const mintRes = await fetch(`${RELAY_API_URL}/auth/webauthn`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
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
	requestId,
	setStatusFn,
	onSuccess
) {
	if (!requestId) {
		return;
	}

	const maxPollCount = 20;
	for (let i = 0; i < maxPollCount; i++) {
		setStatusFn(`Waiting for auth completion (poll #${i + 1})`);
		const getAuthStatusRes = await fetch(
			`${RELAY_API_URL}/auth/status/${requestId}`
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
	setStatusFn,
	selectedAuthMethod,
	googleCredentialResponse,
	webAuthnVerificationMaterial,
	pkpEthAddress,
	pkpPublicKey
) {
	setStatusFn("Storing encryption condition...");
	var unifiedAccessControlConditions = [
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
	}) => {
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
		sessionCapabilityObject: {
			def: ["litEncryptionCondition"],
		},
		switchChain: false,
		authNeededCallback,
	});
	console.log("sessionSigs before saving encryption key: ", sessionSigs);

	const { encryptedZip, symmetricKey } = await LitJsSdk.zipAndEncryptString(
		"this is a secret message"
	);

	// value parameter - hash unified conditions
	const hashedAccessControlConditions = await LitJsSdk.hashUnifiedAccessControlConditions(
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
	const encryptedSymmetricKey = LitJsSdk.encryptWithBlsPubkey({
		pubkey: litNodeClient.networkPubKey,
		data: symmetricKey,
	});
	const hashedEncryptedSymmetricKeyStr = await LitJsSdk.hashEncryptionKey({
		encryptedSymmetricKey,
	});

	// securityHash parameter - encrypt symmetric key, concat with creator address
	const pkpEthAddressBytes = utils.arrayify(pkpEthAddress);
	const securityHashPreimage = new Uint8Array([
		...encryptedSymmetricKey,
		...pkpEthAddressBytes,
	]);
	// TODO: LitJsSdk.hashEncryptionKey ought to be renamed to just .hashBytes
	const securityHashStr = await LitJsSdk.hashEncryptionKey({
		encryptedSymmetricKey: securityHashPreimage,
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

async function handleEncryptThenDecrypt(
	setStatusFn,
	googleCredentialResponse,
	pkpEthAddress,
	pkpPublicKey
) {
	setStatusFn("Encrypting then decrypting...");
	var unifiedAccessControlConditions = [
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
	}) => {
		console.log("authNeededCallback fired");
		const sessionSig = await litNodeClient.signSessionKey({
			sessionKey: uri,
			authMethods: [
				{
					authMethodType: 6,
					accessToken: googleCredentialResponse.credential,
				},
			],
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

	const encryptedSymmetricKey = await litNodeClient.saveEncryptionKey({
		unifiedAccessControlConditions,
		symmetricKey,
		sessionSigs,
	});

	const hashOfKey = await LitJsSdk.hashEncryptionKey({
		encryptedSymmetricKey,
	});

	console.log("encrypted symmetric key", encryptedSymmetricKey);

	const retrievedSymmKey = await litNodeClient.getEncryptionKey({
		unifiedAccessControlConditions,
		toDecrypt: LitJsSdk.uint8arrayToString(encryptedSymmetricKey, "base16"),
		sessionSigs,
	});

	const decryptedFiles = await LitJsSdk.decryptZip(
		encryptedZip,
		retrievedSymmKey
	);
	const decryptedString = await decryptedFiles["string.txt"].async("text");
	console.log("decrypted string", decryptedString);

	setStatusFn("Success!");
}

async function handleWebAuthnRegister(setStatusFn, onSuccess) {
	const resp = await fetch(`${RELAY_API_URL}/generate-registration-options`);

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
	setStatusFn,
	webAuthnCredentialPublicKey,
	onSuccess,
	setWebAuthnSignatureFn,
	setWebAuthnSignatureBaseFn
) {
	const resp = await fetch(
		`${RELAY_API_URL}/generate-authentication-options`
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
