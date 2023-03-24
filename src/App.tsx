import * as LitJsSdk_accessControlConditions from "@lit-protocol/access-control-conditions";
import * as LitJsSdk_blsSdk from "@lit-protocol/bls-sdk";
import * as LitJsSdk from "@lit-protocol/lit-node-client";
import { AccsDefaultParams } from "@lit-protocol/types";
import { Button, ButtonGroup, TextField } from "@mui/material";
import { GoogleLogin } from "@react-oauth/google";
import {
	startAuthentication,
	startRegistration,
} from "@simplewebauthn/browser";
import base64url from "base64url";
import { ethers, utils } from "ethers";
import { useState } from "react";
import "./App.css";
import { getDomainFromOrigin } from "./utils/string";

type CredentialResponse = any;

declare global {
	interface Window {
		cbor: any;
	}
}

const RELAY_API_URL =
	process.env.REACT_APP_RELAY_API_URL || "http://localhost:3001";

function App() {
	const [pkpEthAddress, setPkpEthAddress] = useState<string>("");
	const [
		googleCredentialResponse,
		setGoogleCredentialResponse,
	] = useState<CredentialResponse | null>(null);
	const [pkpPublicKey, setPkpPublicKey] = useState<string>("");
	const [status, setStatus] = useState("");
	const [selectedAuthMethod, setSelectedAuthMethod] = useState(6);
	const [webAuthnUsername, setWebAuthnUsername] = useState<string>("");

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
						Step 1: Log in with Google. Upon OAuth success, we will
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
					<h3>Step 1: Register to mint PKP. (optional username)</h3>
					<TextField
						label="Username"
						variant="outlined"
						onChange={e => setWebAuthnUsername(e.target.value)}
					/>
					<Button
						variant="contained"
						onClick={async () => {
							await handleWebAuthnRegister(
								webAuthnUsername,
								setStatus,
								({ pkpEthAddress, pkpPublicKey }) => {
									setPkpEthAddress(pkpEthAddress);
									setPkpPublicKey(pkpPublicKey);
								}
							);
						}}
					>
						Register
					</Button>
					{pkpEthAddress && (
						<div>PKP Eth Address: {pkpEthAddress}</div>
					)}
					<h3>
						Step 2: Authenticate against Lit Nodes to generate auth
						sigs.
					</h3>
					<Button
						variant="contained"
						onClick={async () => {
							await handleWebAuthnAuthenticate(
								setStatus,
								({}) => {}
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
									signature: "dummy",
									signatureBase: "dummy",
									credentialPublicKey: "dummy",
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
			"api-key": "1234567890",
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
				headers: {
					"api-key": "1234567890",
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
	// TODO: change to serrano once deployed on node side.
	const litNodeClient = new LitJsSdk.LitNodeClient({
		alertWhenUnauthorized: false,
		litNetwork: "custom",
		bootstrapUrls: [
			"http://localhost:7470",
			"http://localhost:7471",
			"http://localhost:7472",
			// "http://localhost:7473",
			// "http://localhost:7474",
			// "http://localhost:7475",
			// "http://localhost:7476",
			// "http://localhost:7477",
			// "http://localhost:7478",
			// "http://localhost:7479",
		],
		debug: true,
		minNodeCount: 2,
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
			"api-key": "1234567890",
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
	username: string,
	setStatusFn: (status: string) => void,
	onSuccess: ({
		pkpEthAddress,
		pkpPublicKey,
	}: {
		pkpEthAddress: string;
		pkpPublicKey: string;
	}) => void
) {
	let url = `${RELAY_API_URL}/auth/webauthn/generate-registration-options`;

	// Handle optional username
	if (!username && username !== "") {
		url += `?username=${username}`;
	}

	const resp = await fetch(url, { headers: { "api-key": "1234567890" } });

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

	// Verify and mint PKP.
	setStatusFn("Verifying WebAuthn registration...");
	const verificationAndMintResp = await fetch(
		`${RELAY_API_URL}/auth/webauthn/verify-registration`,
		{
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"api-key": "1234567890",
			},
			body: JSON.stringify({ credential: attResp }),
		}
	);

	if (
		verificationAndMintResp.status < 200 ||
		verificationAndMintResp.status >= 400
	) {
		console.warn(
			"Something went wrong with the API call",
			await verificationAndMintResp.json()
		);
		setStatusFn("Uh oh, something's not quite right.");
		return null;
	}

	const resBody = await verificationAndMintResp.json();
	console.log("Response OK", { body: resBody });
	setStatusFn(
		"Successfully registered using WebAuthn! PKP minting initiated..."
	);

	// Poll until success
	const mintRequestId = resBody.requestId;
	await pollRequestUntilTerminalState(mintRequestId, setStatusFn, onSuccess);
}

const rpcUrl = process.env.REACT_APP_RPC_URL || "http://localhost:8545";

async function handleWebAuthnAuthenticate(
	setStatusFn: (status: string) => void,
	onSuccess: (resp: any) => void
) {
	// Fetch latest blockHash
	setStatusFn("Fetching latest block hash...");
	const provider = new ethers.providers.JsonRpcProvider(rpcUrl);

	const block = await provider.getBlock("latest");
	const blockHash = block.hash;

	// Turn into byte array.
	const blockHashBytes = ethers.utils.arrayify(blockHash);
	console.log(
		"blockHash",
		blockHash,
		blockHashBytes,
		base64url(Buffer.from(blockHashBytes))
	);

	// Construct authentication options.
	const rpId = getDomainFromOrigin(window.location.origin);
	console.log("Using rpId: ", { rpId });
	const authenticationOptions = {
		challenge: base64url(Buffer.from(blockHashBytes)),
		timeout: 60000,
		userVerification: "required",
		rpId,
	};

	// Authenticate with WebAuthn.
	setStatusFn("Authenticating with WebAuthn...");
	const authenticationResponse = await startAuthentication(
		authenticationOptions
	);

	// BUG: We need to make sure userHandle is base64url encoded.
	// Deep copy the authentication response.
	const actualAuthenticationResponse = JSON.parse(
		JSON.stringify(authenticationResponse)
	);
	actualAuthenticationResponse.response.userHandle = base64url.encode(
		authenticationResponse.response.userHandle
	);

	// Call all nodes POST /web/auth/webauthn to generate authSig.
	setStatusFn("Verifying WebAuthn authentication against Lit Network...");
	// TODO: change to serrano once deployed on node side.
	const litNodeClient = new LitJsSdk.LitNodeClient({
		alertWhenUnauthorized: false,
		litNetwork: "custom",
		bootstrapUrls: [
			"http://localhost:7470",
			"http://localhost:7471",
			"http://localhost:7472",
			// "http://localhost:7473",
			// "http://localhost:7474",
			// "http://localhost:7475",
			// "http://localhost:7476",
			// "http://localhost:7477",
			// "http://localhost:7478",
			// "http://localhost:7479",
		],
		debug: true,
		minNodeCount: 2,
	});
	await litNodeClient.connect();
	litNodeClient.getWebAuthnAuthenticationAuthSig({
		verificationParams: actualAuthenticationResponse,
	});
}
