import { useState } from "react";
import "./App.css";
import { GoogleLogin } from "@react-oauth/google";
import { ethers, utils } from "ethers";
import { Base64 } from "js-base64";
import LitJsSdk from "lit-js-sdk";

import PKPHelper from "./abis/PKPHelper.json";
import PKPNFT from "./abis/PKPNFT.json";
import ContractAddresses from "./abis/deployed-contracts.json";

window.LitJsSdk = LitJsSdk;
window.ethers = ethers;

const RELAY_API_URL = process.env.RELAY_API_URL || 'http://localhost:3001';

function App() {
  const [pkpEthAddress, setPkpEthAddress] = useState(null);
  const [googleCredentialResponse, setGoogleCredentialResponse] =
    useState(null);
  const [pkpPublicKey, setPkpPublicKey] = useState(null);
  const [status, setStatus] = useState("");

  const handleLoggedInToGoogle = async (credentialResponse) => {
    setStatus("Logged in to Google");
    console.log("got this response from google sign in: ", credentialResponse);
    setGoogleCredentialResponse(credentialResponse);
    mintPkp(credentialResponse);
  };

  const mintPkp = async (credentialResponse) => {
    setStatus("Minting PKP...");
    // mint a PKP for the user
    // A Web3Provider wraps a standard Web3 provider, which is
    // what MetaMask injects as window.ethereum into each page
    const provider = new ethers.providers.Web3Provider(window.ethereum);

    // MetaMask requires requesting permission to connect users accounts
    await provider.send("eth_requestAccounts", []);

    // The MetaMask plugin also allows signing transactions to
    // send ether and pay to change state within the blockchain.
    // For this, you need the account signer...
    const signer = provider.getSigner();

    const helperContract = new ethers.Contract(
      ContractAddresses.pkpHelperContractAddress,
      PKPHelper.abi,
      signer
    );
    const pkpContract = new ethers.Contract(
      ContractAddresses.pkpNftContractAddress,
      PKPNFT.abi,
      signer
    );

    let jwtParts = credentialResponse.credential.split(".");
    let jwtPayload = JSON.parse(Base64.decode(jwtParts[1]));

    let idForAuthMethod = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(`${jwtPayload.sub}:${jwtPayload.aud}`)
    );

    const mintCost = await pkpContract.mintCost();

    const mintTx = await helperContract.mintNextAndAddAuthMethods(
      2, // keyType
      [6], // permittedAuthMethodTypes,
      [idForAuthMethod], // permittedAuthMethodIds
      ["0x"], // permittedAuthMethodPubkeys
      [[ethers.BigNumber.from("0")]], // permittedAuthMethodScopes
      true, // addPkpEthAddressAsPermittedAddress
      true, // sendPkpToItself
      { value: mintCost }
    );
    console.log("mintTx: ", mintTx);
    const mintingReceipt = await mintTx.wait();
    console.log("mintingReceipt: ", mintingReceipt);
    const tokenIdFromEvent = mintingReceipt.events[2].topics[3];
    const ethAddress = await pkpContract.getEthAddress(tokenIdFromEvent);
    setPkpEthAddress(ethAddress);

    console.log("minted PKP with eth address: ", ethAddress);
    const pkpPublicKey = await pkpContract.getPubkey(tokenIdFromEvent);
    setPkpPublicKey(pkpPublicKey);
    setStatus("Minted PKP");
  };

  const handleStoreEncryptionCondition = async () => {
    setStatus("Storing encryption condition...");
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
      sessionCapabilityObject: {
        def: ["litEncryptionCondition"]
      },
      switchChain: false,
      authNeededCallback,
    });
    console.log("sessionSigs before saving encryption key: ", sessionSigs);

    const { encryptedZip, symmetricKey } = await LitJsSdk.zipAndEncryptString(
      "this is a secret message"
    );

    // value parameter - hash unified conditions
    const hashedAccessControlConditions = await LitJsSdk.hashUnifiedAccessControlConditions(unifiedAccessControlConditions);
    console.log("hashedAccessControlConditions", { hashedAccessControlConditions });
    const hashedAccessControlConditionsStr = LitJsSdk.uint8arrayToString(new Uint8Array(hashedAccessControlConditions), "base16");

    // key parameter - encrypt symmetric key then hash it 
    const encryptedSymmetricKey = LitJsSdk.encryptWithBlsPubkey({
      pubkey: litNodeClient.networkPubKey,
      data: symmetricKey,
    });
    const hashedEncryptedSymmetricKeyStr = await LitJsSdk.hashEncryptionKey({ encryptedSymmetricKey });
    
    // securityHash parameter - encrypt symmetric key, concat with creator address
    const pkpEthAddressBytes = utils.arrayify(pkpEthAddress);
    const securityHashPreimage = new Uint8Array([...encryptedSymmetricKey, ...pkpEthAddressBytes]);
    // TODO: LitJsSdk.hashEncryptionKey ought to be renamed to just .hashBytes
    const securityHashStr = await LitJsSdk.hashEncryptionKey({ encryptedSymmetricKey: securityHashPreimage });

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
        'Content-Type': 'application/json'
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

    setStatus("Success!");
  }

  const handleEncryptThenDecrypt = async () => {
    setStatus("Encrypting then decrypting...");
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

    setStatus("Success!");
  };

  return (
    <div className="App">
      <div style={{ height: 50 }} />
      <h1>{status}</h1>
      <div style={{ height: 100 }} />
      <h3>
        Step 1: log in with Google. You will mint a PKP and obtain a session
        sig. Note: Your metamask must be switched to Mumbai.
      </h3>
      <GoogleLogin
        onSuccess={handleLoggedInToGoogle}
        onError={() => {
          console.log("Login Failed");
        }}
        useOneTap
      />
      <div style={{ height: 100 }} />
      {pkpEthAddress && <div>PKP Eth Address: {pkpEthAddress}</div>}
      <div style={{ height: 100 }} />
      <h3>Step 2: Use Lit</h3>
      <button onClick={handleStoreEncryptionCondition}>
        Encrypt with Lit
      </button>
    </div>
  );
}

export default App;
