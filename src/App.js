import { useState } from "react";
import "./App.css";
import { GoogleLogin } from "@react-oauth/google";
import { ethers } from "ethers";
import { Base64 } from "js-base64";

import PKPHelper from "./abis/PKPHelper.json";
import PKPNFT from "./abis/PKPNFT.json";
import ContractAddresses from "./abis/deployed-contracts.json";

function App() {
  const [pkpEthAddress, setPkpEthAddress] = useState(null);

  const handleLoggedInToGoogle = async (credentialResponse) => {
    console.log("got this response from google sign in: ", credentialResponse);
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

    let idForAuthMethod = ethers.utils.hexlify(
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
    console.log("minted PKP with eth address: ", ethAddress);
    setPkpEthAddress(ethAddress);

    // get the user a session with it
    const fakeSessionKey = "0x1234567890";
  };
  return (
    <div className="App">
      <GoogleLogin
        onSuccess={handleLoggedInToGoogle}
        onError={() => {
          console.log("Login Failed");
        }}
        useOneTap
      />
      <div style={{ height: 100 }} />
      {pkpEthAddress && <div>PKP Eth Address: {pkpEthAddress}</div>}
    </div>
  );
}

export default App;
