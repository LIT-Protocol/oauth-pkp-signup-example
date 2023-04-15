# Lit Protocol Oauth -> Wallet example

This project lets you start using Ethereum with just a Google Account. It's a simple example of how to use the Lit Protocol Oauth service to authenticate users and then use their Ethereum address.

This project specifically:

1. Uses Google Oauth to auth the user
2. Mints a PKP token for the user, with their Google account as a valid auth method
3. Uses the PKP token to get an Ethereum address for the user
4. Generates a local session key for the user and stores it in LocalStorage
5. Uses the Lit Protocol's PKP Session Signing service to sign that session key with their PKP
6. Uses the local session key to sign a request to encrypt and decrypt a string that only the user can decrypt.

## How to run

First, run `yarn install`. Then run `yarn start` to run this project. You'll need a Metamask wallet set to the Chronicle network with some Lit Test tokens in it. You can learn more about Chronicle here: https://developer.litprotocol.com/intro/rollup

Sign in with Google and wait until it says "PKP Minted". Then, click the "Encrypt then Decrypt with Lit" button. If you see the word "Success!" at the top, then it worked! Open the dev console to see how it works.

You also need to set 2 env vars:

export REACT_APP_RELAY_API_URL="https://relay-server-staging.herokuapp.com"

export REACT_APP_RPC_URL="https://chain-rpc.litprotcol.com/http"
