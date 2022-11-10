# SealHub ECDSA verifier contract

Verifies that a signature is a valid ECDSA signature and outputs the hash of that signature.

## Usage

1. Clone the repository with `git clone git@github.com:BigWhaleLabs/seal-hub-ecdsa-verifier-contract.git`
2. Install the dependencies with `yarn`
3. Download the ptau file with `yarn download-ptau`
4. Add environment variables to your `.env` file
5. Run `yarn generate-inputs` to generate random circuit inputs
6. Run `yarn compile` to compile the circom circuit, create proof, verify proof, export verifier as a solidity file `ECDSACheckerVerifier.sol`
7. Run `yarn test` to run the test suits
8. Use the artifacts from the `public` folder in [snarkjs](https://github.com/iden3/snarkjs)
9. Run `yarn deploy` to deploy the verifier smart contract to blockchain
10. Run `yarn release` to publish an NPM package with typings that can later be used in any of your JS/TS projects

## Environment variables

| Name                         | Description                       |
| ---------------------------- | --------------------------------- |
| `ETHERSCAN_API_KEY`          | Etherscan API key                 |
| `ETH_RPC`                    | Ethereum RPC URL                  |
| `CONTRACT_OWNER_PRIVATE_KEY` | Private key of the contract owner |

Also check out the `.env.example` file for more information.

## Available scripts

- `yarn build` — compiles the contracts' ts interfaces to the `typechain` directory
- `yarn compile` - compiles the circom circuit, creates proof, verifies proof, exports verifier as a solidity file, exports artifacts to the `public` directory
- `yarn test` — runs the test suite
- `yarn deploy` — deploys the contract to the network
- `yarn eth-lint` — runs the linter for the solidity contracts
- `yarn lint` — runs all the linters
- `yarn prettify` — prettifies the code in th project
- `yarn release` — relases the `typechain` directory to NPM
- `yarn download-ptau` — downloads the relevant ptau file
- `yarn download-public` — downloads the relevant public binary files
