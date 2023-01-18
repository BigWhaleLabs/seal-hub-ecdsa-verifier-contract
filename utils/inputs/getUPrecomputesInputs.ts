import { Wallet } from 'ethers'
import { getUAndSFromSignature } from '@big-whale-labs/seal-hub-kit'
import wallet from '../wallet'

async function inputsForMessage(signer: Wallet, message: string) {
  const signature = await signer.signMessage(message)
  const { U, scalarForU } = getUAndSFromSignature(signature, message)
  return {
    U,
    scalarForU,
  }
}

export default function (signer = wallet) {
  return inputsForMessage(signer, 'Signature for SealHub')
}
