import { Wallet } from 'ethers'
import { getMessage, getUAndSFromSignature } from '@big-whale-labs/seal-hub-kit'
import wallet from '../wallet'

async function inputsForMessage(signer: Wallet, message: string) {
  const signature = await signer.signMessage(message)
  const { U, rInv } = getUAndSFromSignature(signature, message)
  return {
    U,
    rInv,
  }
}

export default function (signer = wallet, message = getMessage()) {
  return inputsForMessage(signer, message)
}
