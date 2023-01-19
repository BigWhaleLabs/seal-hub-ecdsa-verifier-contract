import { Wallet } from 'ethers'
import {
  getMessage,
  getTPrecomputesFromSignature,
  getUAndSFromSignature,
} from '@big-whale-labs/seal-hub-kit'
import wallet from '../wallet'

async function inputsForMessage(signer: Wallet, message: string) {
  const signature = await signer.signMessage(message)

  const { U, s, scalarForT } = getUAndSFromSignature(signature, message)
  const { TPrecomputes, T } = getTPrecomputesFromSignature(signature)

  return {
    U,
    s,
    scalarForT,
    TPrecomputes,
    T,
  }
}

export default function (signer = wallet, message = getMessage()) {
  return inputsForMessage(signer, message)
}
