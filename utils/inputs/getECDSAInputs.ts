import {
  getMessageForAddress,
  getSealHubInputs,
} from '@big-whale-labs/seal-hub-kit'
import wallet from '../wallet'

export default async function (signer = wallet) {
  const message = getMessageForAddress(signer.address)
  const signature = await signer.signMessage(message)
  return getSealHubInputs(signature, message)
}
