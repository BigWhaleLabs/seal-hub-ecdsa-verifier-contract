import { Wallet } from 'ethers'
import { publicKeyToArraysSplitted } from './inputs/getECDSAInputs'
import _ from 'lodash'

export default function buildInputs(inputs, wallet: Wallet) {
  const k = 4
  const prepHash: number[] = []

  const pubKey = publicKeyToArraysSplitted(wallet.publicKey)

  for (let i = 0; i < k; i++) {
    prepHash[i] = inputs.s[i]
    prepHash[k + i] = inputs.U[0][i]
    prepHash[2 * k + i] = inputs.U[1][i]
    prepHash[3 * k + i] = pubKey[0][i] as unknown as number
    prepHash[4 * k + i] = pubKey[1][i] as unknown as number
  }

  return _.flattenDeep(prepHash.filter((item) => item)).map((v) => BigInt(v))
}
