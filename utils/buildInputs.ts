import { Wallet } from 'ethers'
import _ from 'lodash'

export default function buildInputs(inputs, wallet: Wallet) {
  const k = 4
  const prepHash: bigint[] = []

  for (let i = 0; i < k; i++) {
    prepHash[i] = inputs.s[i]
    prepHash[k + i] = inputs.U[0][i]
    prepHash[2 * k + i] = inputs.U[1][i]
  }
  prepHash[3 * k] = BigInt(wallet.address)

  return _.flattenDeep(prepHash.filter((item) => item)).map((v) => BigInt(v))
}
