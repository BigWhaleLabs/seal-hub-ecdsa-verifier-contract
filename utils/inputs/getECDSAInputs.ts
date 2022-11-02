import { BigNumber, utils } from 'ethers'
import { Point } from '@noble/secp256k1'
import { buildMimc7 } from 'circomlibjs'
import wallet from '../ecdsa/wallet'

const regSize = 64
const regNumber = 4

function bigintToArray(x: bigint, n = regSize, k = regNumber) {
  let mod = 1n
  for (let idx = 0; idx < n; idx++) {
    mod = mod * 2n
  }

  const ret = [] as bigint[]
  let x_temp = x
  for (let idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod)
    x_temp = x_temp / mod
  }
  return ret
}

async function inputsForMessage(message: string) {
  const messageBytes = utils.toUtf8Bytes(message)
  const mimc7 = await buildMimc7()
  const messageHash = mimc7.multiHash(messageBytes)
  const signature = await wallet.signMessage(messageHash)
  const r = bigintToArray(BigInt('0x' + signature.slice(2, 2 + 64)), 64, 4).map(
    (el) => el.toString()
  )
  const s = bigintToArray(
    BigInt('0x' + signature.slice(66, 66 + 64)),
    64,
    4
  ).map((el) => el.toString())
  const { x: pubKeyX, y: pubKeyY } = Point.fromPrivateKey(
    BigInt(wallet.privateKey)
  )

  return {
    r,
    s,
    pubKey: [
      bigintToArray(pubKeyX).map((v) => BigNumber.from(v).toHexString()),
      bigintToArray(pubKeyY).map((v) => BigNumber.from(v).toHexString()),
    ],
    // message: messageBytes,
    msgHash: [bigintToArray(BigInt(messageHash), 64, 4)],
  }
}

export default function () {
  return inputsForMessage('Signature for SealHub')
}
