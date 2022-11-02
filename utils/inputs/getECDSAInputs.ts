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
  const { r, s } = utils.splitSignature(signature)
  const rBigint = BigInt(r)
  const sBigint = BigInt(s)
  const rArray = bigintToArray(rBigint).map((v) =>
    BigNumber.from(v).toHexString()
  )
  const sArray = bigintToArray(sBigint).map((v) =>
    BigNumber.from(v).toHexString()
  )
  const { x: pubKeyX, y: pubKeyY } = Point.fromPrivateKey(
    BigInt(wallet.privateKey)
  )
  const mBigInt = BigNumber.from(messageHash).toBigInt()

  return {
    r: rArray,
    s: sArray,
    pubKey: [
      bigintToArray(pubKeyX).map((v) => BigNumber.from(v).toHexString()),
      bigintToArray(pubKeyY).map((v) => BigNumber.from(v).toHexString()),
    ],
    // message: messageBytes,
    msgHash: [
      bigintToArray(mBigInt).map((v) => BigNumber.from(v).toHexString()),
    ],
  }
}

export default function () {
  return inputsForMessage('Signature for SealHub')
}
