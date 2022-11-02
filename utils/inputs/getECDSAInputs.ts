import { BigNumber, utils } from 'ethers'
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
  return ret.map((el) => el.toString())
}

function pubkeyToXYArrays(pk: string) {
  const XArr = bigintToArray(BigInt('0x' + pk.slice(4, 4 + 64)))
  const YArr = bigintToArray(BigInt('0x' + pk.slice(68, 68 + 64)))

  return [XArr, YArr]
}

async function inputsForMessage(message: string) {
  const messageBytes = utils.toUtf8Bytes(message)
  const mimc7 = await buildMimc7()
  const messageHash = mimc7.multiHash(messageBytes)
  const signature = await wallet.signMessage(messageHash)

  const publicKey = utils.recoverPublicKey(messageHash, signature)

  const r = bigintToArray(BigInt('0x' + signature.slice(2, 2 + 64)), 64, 4)
  const s = bigintToArray(BigInt('0x' + signature.slice(66, 66 + 64)), 64, 4)

  return {
    r,
    s,
    pubKey: pubkeyToXYArrays(publicKey),
    msgHash: [bigintToArray(BigNumber.from(messageHash).toBigInt())],
  }
}

export default function () {
  return inputsForMessage('Signature for SealHub')
}
