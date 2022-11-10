import { hashPersonalMessage } from '@ethereumjs/util'
import { utils } from 'ethers'
import BN from 'bn.js'
import elliptic from 'elliptic'
import wallet from '../wallet'

const ec = new elliptic.ec('secp256k1')
const STRIDE = 8n
const NUM_STRIDES = 256n / STRIDE // = 32
const REGISTERS = 4n

const SECP256K1_N = new BN(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  16
)

export function publicKeyToArraysSplitted(publicKey: string) {
  const x = splitToRegisters(BigInt('0x' + publicKey.slice(4, 4 + 64)))
  const y = splitToRegisters(BigInt('0x' + publicKey.slice(68, 68 + 64)))

  return [x, y]
}

const addHexPrefix = (str) => `0x${str}`

const splitToRegisters = (value) => {
  const registers = [] as bigint[]

  if (!value) {
    return [0n, 0n, 0n, 0n]
  }

  const hex = value.toString(16).padStart(64, '0')
  for (let k = 0; k < REGISTERS; k++) {
    // 64bit = 16 chars in hex
    const val = hex.slice(k * 16, (k + 1) * 16)

    registers.unshift(BigInt(addHexPrefix(val)))
  }

  return registers.map((el) => el.toString())
}

const getPointPreComputes = (point) => {
  const keyPoint = ec.keyFromPublic({
    x: Buffer.from(point.x.toString(16), 'hex'),
    y: Buffer.from(point.y.toString(16), 'hex'),
  })

  const gPowers = [] as (bigint[] | string[])[][][]
  for (let i = 0n; i < NUM_STRIDES; i++) {
    const stride: (bigint[] | string[])[][] = []
    const power = 2n ** (i * STRIDE)
    for (let j = 0n; j < 2n ** STRIDE; j++) {
      const l = j * power

      const gPower = keyPoint.getPublic().mul(new BN(l.toString()))

      const x = splitToRegisters(gPower.x)
      const y = splitToRegisters(gPower.y)
      stride.push([x, y])
    }
    gPowers.push(stride)
  }

  return gPowers
}

async function inputsForMessage(message: string) {
  const msgHash = hashPersonalMessage(Buffer.from(message))

  const signature = await wallet.signMessage(msgHash)
  const { r, s, v } = utils.splitSignature(signature)
  const isYOdd = (v - 27) % 2

  const bnR = new BN(BigInt(r).toString())

  const rPoint = ec.keyFromPublic(
    ec.curve.pointFromX(bnR, isYOdd).encode('hex'),
    'hex'
  )
  const rInv = bnR.invm(SECP256K1_N)
  const w = rInv.mul(new BN(msgHash)).neg().umod(SECP256K1_N)
  const U = ec.curve.g.mul(w)
  const T = rPoint.getPublic().mul(rInv)
  const TPreComputes = getPointPreComputes(T)

  return {
    TPreComputes,
    U: [splitToRegisters(U.x), splitToRegisters(U.y)],
    s: [splitToRegisters(Buffer.from(s).toString('hex'))],
  }
}

export default function () {
  return inputsForMessage('Signature for SealHub')
}
