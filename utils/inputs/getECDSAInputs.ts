import * as bigintConversion from 'bigint-conversion'
import { ecsign, hashPersonalMessage } from '@ethereumjs/util'
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

const privKey = bigintConversion.bigintToBuf(
  BigInt(wallet.privateKey)
) as Buffer

function inputsForMessage(message: string) {
  const msgHash = hashPersonalMessage(Buffer.from(message))

  const { v, r, s } = ecsign(msgHash, privKey)

  const isYOdd = (v - BigInt(27)) % BigInt(2)
  const rPoint = ec.keyFromPublic(
    ec.curve.pointFromX(new BN(r), isYOdd).encode('hex'),
    'hex'
  )

  const rInv = new BN(r).invm(SECP256K1_N)
  const w = rInv.mul(new BN(msgHash)).neg().umod(SECP256K1_N)
  const U = ec.curve.g.mul(w)
  const T = rPoint.getPublic().mul(rInv)
  const TPreComputes = getPointPreComputes(T)

  return {
    TPreComputes,
    U: [splitToRegisters(U.x), splitToRegisters(U.y)],
    s: [splitToRegisters(s.toString('hex'))],
  }
}

export default function () {
  return inputsForMessage('Signature for SealHub')
}
