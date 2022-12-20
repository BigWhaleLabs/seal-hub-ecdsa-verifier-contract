import { Wallet, utils } from 'ethers'
import { hashPersonalMessage } from '@ethereumjs/util'
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
  const x = splitToRegisters(
    new BN(BigInt(addHexPrefix(publicKey.slice(4, 4 + 64))).toString())
  )
  const y = splitToRegisters(
    new BN(BigInt(addHexPrefix(publicKey.slice(68, 68 + 64))).toString())
  )

  return [x, y]
}

const addHexPrefix = (str: string) => `0x${str}`

interface ExtendedBasePoint extends elliptic.curve.base.BasePoint {
  x: BN
  y: BN
}

const splitToRegisters = (value?: BN | string) => {
  const registers = [] as bigint[]

  if (!value) {
    return [0n, 0n, 0n, 0n]
  }
  const hex = value.toString('hex').padStart(64, '0')
  for (let k = 0; k < REGISTERS; k++) {
    // 64bit = 16 chars in hex
    const val = hex.slice(k * 16, (k + 1) * 16)

    registers.unshift(BigInt(addHexPrefix(val)))
  }

  return registers.map((el) => el.toString())
}

const getPointPreComputes = (point: ExtendedBasePoint) => {
  const keyPoint = ec.keyFromPublic({
    x: Buffer.from(point.x.toString(16), 'hex').toString('hex'),
    y: Buffer.from(point.y.toString(16), 'hex').toString('hex'),
  })

  const gPowers = [] as (bigint[] | string[])[][][]
  for (let i = 0n; i < NUM_STRIDES; i++) {
    const stride: (bigint[] | string[])[][] = []
    const power = 2n ** (i * STRIDE)
    for (let j = 0n; j < 2n ** STRIDE; j++) {
      const l = j * power

      const gPower = keyPoint
        .getPublic()
        .mul(new BN(l.toString())) as ExtendedBasePoint
      const x = splitToRegisters(gPower.x)
      const y = splitToRegisters(gPower.y)
      stride.push([x, y])
    }
    gPowers.push(stride)
  }

  return gPowers
}

async function inputsForMessage(signer: Wallet, message: string) {
  const msgHash = hashPersonalMessage(Buffer.from(message))
  const signature = await signer.signMessage(message)
  const { v, r } = utils.splitSignature(signature)

  const biV = BigInt(v)
  const biR = new BN(r.slice(2, r.length), 'hex')

  const isYOdd = (biV - BigInt(27)) % BigInt(2)
  const rPoint = ec.keyFromPublic(
    ec.curve.pointFromX(new BN(biR), isYOdd).encode('hex'),
    'hex'
  )

  // Get the group element: -(m * r^−1 * G)
  const rInv = new BN(biR).invm(SECP256K1_N)

  // w = -(r^-1 * msg)
  const w = rInv.mul(new BN(msgHash)).neg().umod(SECP256K1_N)
  // U = -(w * G) = -(r^-1 * msg * G)
  const U = ec.curve.g.mul(w)

  // T = r^-1 * R
  const T = rPoint.getPublic().mul(rInv) as ExtendedBasePoint

  const TPreComputes = getPointPreComputes(T)

  return {
    pointPreComputesForT: TPreComputes,
    scalarForT: splitToRegisters(biR),
    scalarForU: splitToRegisters(w),
    precompForT: [
      splitToRegisters(rPoint.getPublic().x),
      splitToRegisters(rPoint.getPublic().y),
    ],
    precompForU: [splitToRegisters(U.x), splitToRegisters(U.y)],
  }
}

export default function (signer = wallet) {
  return inputsForMessage(signer, 'Signature for SealHub')
}
