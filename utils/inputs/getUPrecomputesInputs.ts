import * as elliptic from 'elliptic'
import { Wallet, utils } from 'ethers'
import { getMessage } from '@big-whale-labs/seal-hub-kit'
import { hashPersonalMessage } from '@ethereumjs/util'
import BN from 'bn.js'
import wallet from '../wallet'

export const secp256k1 = new elliptic.ec('secp256k1')

export const REGISTERS = 4n
export const SECP256K1_N = new BN(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  16
)

function addHexPrefix(str: string) {
  return `0x${str}`
}

export function splitToRegisters(value?: BN | string) {
  const registers = [] as bigint[]

  if (!value) {
    return ['0', '0', '0', '0']
  }
  const hex = value.toString('hex').padStart(64, '0')
  for (let k = 0; k < REGISTERS; k++) {
    // 64bit = 16 chars in hex
    const val = hex.slice(k * 16, (k + 1) * 16)

    registers.unshift(BigInt(addHexPrefix(val)))
  }

  return registers.map((el) => el.toString())
}

export function getUAndSFromSignature(signature: string, message: string) {
  const msgHash = hashPersonalMessage(Buffer.from(message))
  const { r, s } = utils.splitSignature(signature)
  const biR = new BN(r.slice(2, r.length), 'hex')
  const hexS = s.slice(2, s.length)
  const rInv = new BN(biR).invm(SECP256K1_N)
  const w = rInv.mul(new BN(msgHash)).neg().umod(SECP256K1_N)
  const U = secp256k1.curve.g.mul(w)
  return {
    U: [splitToRegisters(U.x), splitToRegisters(U.y)],
    s: splitToRegisters(hexS),
    scalarForT: splitToRegisters(biR),
    scalarForU: splitToRegisters(w),
    // Debug
    msgHash: new BN(msgHash).toString(),
    msgHashSplit: splitToRegisters(new BN(msgHash)),
    rInv: splitToRegisters(rInv),
  }
}

async function inputsForMessage(signer: Wallet, message: string) {
  const signature = await signer.signMessage(message)
  const { U, rInv } = getUAndSFromSignature(signature, message)
  return {
    U,
    rInv,
  }
}

export default function (signer = wallet, message = getMessage()) {
  return inputsForMessage(signer, message)
}
