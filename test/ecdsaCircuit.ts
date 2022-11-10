import { BigNumber } from 'ethers'
import { expect } from 'chai'
import { wasm as wasmTester } from 'circom_tester'
import Mimc7 from '../utils/Mimc7'
import _ from 'lodash'
import getECDSAInputs, {
  publicKeyToArraysSplitted,
} from '../utils/inputs/getECDSAInputs'
import wallet from '../utils/wallet'

describe('ECDSAChecker circuit', function () {
  before(async function () {
    this.circuit = await wasmTester('circuits/ECDSAChecker.circom')
    this.baseInputs = await getECDSAInputs()
  })
  it.only('should generate the witness successfully and return correct mimc7', async function () {
    const witness = await this.circuit.calculateWitness(this.baseInputs)
    await this.circuit.assertOut(witness, {})

    const k = 4
    const prepHash: number[] = []

    const pubKey = publicKeyToArraysSplitted(wallet.publicKey)

    for (let i = 0; i < k; i++) {
      prepHash[i] = this.baseInputs.s[i]
      prepHash[k + i] = this.baseInputs.U[0][i]
      prepHash[2 * k + i] = this.baseInputs.U[1][i]
      prepHash[3 * k + i] = pubKey[0][i] as never
      prepHash[4 * k + i] = pubKey[1][i] as never
    }

    const inputs = [..._.flattenDeep(prepHash.filter((item) => item))].map(
      (v) => BigNumber.from(v)
    )

    const mimc7 = await new Mimc7().prepare()
    const hash = mimc7.hash(inputs)
    expect(hash).to.equal(witness[1])
  })
  it('should fail because inputs are different', async function () {
    const witness = await this.circuit.calculateWitness(this.baseInputs)
    await this.circuit.assertOut(witness, {})

    const inputs = [
      ..._.flattenDeep(this.baseInputs.TPreComputes),
      ..._.flattenDeep(this.baseInputs.U),
      ..._.flattenDeep(this.baseInputs.s),
    ].map((v) => BigNumber.from(v))

    const mimc7 = await new Mimc7().prepare()
    const hash = mimc7.hash(inputs)
    expect(hash).not.to.equal(witness[1])
  })
})
