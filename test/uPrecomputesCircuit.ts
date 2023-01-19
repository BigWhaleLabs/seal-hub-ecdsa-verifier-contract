import { Wallet } from 'ethers'
import { expect } from 'chai'
import { wasm as wasmTester } from 'circom_tester'
import Mimc7 from '../utils/Mimc7'
import getUPrecomputesInputs from '../utils/inputs/getUPrecomputesInputs'

describe('UPrecomputesChecker circuit', function () {
  before(async function () {
    this.circuit = await wasmTester('circuits/UPrecomputesChecker.circom')
    this.wallet = Wallet.createRandom()
    this.baseInputs = await getUPrecomputesInputs(this.wallet)
  })
  it.only('should generate the witness successfully and return correct mimc7', async function () {
    const witness = await this.circuit.calculateWitness(this.baseInputs)
    await this.circuit.assertOut(witness, {})
    // Check commitment
    const mimc7 = await new Mimc7().prepare()
    const hash = mimc7.hash([...this.baseInputs.U[0], ...this.baseInputs.U[1]])
    expect(hash).to.equal(witness[1])
  })
  it('should fail because inputs are different', async function () {
    const witness = await this.circuit.calculateWitness(this.baseInputs)
    await this.circuit.assertOut(witness, {})

    const inputs = this.baseInputs

    // corrupt input
    inputs[0] = BigInt(0)

    const mimc7 = await new Mimc7().prepare()
    const hash = mimc7.hash(inputs)
    expect(hash).not.to.equal(witness[1])
  })
})
