import { Wallet } from 'ethers'
import { expect } from 'chai'
import { wasm as wasmTester } from 'circom_tester'
import Mimc7 from '../utils/Mimc7'
import getECDSAInputs from '../utils/inputs/getECDSAInputs'

describe('ECDSAChecker circuit', function () {
  before(async function () {
    this.circuit = await wasmTester('circuits/ECDSAChecker.circom')
    this.wallet = Wallet.createRandom()
    this.baseInputs = await getECDSAInputs(this.wallet)
  })
  it('should generate the witness successfully and return correct mimc7', async function () {
    const witness = await this.circuit.calculateWitness(this.baseInputs)
    await this.circuit.assertOut(witness, {})
    // Check commitment
    const mimc7 = await new Mimc7().prepare()
    const hash = mimc7.hash([
      ...this.baseInputs.s,
      ...this.baseInputs.U[0],
      ...this.baseInputs.U[1],
      this.wallet.address,
    ])
    expect(hash).to.equal(witness[1])
    // Check hash of U
    const hashU = mimc7.hash([...this.baseInputs.U[0], ...this.baseInputs.U[1]])
    expect(hashU).to.equal(witness[2])
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
