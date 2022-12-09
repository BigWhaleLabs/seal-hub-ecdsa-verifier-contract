import { Wallet } from 'ethers'
import { expect } from 'chai'
import {
  getCommitmentFromSignature,
  getMessageForAddress,
} from '@big-whale-labs/seal-hub-kit'
import { wasm as wasmTester } from 'circom_tester'
import getECDSAInputs from '../utils/inputs/getECDSAInputs'

describe('ECDSAChecker circuit', function () {
  before(async function () {
    this.circuit = await wasmTester('circuits/ECDSAChecker.circom')
    this.wallet = Wallet.createRandom()
    this.message = getMessageForAddress(this.wallet.address)
    this.signature = await this.wallet.signMessage(this.message)
    this.commitment = await getCommitmentFromSignature(
      this.signature,
      this.message
    )
    this.baseInputs = await getECDSAInputs(this.wallet)
  })
  it('should generate the witness successfully and return correct commitment', async function () {
    const witness = await this.circuit.calculateWitness(this.baseInputs)
    await this.circuit.assertOut(witness, {})
    // Check commitment
    expect(this.commitment).to.equal(witness[1])
  })
})
