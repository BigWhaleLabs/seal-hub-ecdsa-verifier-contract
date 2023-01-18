import { ethers } from 'hardhat'
import { expect } from 'chai'
import { version } from '../package.json'
import getSolidityCallProof from '../utils/getSolidityCallProof'

describe('CompleteECDSACheckerVerifier contract', function () {
  before(async function () {
    // Get UPrecomputesCheckerVerifier contract
    const uPrecomputesFactory = await ethers.getContractFactory(
      'UPrecomputesCheckerVerifier'
    )
    this.uPrecomputesContract = await uPrecomputesFactory.deploy(version)
    await this.uPrecomputesContract.deployed()
    // Get ECDSACheckerVerifier contract
    const ecdsaFactory = await ethers.getContractFactory('ECDSACheckerVerifier')
    this.ecdsaContract = await ecdsaFactory.deploy(version)
    await this.ecdsaContract.deployed()
    // Get CompleteECDSACheckerVerifier contract
    const factory = await ethers.getContractFactory(
      'CompleteECDSACheckerVerifier'
    )
    this.contract = await factory.deploy(
      version,
      this.ecdsaContract.address,
      this.uPrecomputesContract.address
    )
    await this.contract.deployed()
    // Get proofs
    this.uPrecomputesProof = await getSolidityCallProof('u-precomputes')
    this.ecdsaProof = await getSolidityCallProof('ecdsa')
  })
  describe('Constructor', function () {
    it('should deploy the contract with the correct fields', async function () {
      expect(await this.contract.version()).to.equal(version)
    })
  })
  it('should successfully verify correct proof', async function () {
    expect(
      await this.contract.verifyProofs(this.ecdsaProof, this.uPrecomputesProof)
    ).to.be.equal(true)
  })
  it('should fail to verify incorrect ecdsa proof', async function () {
    await expect(
      this.contract.verifyProofs(
        {
          ...this.ecdsaProof,
          c: [
            '0x184b074c1fac82c2dda436071d098edb4a2955343721ef642e6b844e40a50cc0',
            '0x1e11078629c2031c0eb203d84f745e423440ed52091d06ece6020cd5674fda5f',
          ],
        },
        this.uPrecomputesProof
      )
    ).to.be.revertedWith('ECDSA proof failed')
  })
  it('should fail to verify incorrect precomputes proof', async function () {
    await expect(
      this.contract.verifyProofs(this.ecdsaProof, {
        ...this.uPrecomputesProof,
        c: [
          '0x184b074c1fac82c2dda436071d098edb4a2955343721ef642e6b844e40a50cc0',
          '0x1e11078629c2031c0eb203d84f745e423440ed52091d06ece6020cd5674fda5f',
        ],
      })
    ).to.be.revertedWith('UPrecomputes proof failed')
  })
  it('should fail to verify if proofs are for different precomputes', async function () {
    await expect(
      this.contract.verifyProofs(this.ecdsaProof, {
        ...this.uPrecomputesProof,
        input: [
          '0x2a736cf3d9bae76bfce4b699e45ad68ca1aaa7b96ec20ca6b4864433742affdd',
        ],
      })
    ).to.be.revertedWith('Input mismatch')
  })
})
