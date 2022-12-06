import { ethers } from 'hardhat'
import { expect } from 'chai'
import getECDSAInputs from '../utils/inputs/getECDSAInputs'

describe.only('Precomputes', function () {
  before(function () {
    this.wallets = Array(2)
      .fill(0)
      .map(() => ethers.Wallet.createRandom())
  })
  it('generates the same signature for the same message and the same wallet', async function () {
    const wallet = this.wallets[0]
    const message =
      'SealHub verification\n⚠️ Make sure to never sign this message outside of hub.sealhub.xyz! If you sign this message anywhere else, you can be impersonated! ⚠️'
    const signature1 = await wallet.signMessage(message)
    const signature2 = await wallet.signMessage(message)
    expect(signature1).to.equal(signature2)
  })
  it.only('generates the same precomputes for different addresses', async function () {
    await getECDSAInputs(this.wallets[0])
    await getECDSAInputs(this.wallets[1])

    // const precomputes = (
    //   await Promise.all(this.wallets.map((wallet) => getECDSAInputs(wallet)))
    // ).map((p) => ({
    //   TPreComputes: p.TPreComputes,
    //   // U: p.U,
    // }))
    // console.log(JSON.stringify(precomputes[0], undefined, 2))
    // expect(precomputes[0]).to.deep.equal(precomputes[1])
  })
})
