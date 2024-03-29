import { cwd } from 'process'
import { resolve } from 'path'
import { writeFileSync } from 'fs'
import getECDSAInputs from '../utils/inputs/getECDSAInputs'
import getUPrecomputesInputs from '../utils/inputs/getUPrecomputesInputs'
import wallet from '../utils/wallet'

void (async () => {
  console.log('ECDSA private key', wallet.privateKey)
  console.log('ECDSA public key', wallet.publicKey)
  console.log('ECDSA address', wallet.address)
  const inputs = {
    ecdsa: getECDSAInputs,
    'u-precomputes': getUPrecomputesInputs,
  }
  for (const [name, fn] of Object.entries(inputs)) {
    const inputs = await fn()
    // Writing inputs
    writeFileSync(
      resolve(cwd(), 'inputs', `input-${name}.json`),
      JSON.stringify(
        inputs,
        (this,
        (key, value) => (typeof value === 'bigint' ? value.toString() : value)) // return everything else unchanged
      ),
      'utf-8'
    )
    console.log(`Generated input-${name}.json!`)
  }
})()
