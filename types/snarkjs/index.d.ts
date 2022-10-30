declare module 'snarkjs' {
  const snarkjs: {
    groth16: {
      exportSolidityCallData: any
      fullProve: any
      prove: any
      verify: any
    }
    plonk: {
      exportSolidityCallData: any
      fullProve: any
      prove: any
      setup: any
      verify: any
    }
    powersOfTau: {
      beacon: any
      challengeContribute: any
      contribute: any
      convert: any
      exportChallenge: any
      exportJson: any
      importResponse: any
      newAccumulator: any
      preparePhase2: any
      truncate: any
      verify: any
    }
    r1cs: {
      exportJson: any
      info: any
      print: any
    }
    wtns: {
      calculate: any
      debug: any
      exportJson: any
    }
    zKey: {
      beacon: any
      bellmanContribute: any
      contribute: any
      exportBellman: any
      exportJson: any
      exportSolidityVerifier: any
      exportVerificationKey: any
      importBellman: any
      newZKey: any
      verifyFromInit: any
      verifyFromR1cs: any
    }
  }
  export = snarkjs
}
