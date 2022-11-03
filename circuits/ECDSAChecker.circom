pragma circom 2.0.4;

include "../circom-ecdsa/circuits/ecdsa.circom";
include "../node_modules/circomlib/circuits/mimc.circom";

template ECDSAChecker(k, n) {
  // Verify ECDSA signature
  signal input r[k];
  signal input s[k];
  signal input msgHash[k];
  signal input pubKey[2][k];

  component verifySignature = ECDSAVerifyNoPubkeyCheck(n, k);
  for (var i = 0; i < k; i++) {
    verifySignature.r[i] <== r[i];
    verifySignature.s[i] <== s[i];
    verifySignature.msghash[i] <== msgHash[i];
    for (var j = 0; j < 2; j++) {
      verifySignature.pubkey[j][i] <== pubKey[j][i];
    }
  }
  verifySignature.result === 1;

  // Hash message
  component mimc7 = MultiMiMC7(k, 91);
  mimc7.k <== 0;
  for (var i = 0; i < k; i++) {
    mimc7.in[i] <== msgHash[i];
  }

  signal output commitment <== mimc7.out;
}

component main = ECDSAChecker(4, 64);