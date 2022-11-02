pragma circom 2.0.4;

include "../circom-ecdsa/circuits/ecdsa.circom";

template ECDSAChecker() {
  var k = 4;
  var n = 64;
  
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

  
}

component main{public [pubKey]} = ECDSAChecker();