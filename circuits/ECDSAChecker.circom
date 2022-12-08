pragma circom 2.0.6;

include "../efficient-zk-sig/ecdsa_verify.circom";
include "../efficient-zk-sig/circom-ecdsa-circuits/zk-identity/eth.circom";
include "../node_modules/circomlib/circuits/mimc.circom";

template ECDSAChecker(k, n) {
  // Verify ECDSA signature
  signal input s[k];
  signal input TPreComputes[32][256][2][4];
  signal input U[2][k];

  component verifySignature = ECDSAVerify(n, k);
  for (var i = 0; i < k; i++) {
    verifySignature.s[i] <== s[i];
    verifySignature.U[0][i] <== U[0][i];
    verifySignature.U[1][i] <== U[1][i];
  }
  for (var i = 0; i < 32; i++) {
    for (var j = 0; j < 256; j++) {
      for (var l = 0; l < 2; l++) {
        for (var m = 0; m < 4; m++) {
          verifySignature.TPreComputes[i][j][l][m] <== TPreComputes[i][j][l][m];
        }
      }
    }
  }
  // Get the public key
  signal pubKey[2][k];
  for (var i = 0; i < k; i++) {
    pubKey[0][i] <== verifySignature.pubKey[0][i];
    pubKey[1][i] <== verifySignature.pubKey[1][i];
  }

  // Get address
  component flattenPubkey = FlattenPubkey(n, k);
  for (var i = 0; i < k; i++) {
    flattenPubkey.chunkedPubkey[0][i] <== verifySignature.pubKey[0][i];
    flattenPubkey.chunkedPubkey[1][i] <== verifySignature.pubKey[1][i];
  }
  component pubKeyToAddress = PubkeyToAddress();
  for (var i = 0; i < 512; i++) {
    pubKeyToAddress.pubkeyBits[i] <== flattenPubkey.pubkeyBits[i];
  }
  signal address <== pubKeyToAddress.address;

  // Generate commitment
  component mimc7 = MultiMiMC7(k * 3 + 1, 91);
  mimc7.k <== 0;
  for (var i = 0; i < k; i++) {
    mimc7.in[i] <== s[i];
    mimc7.in[k + i] <== U[0][i];
    mimc7.in[2 * k + i] <== U[1][i];
  }
  mimc7.in[3 * k] <== address;

  signal output commitment <== mimc7.out;
}

component main = ECDSAChecker(4, 64);