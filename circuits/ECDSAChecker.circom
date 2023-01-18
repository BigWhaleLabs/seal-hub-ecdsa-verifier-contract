pragma circom 2.0.6;

include "../efficient-zk-sig/circom-ecdsa-circuits/zk-identity/eth.circom";
include "../efficient-zk-sig/ecdsa_verify.circom";
include "../node_modules/circomlib/circuits/mimc.circom";
include "./templates/TPrecomputesChecker.circom";

template ECDSAChecker(k, n) {
  // Verify ECDSA signature
  signal input s[k];
  signal input TPrecomputes[32][256][2][4];
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
          verifySignature.TPreComputes[i][j][l][m] <== TPrecomputes[i][j][l][m];
        }
      }
    }
  }
  // Verify TPrecomputes
  signal input scalarForT[k]; // r value
  signal input T[2][k]; // input R: expected val for checkT r * T = R

  component tPrecomputesChecker = TPrecomputesChecker(k, n); // load T vals

  for (var i = 0; i < k; i++) {
    tPrecomputesChecker.scalarForT[i] <== scalarForT[i];
    tPrecomputesChecker.T[0][i] <== T[0][i];
    tPrecomputesChecker.T[1][i] <== T[1][i];
  }
  for (var i = 0; i < 32; i++) {
    for (var j = 0; j < 256; j++) {
      for (var l = 0; l < 2; l++) {
        for (var m = 0; m < 4; m++) {
          tPrecomputesChecker.TPrecomputes[i][j][l][m] <== TPrecomputes[i][j][l][m];
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
  component commitmentMimc7 = MultiMiMC7(k * 3 + 1, 91);

  commitmentMimc7.k <== 0;
  for (var i = 0; i < k; i++) {
    commitmentMimc7.in[i] <== s[i];
    commitmentMimc7.in[k + i] <== U[0][i];
    commitmentMimc7.in[2 * k + i] <== U[1][i];
  }
  commitmentMimc7.in[3 * k] <== address;

  signal output commitment <== commitmentMimc7.out;
  // Generate hash of UPrecomputes
  component uMimc7 = MultiMiMC7(k * 2, 91);

  uMimc7.k <== 0;
  for (var i = 0; i < k; i++) {
    uMimc7.in[i] <== U[0][i];
    uMimc7.in[k + i] <== U[1][i];
  }

  signal output uHash <== uMimc7.out;
}

component main = ECDSAChecker(4, 64);
