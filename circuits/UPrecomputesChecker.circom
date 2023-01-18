pragma circom 2.1.0;

include "../efficient-zk-sig/circom-ecdsa-circuits/ecdsa.circom";
include "../efficient-zk-sig/secp256k1_scalar_mult_cached_windowed.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mimc.circom";

// Check if scalar * groupPoint = precomp for precomputed U = r^{-1} * m * G, and hash(scalar * groupPoint) = hash(precomp)
template UPrecomputesChecker(k, n) {
  signal input scalarForU[k]; // r^{-1} * m is the scalar
  signal input U[2][k]; // input precomputed value

  // Populate scalarMul
  component scalarMul = ECDSAPrivToPub(n, k); // computes scalar * G (using cached multiples)

  for (var i = 0; i < k; i++){
    scalarMul.privkey[i] <== scalarForU[i];
  }
  // Populate mul
  signal mul[2][k]; 

  for (var i = 0; i < k; i++){
    mul[0][i] <== scalarMul.pubkey[0][i];
    mul[1][i] <== scalarMul.pubkey[1][i];
  }
  // Compare mul and precomp
  component compare[2 * k];

  for (var i = 0; i < k; i++){
    compare[i] = IsEqual();
    compare[i].in[0] <== U[0][i];
    compare[i].in[1] <== mul[0][i];
    compare[i].out === 1;

    compare[i + k] = IsEqual();
    compare[i + k].in[0] <== U[1][i];
    compare[i + k].in[1] <== mul[1][i];
    compare[i + k].out === 1;
  }
  // Generate UPrecomputes hash
  component mimc7 = MultiMiMC7(2 * k, 91);
  mimc7.k <== 0;

  for (var i = 0; i < k; i++){
    mimc7.in[i] <== mul[0][i];
    mimc7.in[k + i] <== mul[1][i];
  }

  signal output hash <== mimc7.out;
}

component main = UPrecomputesChecker(4, 64);
