pragma circom 2.1.0;

include "../efficient-zk-sig/circom-ecdsa-circuits/ecdsa.circom";
include "../efficient-zk-sig/secp256k1_scalar_mult_cached_windowed.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mimc.circom";

// Check if scalar * groupPoint = precomp for precomputed U = r^{-1} * m * G, and hash(scalar * groupPoint) = hash(precomp)
template UPrecomputesChecker(k, n) {
  // Get prime order
  var order[100] = get_secp256k1_order(n, k);
  // Message is predefined for SealHub
  signal msgHash[k];
  msgHash[0] <== 10098449060333729392;
  msgHash[1] <== 824620465769997390;
  msgHash[2] <== 6522454934198464922;
  msgHash[3] <== 2124243329339765579;
  // Calculate -r^{-1} * m
  signal input rInv[k];
  component negate = BigSubModP(n, k);

  for (var i = 0; i < k; i++){
    negate.a[i] <== 0;
    negate.b[i] <== rInv[i];
    negate.p[i] <== order[i];
  }

  signal negRInv[k];
  for (var i = 0; i < k; i++){
    negRInv[i] <== negate.out[i];
  }
  // Calculate scalar
  signal scalarForU[k]; // r^{-1} * m is the scalar

  component scalarMulMod = BigMultModP(n, k);
  
  for (var i = 0; i < k; i++){
    scalarMulMod.a[i] <== negRInv[i];
    scalarMulMod.b[i] <== msgHash[i];
    scalarMulMod.p[i] <== order[i];
  }
  for (var i = 0; i < k; i++){
    scalarForU[i] <== scalarMulMod.out[i];
  }
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
  signal input U[2][k]; // precomputed value

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
