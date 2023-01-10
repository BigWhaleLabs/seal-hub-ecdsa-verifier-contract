pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../efficient-zk-sig/secp256k1_scalar_mult_cached_windowed.circom";
include "../node_modules/circomlib/circuits/mimc.circom";
include "../efficient-zk-sig/circom-ecdsa-circuits/ecdsa.circom";

// check if scalar*groupPoint = expected val for group pt T = r^{-1}*R, scalar=r, expected val = R
template PrecompCheckT(k, n) {
  signal input scalar[k]; // r
  signal input pointPreComputes[32][256][2][4]; 
  signal input precomp[2][k]; // input precomputed value R

  signal mul[2][k]; 

  component scalarMul;
  scalarMul = Secp256K1ScalarMultCachedWindowed(n, k);

  for (var i = 0; i < 32; i++) {
    for (var j = 0; j < 256; j++) {
      for (var l = 0; l < 2; l++) {
        for (var m = 0; m < 4; m++) {
          scalarMul.pointPreComputes[i][j][l][m] <== pointPreComputes[i][j][l][m];
        }
      }
    }
  }

  for (var i = 0; i < k; i++){
    scalarMul.scalar[i] <== scalar[i];
  }

  for (var i = 0; i < k; i++){
    mul[0][i]<==scalarMul.out[0][i];
    mul[1][i]<==scalarMul.out[1][i];
  }

  component compare[2*k]; // to compare mul and precomp

  for (var i = 0; i < k; i++){
    compare[i] = IsEqual();
    compare[i].in[0] <== precomp[0][i];
    compare[i].in[1] <== mul[0][i];
    compare[i].out === 1;

    compare[i + k] = IsEqual();
    compare[i + k].in[0] <== precomp[1][i];
    compare[i + k].in[1] <== mul[1][i];
    compare[i + k].out === 1;
  }
}

// check if scalar*groupPoint = precomp for precomputed U = r^{-1}*m*G, and hash(scalar*groupPoint) = hash(precomp)
template PrecompCheckU(k, n) {
  signal input scalar[k]; // r^{-1}*m is the scalar
  signal input precomp[2][k]; // input precomputed value
  signal input precompHash; // hash of the precomputed value

  signal mul[2][k]; 

  component scalarMul;
  scalarMul = ECDSAPrivToPub(n, k); // computes scalar*G (using cached multiples)

  for (var i = 0; i < k; i++){
    scalarMul.privkey[i] <== scalar[i];
  }

  for (var i = 0; i < k; i++){
    mul[0][i]<==scalarMul.pubkey[0][i];
    mul[1][i]<==scalarMul.pubkey[1][i];
  }

  component compare[2*k]; // to compare mul and precomp

  for (var i = 0; i < k; i++){
    compare[i] = IsEqual();
    compare[i].in[0] <== precomp[0][i];
    compare[i].in[1] <== mul[0][i];
    compare[i].out === 1;

    compare[i + k] = IsEqual();
    compare[i + k].in[0] <== precomp[1][i];
    compare[i + k].in[1] <== mul[1][i];
    compare[i + k].out === 1;
  }

  component mimc7 = MultiMiMC7(2*k, 91);
  mimc7.k <== 0;
  signal hash;

  for (var i = 0; i < k; i++){
    mimc7.in[i] <== mul[0][i];
    mimc7.in[k+i] <== mul[1][i];
  }

  hash <== mimc7.out;
  hash === precompHash;
}