pragma circom 2.0.4;

include "../circom-ecdsa/circuits/ecdsa.circom";

template ECDSAChecker() {
  var balanceMessageLength = 5;
  // Get messages
  signal input balanceMessage[balanceMessageLength];
  signal input address;
  // Gather signals
  signal output attestationType <== balanceMessage[0];
  signal ownersMerkleRoot <== balanceMessage[1];
  signal output tokenAddress <== balanceMessage[2];
  signal output network <== balanceMessage[3];
  signal output threshold <== balanceMessage[4];
  // Check if the EdDSA signature of token balance is valid
  signal input balancePubKeyX;
  signal input balancePubKeyY;
  signal input balanceR8x;
  signal input balanceR8y;
  signal input balanceS;

  component edDSAValidatorToken = EdDSAValidator(balanceMessageLength);
  edDSAValidatorToken.pubKeyX <== balancePubKeyX;
  edDSAValidatorToken.pubKeyY <== balancePubKeyY;
  edDSAValidatorToken.R8x <== balanceR8x;
  edDSAValidatorToken.R8y <== balanceR8y;
  edDSAValidatorToken.S <== balanceS;
  for (var i = 0; i < balanceMessageLength; i++) {
    edDSAValidatorToken.message[i] <== balanceMessage[i];
  }
  // Check if the EdDSA signature of address is valid
  signal input addressPubKeyX;
  signal input addressPubKeyY;
  signal input addressR8x;
  signal input addressR8y;
  signal input addressS;

  component edDSAValidatorAddress = EdDSAValidator(1);
  edDSAValidatorAddress.pubKeyX <== addressPubKeyX;
  edDSAValidatorAddress.pubKeyY <== addressPubKeyY;
  edDSAValidatorAddress.R8x <== addressR8x;
  edDSAValidatorAddress.R8y <== addressR8y;
  edDSAValidatorAddress.S <== addressS;
  edDSAValidatorAddress.message[0] <== address;
  // Check if attestors are the same
  balancePubKeyX === addressPubKeyX;
  // Create nullifier
  signal input nonce[2];
  
  component nullifier = Nullify();
  nullifier.r <== nonce[0];
  nullifier.s <== nonce[1];

  signal output nullifierHash <== nullifier.nullifierHash;
  // Check Merkle proof
  var levels = 20;
  signal input pathIndices[levels];
  signal input siblings[levels];

  component merkleTreeChecker = MerkleTreeChecker(levels);
  merkleTreeChecker.leaf <== address;
  merkleTreeChecker.root <== ownersMerkleRoot;
  for (var i = 0; i < levels; i++) {
    merkleTreeChecker.pathElements[i] <== siblings[i];
    merkleTreeChecker.pathIndices[i] <== pathIndices[i];
  }
}

component main{public [balancePubKeyX]} = BalanceChecker();