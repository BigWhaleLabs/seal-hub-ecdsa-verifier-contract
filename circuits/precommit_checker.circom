pragma circom 2.1.0;

include "circomlib/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mimcsponge.circom";

// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

// check if m*G = precomp, and hash(m*G) = hash(precomp)
template single_precomp_check() {

    signal input G;
    signal input m;
    signal input precomp; //input precomputed value
    signal input precomp_hash; //hash of the precomputed value
    
    signal mul;

    component compare; //comparator

    mul <== m*G;

    compare = IsEqual();

    compare.in[0] <== precomp;
    compare.in[1] <== mul;
    compare.out === 1;

    component hasher = MiMCSponge(1, 220, 1);
    signal hash;
    hasher.ins[0] <== mul;
    hasher.k <== 0;
    hash <== hasher.outs[0];

    hash === precomp_hash;

}


//takes as input the multiple possible m values, G, precomputed multiples of G, checks correctness, and commitment/hash of precompute

template multi_precomp_check(num_m) {

    signal input G;
    signal input m[num_m];
    signal input precomp[num_m]; //input precomputed value = [ m[0]*G, m[1]*G, m[2]*G, ...., m[num_m-1]**G]
    signal input precomp_hash;

    signal mul[num_m]; //to hold multiplactions to compare

    component compare[num_m];

    component hasher = MiMCSponge(num_m, 220, 1);
    signal hash;

    

    for (var i = 0; i < num_m; i++){

        mul[i] <== m[i]*G;

        compare[i] = IsEqual();

        compare[i].in[0] <== precomp[i];
        compare[i].in[1] <== mul[i];
        compare[i].out === 1;

        hasher.ins[i] <== mul[i];


    }

    hasher.k <== 0;
    hash <== hasher.outs[0];
    hash === precomp_hash;
}

//takes as input the message space range (from 0 to m_space), G, precomputed multiples of G, checks correctness, hash of precompute

template range_precomp_check(m_space) {

    signal input G;
    signal input precomp[m_space]; //input precomputed value = [0 , G, 2*G, 3*G, ...., (m_space-1)*G]
    signal input precomp_hash;

    signal mul[m_space]; //to hold multiplactions to compare

    component compare[m_space];

    component hasher = MiMCSponge(m_space, 220, 1);
    signal hash;

    for (var i = 0; i < m_space; i++){


        mul[i] <== i*G;

        compare[i] = IsEqual();

        compare[i].in[0] <== precomp[i];
        compare[i].in[1] <== mul[i];
        compare[i].out === 1;

        hasher.ins[i] <== mul[i];

    }

    hasher.k <== 0;
    hash <== hasher.outs[0];
    hash === precomp_hash;

    log(hash);
}

component main { public [ G, precomp, precomp_hash ] } = range_precomp_check(3);

/* INPUT = {
    "G": "5",
    "precomp": ["0", "5", "10"],
    "precomp_hash": "2513270011772409283706691126601629720189034777014885588490675828976910378425"
} */
