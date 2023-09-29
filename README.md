# sigmabus-poc
Proof of concept implementation of Sigmabus https://eprint.iacr.org/2023/1406, a cool idea by [George Kadianakis](https://twitter.com/asn_d6) and [Mary Maller](https://www.marymaller.com/) and [Andrija Novakovic](https://twitter.com/AndrijaNovakov6).

> Experimental code, do not use in production.


This PoC implements [Sigmabus](https://eprint.iacr.org/2023/1406) to prove & verify that $X = x \cdot G \in \mathbb{G}$ for a public input $X \in \mathbb{G}$ and a private input $x \in \mathbb{F}_r$ ($\mathbb{G}$'s ScalarField), while the circuit is defined on $\mathbb{F}_r$ (note that $\mathbb{G}$ coordinates are on $\mathbb{F}_q$ ($\mathbb{G}$'s BaseField)).

Proving $X = x \cdot G$ with a 'traditional' approach in a zkSNARK circuit, would require non-native arithmetic for computing the scalar multiplication $x \cdot G \in \mathbb{G}$ over $\mathbb{F}_r$, which would take lot of constraints. The number of constraints in the circuit for this Sigmabus instantiation mainly depends on the constraints needed for 2 Poseidon hashes.

Let $\mathbb{G}$ be [BN254](https://hackmd.io/@jpw/bn254)'s $G1$, an example of usage would be:
```rust
// generate the trusted setup
let params = Sigmabus::<Bn254>::setup(&mut rng, &poseidon_config);

// compute X = x * G
let x = Fr::rand(&mut rng);
let X = G1Projective::generator().mul(x);

// generate Sigmabus proof for X==x*G
let mut transcript_p = PoseidonTranscript::<G1Projective>::new(&poseidon_config);
let proof = Sigmabus::<Bn254>::prove(&mut rng, &params, &mut transcript_p, x);

// verify Sigmabus proof for X==x*G
let mut transcript_v = PoseidonTranscript::<G1Projective>::new(&poseidon_config);
Sigmabus::<Bn254>::verify(&params, &mut transcript_v, proof, X).unwrap();
```
