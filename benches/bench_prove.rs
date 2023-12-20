use ark_std::UniformRand;
use sigmabus_poc::transcript::{tests::poseidon_test_config, PoseidonTranscript};

use criterion::{criterion_group, criterion_main, Criterion};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::test_rng;
use sigmabus_poc::sigmabus::Sigmabus;

fn bench_prove(c: &mut Criterion) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let poseidon_config = poseidon_test_config::<Fr>();

    // generate the trusted setup
    let params = Sigmabus::<Bn254>::setup(&mut rng, &poseidon_config);

    // compute the witness x
    let x = Fr::rand(&mut rng);

    let mut transcript_p = PoseidonTranscript::<G1Projective>::new(&poseidon_config);

    // generate Sigmabus proof for X==x*G
    c.bench_function("prove", |b| {
        b.iter(|| {
            let _proof = Sigmabus::<Bn254>::prove(&mut rng, &params, &mut transcript_p, x).unwrap();
        });
    });
}

criterion_group! {
    name=prover_benches;
    config=Criterion::default();
    targets=
            bench_prove,
}
criterion_main!(prover_benches);
