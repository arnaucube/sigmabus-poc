use ark_crypto_primitives::{
    crh::{poseidon::CRH, CRHScheme},
    snark::SNARK,
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_groth16::{Groth16, Proof as Groth16Proof};
use ark_std::{
    rand::{CryptoRng, Rng},
    UniformRand, Zero,
};
use std::marker::PhantomData;
use std::ops::Mul;

use crate::circuits::GenZKCircuit;
use crate::transcript::PoseidonTranscript;
use crate::Error;

/// Proof represents the Sigmabus proof
pub struct Proof<E: Pairing> {
    cm: E::ScalarField,
    sigma_proof: SigmaProof<E::G1>,
    zkproof: Groth16Proof<E>,
}

/// SigmaProof represents the Sigma protocol proof (not Sigmabus proof)
pub struct SigmaProof<C: CurveGroup> {
    pub s: C::ScalarField,
    pub R: C,
    pub r_h: C::ScalarField,
}

pub struct Params<E: Pairing> {
    _e: PhantomData<E>,
    poseidon_config: PoseidonConfig<E::ScalarField>,
    pk: <Groth16<E> as SNARK<E::ScalarField>>::ProvingKey,
    vk: <Groth16<E> as SNARK<E::ScalarField>>::VerifyingKey,
}

/// Sigmabus implements [Sigmabus](https://eprint.iacr.org/2023/1406) prover & verifier for proving
/// X=x*G as described in section 3 of the paper, using Groth16's zkSNARK scheme.
pub struct Sigmabus<E: Pairing> {
    _e: PhantomData<E>,
}

impl<E: Pairing> Sigmabus<E>
where
    E::ScalarField: Absorb,
{
    pub fn setup<R: Rng + CryptoRng>(
        rng: &mut R,
        poseidon_config: &PoseidonConfig<E::ScalarField>,
    ) -> Params<E> {
        let circuit = GenZKCircuit::<E::G1> {
            _c: PhantomData,
            poseidon_config: poseidon_config.clone(),
            // public
            cm: E::ScalarField::zero(),
            s: E::ScalarField::zero(),
            r_h: E::ScalarField::zero(),
            c: E::ScalarField::zero(),
            // private
            x: E::ScalarField::zero(),
            r: E::ScalarField::zero(),
            o_h: E::ScalarField::zero(),
        };

        // generate the snark proof
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        Params::<E> {
            _e: PhantomData,
            poseidon_config: poseidon_config.clone(),
            pk,
            vk,
        }
    }

    pub fn prove<R: Rng + CryptoRng>(
        rng: &mut R,
        params: &Params<E>,
        transcript: &mut PoseidonTranscript<E::G1>,
        x: E::ScalarField,
    ) -> Result<Proof<E>, Error> {
        // cm
        let cm: E::ScalarField =
            CRH::<E::ScalarField>::evaluate(&params.poseidon_config, [x]).unwrap();
        transcript.absorb(&cm);

        let r = E::ScalarField::rand(rng);
        let o_h = E::ScalarField::rand(rng);

        let R = E::G1::generator().mul(r);

        let r_h: E::ScalarField =
            CRH::<E::ScalarField>::evaluate(&params.poseidon_config, [r, o_h]).unwrap();

        transcript.absorb_point(&R);
        transcript.absorb(&r_h);

        let c = transcript.get_challenge();

        let s = r + c * x;

        let circuit = GenZKCircuit::<E::G1> {
            _c: PhantomData,
            poseidon_config: params.poseidon_config.clone(),
            // public
            cm,
            s,
            r_h,
            c,
            // private
            x,
            r,
            o_h,
        };

        // generate the snark proof
        let zkproof = Groth16::<E>::prove(&params.pk, circuit.clone(), rng).unwrap();

        Ok(Proof {
            cm,
            sigma_proof: SigmaProof { s, R, r_h },
            zkproof,
        })
    }

    pub fn verify(
        params: &Params<E>,
        transcript: &mut PoseidonTranscript<E::G1>,
        proof: Proof<E>,
        X: E::G1,
    ) -> Result<(), Error> {
        let lhs = E::G1::generator().mul(proof.sigma_proof.s);

        transcript.absorb(&proof.cm);
        transcript.absorb_point(&proof.sigma_proof.R);
        transcript.absorb(&proof.sigma_proof.r_h);
        let c = transcript.get_challenge();

        let rhs = proof.sigma_proof.R + X.mul(c);

        if lhs != rhs {
            return Err(Error::SigmaFail);
        }

        // verify zkSNARK proof
        let public_input = [proof.cm, proof.sigma_proof.s, proof.sigma_proof.r_h, c];

        let valid_proof = Groth16::<E>::verify(&params.vk, &public_input, &proof.zkproof).unwrap();
        if !valid_proof {
            return Err(Error::GenZKFail);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr, G1Projective};
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_std::test_rng;

    use crate::transcript::tests::poseidon_test_config;

    #[test]
    fn test_sigmabus_prove_verify() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let poseidon_config = poseidon_test_config::<Fr>();

        // generate the trusted setup
        let params = Sigmabus::<Bn254>::setup(&mut rng, &poseidon_config);

        // compute X = x * G
        let x = Fr::rand(&mut rng);
        let X = G1Projective::generator().mul(x);

        let mut transcript_p = PoseidonTranscript::<G1Projective>::new(&poseidon_config);

        // generate Sigmabus proof for X==x*G
        let proof = Sigmabus::<Bn254>::prove(&mut rng, &params, &mut transcript_p, x).unwrap();

        // verify Sigmabus proof for X==x*G
        let mut transcript_v = PoseidonTranscript::<G1Projective>::new(&poseidon_config);
        Sigmabus::<Bn254>::verify(&params, &mut transcript_v, proof, X).unwrap();
    }
}
