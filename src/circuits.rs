use ark_crypto_primitives::crh::{
    poseidon::constraints::{CRHGadget, CRHParametersVar},
    CRHSchemeGadget,
};
use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ec::{AffineRepr, CurveGroup};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;

// CF (ConstraintField)
pub type CF<C> = <<C as CurveGroup>::Affine as AffineRepr>::ScalarField;

#[derive(Debug, Clone)]
pub struct GenZKCircuit<C: CurveGroup> {
    pub _c: PhantomData<C>,
    pub poseidon_config: PoseidonConfig<C::ScalarField>,
    // public
    pub cm: C::ScalarField,
    pub s: C::ScalarField,
    pub r_h: C::ScalarField,
    pub c: C::ScalarField,
    // private
    pub x: C::ScalarField,
    pub r: C::ScalarField,
    pub o_h: C::ScalarField,
}
impl<C: CurveGroup> ConstraintSynthesizer<CF<C>> for GenZKCircuit<C>
where
    C::ScalarField: Absorb,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<CF<C>>) -> Result<(), SynthesisError> {
        // public inputs
        let cmVar = FpVar::<C::ScalarField>::new_input(cs.clone(), || Ok(self.cm))?;
        let sVar = FpVar::<C::ScalarField>::new_input(cs.clone(), || Ok(self.s))?;
        let r_hVar = FpVar::<C::ScalarField>::new_input(cs.clone(), || Ok(self.r_h))?;
        let cVar = FpVar::<C::ScalarField>::new_input(cs.clone(), || Ok(self.c))?;

        // private inputs
        let xVar = FpVar::<C::ScalarField>::new_witness(cs.clone(), || Ok(self.x))?;
        let rVar = FpVar::<C::ScalarField>::new_witness(cs.clone(), || Ok(self.r))?;
        let o_hVar = FpVar::<C::ScalarField>::new_witness(cs.clone(), || Ok(self.o_h))?;

        let crh_params =
            CRHParametersVar::<C::ScalarField>::new_witness(
                cs.clone(),
                || Ok(self.poseidon_config),
            )
            .unwrap();

        Self::check(&crh_params, cmVar, sVar, r_hVar, cVar, xVar, rVar, o_hVar)?;

        Ok(())
    }
}

impl<C: CurveGroup> GenZKCircuit<C>
where
    C::ScalarField: Absorb,
{
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        crh_params: &CRHParametersVar<C::ScalarField>,
        // public inputs:
        cm: FpVar<C::ScalarField>,
        s: FpVar<C::ScalarField>,
        r_h: FpVar<C::ScalarField>,
        c: FpVar<C::ScalarField>,
        // private inputs:
        x: FpVar<C::ScalarField>,
        r: FpVar<C::ScalarField>,
        o_h: FpVar<C::ScalarField>,
    ) -> Result<(), SynthesisError> {
        // cm == Commit(x) (Poseidon)
        let computed_cm = CRHGadget::<C::ScalarField>::evaluate(crh_params, &[x.clone()]).unwrap();
        computed_cm.enforce_equal(&cm)?;

        // r_h == HCommit(r, o_h) (Poseidon)
        let computed_r_h =
            CRHGadget::<C::ScalarField>::evaluate(crh_params, &[r.clone(), o_h.clone()]).unwrap();
        computed_r_h.enforce_equal(&r_h)?;

        // s == r + c * x
        s.enforce_equal(&(r + (c * x)))?;
        Ok(())
    }
}

// Note: since at the v0.4.0 of ark_curves the bn254 curve does not have the constraints
// implemented, for the following tests we use the pallas curve.
#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use ark_ec::Group;
    use ark_ff::{BigInteger, PrimeField};
    use ark_r1cs_std::{
        alloc::AllocVar,
        boolean::Boolean,
        fields::{fp::FpVar, nonnative::NonNativeFieldVar, FieldVar},
        groups::GroupOpsBounds,
        prelude::CurveVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::UniformRand;
    use std::ops::Mul;

    // import pallas curve
    use ark_pallas::{Fq, Fr, Projective};
    // instead of ark_pallas::constraints::GVar we use a custom non-native version of it:
    use ark_pallas::PallasConfig;
    use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
    pub type NonNativePallasGVar = ProjectiveVar<PallasConfig, NonNativeFieldVar<Fq, Fr>>;

    use crate::sigmabus::SigmaProof;
    use crate::transcript::{tests::poseidon_test_config, PoseidonTranscript};

    #[test]
    fn test_gen_zk() {
        let mut rng = ark_std::test_rng();

        let poseidon_config = poseidon_test_config::<Fr>();
        let mut transcript = PoseidonTranscript::<Projective>::new(&poseidon_config);

        let x = Fr::rand(&mut rng);

        // the next lines do the same that is done in Sigmabus::prove but here in the test to have
        // access to the internal values:
        let mut sponge = PoseidonSponge::<Fr>::new(&poseidon_config);
        sponge.absorb(&x);
        let cm: Fr = sponge.squeeze_field_elements(1)[0];
        transcript.absorb(&cm);

        let r = Fr::rand(&mut rng);
        let o_h = Fr::rand(&mut rng);

        let R = Projective::generator().mul(r);

        let mut sponge = PoseidonSponge::<Fr>::new(&poseidon_config);
        sponge.absorb(&vec![r, o_h]);

        let r_h: Fr = sponge.squeeze_field_elements(1)[0];

        transcript.absorb_point(&R);
        transcript.absorb(&r_h);
        let c = transcript.get_challenge();

        let s = r + c * x;
        let sigma_proof = SigmaProof { s, R, r_h };
        // end of Sigmabus::prove

        let cs = ConstraintSystem::<Fr>::new_ref();

        // public inputs
        let cmVar = FpVar::<Fr>::new_witness(cs.clone(), || Ok(cm)).unwrap();
        let sVar = FpVar::<Fr>::new_witness(cs.clone(), || Ok(sigma_proof.s)).unwrap();
        let r_hVar = FpVar::<Fr>::new_witness(cs.clone(), || Ok(sigma_proof.r_h)).unwrap();
        let cVar = FpVar::<Fr>::new_witness(cs.clone(), || Ok(c)).unwrap();
        // private inputs
        let xVar = FpVar::<Fr>::new_witness(cs.clone(), || Ok(x)).unwrap();
        let rVar = FpVar::<Fr>::new_witness(cs.clone(), || Ok(r)).unwrap();
        let o_hVar = FpVar::<Fr>::new_witness(cs.clone(), || Ok(o_h)).unwrap();

        let crh_params =
            CRHParametersVar::<Fr>::new_witness(cs.clone(), || Ok(poseidon_config)).unwrap();

        // GenZK
        GenZKCircuit::<Projective>::check(
            &crh_params,
            cmVar,
            sVar,
            r_hVar,
            cVar,
            xVar,
            rVar,
            o_hVar,
        )
        .unwrap();
        assert!(cs.is_satisfied().unwrap());
        dbg!(cs.num_constraints());
    }

    // This circuit implements the x*G operation that Sigmabus proves, but here we do it in the
    // 'naive' way, which is computing it non-natively.
    struct NonNativeScalarMulCircuit<
        C: CurveGroup,
        GC: CurveVar<C, C::ScalarField>,
        FV: FieldVar<C::BaseField, C::ScalarField>,
    > {
        _gc: PhantomData<GC>,
        _fv: PhantomData<FV>,
        pub x: C::ScalarField,
        pub X: C,
    }
    impl<C, GC, FV> ConstraintSynthesizer<CF<C>> for NonNativeScalarMulCircuit<C, GC, FV>
    where
        C: CurveGroup,
        GC: CurveVar<C, C::ScalarField>,
        FV: FieldVar<C::BaseField, C::ScalarField>,
        for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
    {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<CF<C>>,
        ) -> Result<(), SynthesisError> {
            let G = GC::new_constant(cs.clone(), C::generator())?;
            let x_bits = Vec::<Boolean<CF<C>>>::new_input(cs.clone(), || {
                Ok(self.x.into_bigint().to_bits_le())
            })?;
            let X = GC::new_input(cs.clone(), || Ok(self.X))?;

            let xG = G.scalar_mul_le(x_bits.iter())?;
            xG.enforce_equal(&X)?;

            Ok(())
        }
    }

    #[test]
    fn test_nonnative_num_constraints() {
        let mut rng = ark_std::test_rng();

        // compute X = x * G
        let x = Fr::rand(&mut rng);
        let X = Projective::generator().mul(x);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let nonnative_scalarmul_circuit = NonNativeScalarMulCircuit::<
            Projective,
            NonNativePallasGVar,
            NonNativeFieldVar<Fq, Fr>,
        > {
            _gc: PhantomData,
            _fv: PhantomData,
            x,
            X,
        };

        assert!(cs.is_satisfied().unwrap());
        dbg!(cs.num_constraints());
    }
}
