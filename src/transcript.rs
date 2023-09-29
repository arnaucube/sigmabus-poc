use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInteger, Field, PrimeField};

pub struct PoseidonTranscript<C: CurveGroup>
where
    <C as Group>::ScalarField: Absorb,
{
    sponge: PoseidonSponge<C::ScalarField>,
}

impl<C: CurveGroup> PoseidonTranscript<C>
where
    <C as Group>::ScalarField: Absorb,
{
    pub fn new(poseidon_config: &PoseidonConfig<C::ScalarField>) -> Self {
        let sponge = PoseidonSponge::<C::ScalarField>::new(poseidon_config);
        Self { sponge }
    }
    pub fn absorb(&mut self, v: &C::ScalarField) {
        self.sponge.absorb(&v);
    }
    pub fn absorb_point(&mut self, p: &C) {
        self.sponge.absorb(&prepare_point(p));
    }
    pub fn get_challenge(&mut self) -> C::ScalarField {
        let c = self.sponge.squeeze_field_elements(1);
        self.sponge.absorb(&c[0]);
        c[0]
    }
}

// Returns the point coordinates in Fr, so it can be absrobed by the transcript. It does not work
// over bytes in order to have a logic that can be reproduced in-circuit.
fn prepare_point<C: CurveGroup>(p: &C) -> Vec<C::ScalarField> {
    let binding = p.into_affine();
    let p_coords = &binding.xy().unwrap();
    let x_bi = p_coords
        .0
        .to_base_prime_field_elements()
        .next()
        .expect("a")
        .into_bigint();
    let y_bi = p_coords
        .1
        .to_base_prime_field_elements()
        .next()
        .expect("a")
        .into_bigint();
    vec![
        C::ScalarField::from_le_bytes_mod_order(x_bi.to_bytes_le().as_ref()),
        C::ScalarField::from_le_bytes_mod_order(y_bi.to_bytes_le().as_ref()),
    ]
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;

    /// WARNING the method poseidon_test_config is for tests only
    #[cfg(test)]
    pub fn poseidon_test_config<F: PrimeField>() -> PoseidonConfig<F> {
        let full_rounds = 8;
        let partial_rounds = 31;
        let alpha = 5;
        let rate = 2;

        let (ark, mds) = find_poseidon_ark_and_mds::<F>(
            F::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds,
            partial_rounds,
            0,
        );

        PoseidonConfig::new(
            full_rounds as usize,
            partial_rounds as usize,
            alpha,
            mds,
            ark,
            rate,
            1,
        )
    }
}
