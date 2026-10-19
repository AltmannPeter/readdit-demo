//! Spec 4.2.1 fixture machinery and BBS-12 Section 8.1 deterministic sources.

use crate::params::{Ciphersuite, EXPAND_LEN};
use crate::primitives::{expand_message, scalar_from_wide};
use crate::types::{ScalarInput, ScalarSource};
use crate::{BbsError, BbsResult};

/// Spec 4.2.1 fixture machinery: replace one scalar after expanding a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarOverride {
    pub call: u64,
    pub index: usize,
    pub value: ScalarInput,
}

/// Spec 4.2.1 fixture machinery: the advancing stream in fixtures/README.md.
///
/// Each call consumes its counter, including an empty request or a failed
/// expansion. Successful draws, including empty draws, are retained in `calls`.
/// Overrides apply after expansion; malformed fixture machinery causes ABORT,
/// rather than silently converting a malformed fixture into a protocol INVALID.
/// Unreached future overrides are allowed because a procedure can reject inputs
/// before it requests the corresponding draw.
pub struct ProfileRng {
    suite: Ciphersuite,
    seed: Vec<u8>,
    dst: Vec<u8>,
    overrides: Vec<ScalarOverride>,
    call: u64,
    pub calls: Vec<Vec<ScalarInput>>,
}

impl ProfileRng {
    /// Spec 4.2.1 fixture machinery: begin a fresh fixture at counter zero.
    pub fn new(
        suite: Ciphersuite,
        seed: Vec<u8>,
        dst: Vec<u8>,
        overrides: Vec<ScalarOverride>,
    ) -> Self {
        Self {
            suite,
            seed,
            dst,
            overrides,
            call: 0,
            calls: Vec::new(),
        }
    }

    /// Spec 4.2.1 fixture machinery: number of consumed invocation labels.
    pub fn call_count(&self) -> u64 {
        self.call
    }
}

impl ScalarSource for ProfileRng {
    /// Spec 4.2.1 fixture machinery: expand SEED || I2OSP(k, 8), then reduce.
    fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>> {
        self.call = self
            .call
            .checked_add(1)
            .ok_or(BbsError::Abort("profile RNG call counter overflow"))?;
        let mut scalars = if count == 0 {
            Vec::new()
        } else {
            let out_len = count
                .checked_mul(EXPAND_LEN)
                .ok_or(BbsError::Abort("profile RNG output length overflow"))?;
            let msg = [self.seed.as_slice(), &self.call.to_be_bytes()].concat();
            let out = expand_message(self.suite, &msg, &self.dst, out_len)?;
            out.chunks_exact(EXPAND_LEN)
                .map(|chunk| {
                    let bytes: &[u8; EXPAND_LEN] = chunk
                        .try_into()
                        .map_err(|_| BbsError::Abort("unexpected profile expansion length"))?;
                    Ok(scalar_from_wide(bytes).into())
                })
                .collect::<BbsResult<Vec<_>>>()?
        };
        let mut overridden = Vec::new();
        for entry in &self.overrides {
            if entry.call == 0 {
                return Err(BbsError::Abort("profile RNG override call must be nonzero"));
            }
            if entry.call != self.call {
                continue;
            }
            if overridden.contains(&entry.index) {
                return Err(BbsError::Abort("duplicate profile RNG override"));
            }
            entry
                .value
                .to_scalar()
                .map_err(|_| BbsError::Abort("profile RNG override scalar out of range"))?;
            let scalar = scalars
                .get_mut(entry.index)
                .ok_or(BbsError::Abort("profile RNG override index out of bounds"))?;
            *scalar = entry.value;
            overridden.push(entry.index);
        }
        self.calls.push(scalars.clone());
        Ok(scalars)
    }
}

/// BBS-12 8.1 seeded_random_scalars. Restart the exact draft stream per call.
///
/// This function serves only the BBS cross-check. It must not be reused as
/// the profile's advancing randomness source. Expansion limits still apply
/// after the draft's explicit 65535-octet output-length check.
/// SI-007 records the contradictory prose; Peter approved following the
/// explicit ABORT pseudocode on 2026-10-15.
pub fn seeded_random_scalars(
    suite: Ciphersuite,
    seed: &[u8],
    dst: &[u8],
    count: usize,
) -> BbsResult<Vec<ScalarInput>> {
    let out_len = EXPAND_LEN
        .checked_mul(count)
        .filter(|length| *length <= 65535)
        .ok_or(BbsError::Abort(
            "seeded_random_scalars output exceeds 65535 octets",
        ))?;
    let v = expand_message(suite, seed, dst, out_len)?;
    let mut mocked_random_scalars = Vec::new();
    for i in 1..=count {
        let start_idx = (i - 1) * EXPAND_LEN;
        let end_idx = i * EXPAND_LEN;
        let bytes: &[u8; EXPAND_LEN] = v[start_idx..end_idx]
            .try_into()
            .map_err(|_| BbsError::Abort("unexpected seeded expansion length"))?;
        mocked_random_scalars.push(scalar_from_wide(bytes).into());
    }
    Ok(mocked_random_scalars)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec 4.2.1 fixture machinery: each call uses its own invocation label.
    #[test]
    fn profile_stream_advances_and_records_empty_calls() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let mut rng = ProfileRng::new(suite, b"seed".to_vec(), b"dst".to_vec(), vec![]);
            for (call, count) in [(1u64, 2), (2, 0), (3, 2), (4, 1)] {
                let result = rng.calculate_random_scalars(count).unwrap();
                let expected = if count == 0 {
                    vec![]
                } else {
                    let label = [b"seed".as_slice(), &call.to_be_bytes()].concat();
                    seeded_random_scalars(suite, &label, b"dst", count).unwrap()
                };
                assert_eq!(result, expected);
                assert_eq!(rng.call_count(), call);
                assert_eq!(rng.calls.last(), Some(&result));
            }
            assert_ne!(rng.calls[0], rng.calls[2]);
            assert!(rng.calls[1].is_empty());
            assert_eq!(rng.calls.len(), 4);
        }
    }

    /// Spec 4.2.1 fixture machinery: overrides replace values without rewinding.
    #[test]
    fn profile_overrides_do_not_rewind() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let mut plain = ProfileRng::new(suite, b"seed".to_vec(), b"dst".to_vec(), vec![]);
            let mut injected = ProfileRng::new(
                suite,
                b"seed".to_vec(),
                b"dst".to_vec(),
                vec![ScalarOverride {
                    call: 1,
                    index: 1,
                    value: 0u64.into(),
                }],
            );
            let mut expected = plain.calculate_random_scalars(3).unwrap();
            expected[1] = 0u64.into();
            assert_eq!(injected.calculate_random_scalars(3).unwrap(), expected);
            assert_eq!(injected.calls, vec![expected]);
            assert_eq!(
                injected.calculate_random_scalars(3).unwrap(),
                plain.calculate_random_scalars(3).unwrap()
            );
        }
    }

    /// Spec 4.2.1 fixture machinery: malformed overrides cause explicit ABORT.
    #[test]
    fn malformed_profile_overrides_abort() {
        let valid = ScalarOverride {
            call: 1,
            index: 0,
            value: 0u64.into(),
        };
        for overrides in [
            vec![ScalarOverride {
                call: 0,
                ..valid.clone()
            }],
            vec![ScalarOverride {
                index: 1,
                ..valid.clone()
            }],
            vec![ScalarOverride {
                value: ScalarInput(crate::params::R),
                ..valid.clone()
            }],
            vec![valid.clone(), valid.clone()],
        ] {
            let mut rng = ProfileRng::new(Ciphersuite::Sha256, vec![], vec![], overrides);
            assert!(matches!(
                rng.calculate_random_scalars(1),
                Err(BbsError::Abort(_))
            ));
            assert_eq!(rng.call_count(), 1);
            assert!(rng.calls.is_empty());
        }
        let mut empty_override = ProfileRng::new(Ciphersuite::Sha256, vec![], vec![], vec![valid]);
        assert_eq!(
            empty_override.calculate_random_scalars(0),
            Err(BbsError::Abort("profile RNG override index out of bounds"))
        );
    }

    /// Spec 4.2.1 fixture machinery: preserve expander and counter limits.
    #[test]
    fn profile_bounds_and_counter_overflow() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let mut rng = ProfileRng::new(suite, vec![], vec![], vec![]);
            assert!(matches!(
                rng.calculate_random_scalars(usize::MAX),
                Err(BbsError::Abort(_))
            ));
            assert!(matches!(
                rng.calculate_random_scalars(1366),
                Err(BbsError::Abort(_))
            ));
            assert_eq!(rng.call_count(), 2);
            assert!(rng.calls.is_empty());
            rng.call = u64::MAX;
            assert_eq!(
                rng.calculate_random_scalars(0),
                Err(BbsError::Abort("profile RNG call counter overflow"))
            );
            assert_eq!(rng.call_count(), u64::MAX);
            assert!(rng.calls.is_empty());
        }
        let mut sha = ProfileRng::new(Ciphersuite::Sha256, vec![], vec![], vec![]);
        assert!(sha.calculate_random_scalars(170).is_ok());
        assert_eq!(
            sha.calculate_random_scalars(171),
            Err(BbsError::Abort("expand_message_xmd ell exceeds 255"))
        );
        let mut shake = ProfileRng::new(Ciphersuite::Shake256, vec![], vec![], vec![]);
        assert!(shake.calculate_random_scalars(1365).is_ok());
    }

    /// BBS-12 8.1. This source restarts and propagates expander length limits.
    #[test]
    fn restarting_stream_and_bounds() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let a = seeded_random_scalars(suite, b"test seed", b"test dst", 2).unwrap();
            let b = seeded_random_scalars(suite, b"test seed", b"test dst", 2).unwrap();
            assert_eq!(a, b);
            assert!(
                seeded_random_scalars(suite, b"", b"", 0)
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                seeded_random_scalars(suite, b"", b"", 1366),
                Err(BbsError::Abort(_))
            ));
            assert!(matches!(
                seeded_random_scalars(suite, b"", b"", usize::MAX),
                Err(BbsError::Abort(_))
            ));
        }
        assert!(seeded_random_scalars(Ciphersuite::Sha256, b"", b"", 170).is_ok());
        assert!(matches!(
            seeded_random_scalars(Ciphersuite::Sha256, b"", b"", 171),
            Err(BbsError::Abort(_))
        ));
    }
}
