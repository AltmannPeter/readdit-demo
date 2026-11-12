// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modified: independent work runs in parallel; every output is identical to the original.

//! Google's ZK prover and verifier (`runtime_zk` at 61a8a73: `ZkProver::commit`,
//! `ZkProver::prove`, `ZkVerifier::verify`) on the runtime's public types, with the Ligero
//! commitment, proof and verification of [`super::ligero`], the circuit's evaluation and the
//! sumcheck prover of [`super::sumcheck`], and the verifier's bound quads at once:
//! - **the prover** makes Google's sumcheck pads, commits the witness and the pads with
//!   [`super::ligero::commit`], then proves with [`super::sumcheck::eval_circuit`],
//!   [`super::sumcheck::prove_core`], Google's symbolic sumcheck verifier, and
//!   [`super::ligero::Committed::prove`];
//! - **the verifier** replays the sumcheck's transcript on a copy of its own for every layer's
//!   challenges, binds every layer's quad to them (independent layers: Google's `bind_quad`, a
//!   function of the layer and of challenges the proof alone fixes; every layer's eq table in
//!   one region, every run of every layer's terms bound in another, by [`super::sumcheck`]), and
//!   gives Google's symbolic sumcheck verifier those values (its `aux`, which the prover gives it
//!   too), so that it binds none itself; then [`super::ligero::verify`].
//!
//! Every output is Google's, byte for byte, at any thread count: the same random engine gives
//! the same commitment and proof, and the verifier the same verdict. Copied from Google's
//! `zk/src/prover.rs` (`commit`, `prove`, `new_pad`) and `zk/src/verifier.rs` and
//! `symbolic_sumcheck_verifier.rs` (`verify`, `bind_quad`), with every count Google asserts on
//! returned as an error, and Google's `ZkCommitResult`, whose fields are private, this module's
//! [`Committed`].

use core_algebra::{ElementOf, SerializableField};
use core_proto::circuit::Circuit;
use crate::Error;
use runtime_algebra::{InterpolatorFactory, Subfield, ZkField};
use runtime_ligero::{LigeroCommitment, LigeroConfig, LigeroParam, LigeroQuadraticConstraint};
use runtime_proto::{sumcheck::SumcheckProofGeometry, RoundPoly, ZkProof, ZkProofGeometry};
use runtime_random::{RandomEngine, Transcript};
use runtime_sumcheck::{LayerProof, SumcheckProof, SumcheckProofAux, TranscriptSumcheck};
use runtime_zk::common::{setup_lqc, ZkContext, DEFAULT_STATEMENT_HASH};
use runtime_zk::symbolic_sumcheck_verifier::symbolic_sumcheck_verifier_core;

use super::{ligero, sumcheck};

/// A build defect: a count Google's runtime asserts on.
const DEFECT: Error = Error::Internal("a count the runtime asserts on");
/// A proof the verifier refuses.
const REFUSED: Error = Error::Proof("does not verify");

/// What a commitment keeps for its proof (Google's `ZkCommitResult`): the sumcheck pads, the
/// Ligero quadratic constraints, the Ligero commitment's state, and the commitment.
pub(crate) struct Committed<const W: usize, F: ZkField<W>> {
    pad: SumcheckProof<W, F>,
    lqc: Vec<LigeroQuadraticConstraint>,
    ligero: ligero::Committed<ElementOf<F>>,
    com: LigeroCommitment,
}

/// The private inputs `circuit` commits: as many as its inputs past the public ones.
fn witness_count<F: SerializableField>(circuit: &Circuit<F>) -> Result<usize, Error> {
    circuit
        .raw
        .ninput
        .checked_sub(circuit.raw.npublic_input)
        .ok_or(DEFECT)
}

/// The geometry of a proof of `circuit` on `param`.
pub(crate) fn geometry<F: SerializableField>(
    circuit: &Circuit<F>,
    param: &LigeroParam,
) -> ZkProofGeometry {
    ZkProofGeometry {
        com_geom: param.geom,
        sc_geom: SumcheckProofGeometry {
            logw_layers: circuit.raw.layers.iter().map(|l| l.logw()).collect(),
        },
    }
}

/// Google's `new_pad`: per layer, for each round, each hand's two pad evaluations, then the two
/// claims' pads and their product; the pads are committed after the witness, in that order.
fn new_pad<const W: usize, F: ZkField<W>, R: RandomEngine>(
    circuit: &Circuit<F>,
    rng: &mut R,
    f: &F,
) -> (SumcheckProof<W, F>, Vec<ElementOf<F>>) {
    let mut layers = Vec::with_capacity(circuit.raw.layers.len());
    let mut witness = Vec::new();
    for clr in &circuit.raw.layers {
        let mut hp = [
            Vec::with_capacity(clr.logw()),
            Vec::with_capacity(clr.logw()),
        ];
        for _round in 0..clr.logw() {
            for slot in &mut hp {
                let r0 = rng.elt_field(f);
                let r2 = rng.elt_field(f);
                witness.push(r0.clone());
                witness.push(r2.clone());
                slot.push(RoundPoly {
                    evaluations: [r0, r2],
                });
            }
        }
        let r0 = rng.elt_field(f);
        let r1 = rng.elt_field(f);
        witness.push(r0.clone());
        witness.push(r1.clone());
        witness.push(f.mulf(&r0, &r1));
        layers.push(LayerProof {
            hp,
            claims: [r0, r1],
        });
    }
    (SumcheckProof { layers }, witness)
}

/// Google's `ZkProver::commit` of `circuit` with `config`: the sumcheck pads drawn, the
/// witness and the pads committed with Ligero (the private inputs below the circuit's subfield
/// boundary in the subfield), the root written to `ts`. Returns what the proof needs and the
/// proof's geometry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit<const W: usize, F, IF, R, SF>(
    circuit: &Circuit<F>,
    config: LigeroConfig,
    witness_only: &[ElementOf<F>],
    ctx: &ZkContext<'_, W, F, IF>,
    ts: &mut Transcript,
    rng: &mut R,
    sf: &SF,
) -> Result<(Committed<W, F>, ZkProofGeometry), Error>
where
    F: ZkField<W> + Sync,
    ElementOf<F>: Send + Sync,
    IF: InterpolatorFactory<W, F>,
    IF::Interpolator: Sync,
    R: RandomEngine,
    SF: Subfield<E = ElementOf<F>>,
{
    let n_witness = witness_count(circuit)?;
    if witness_only.len() != n_witness {
        return Err(DEFECT);
    }
    // The subfield boundary rebased to the private inputs.
    let subfield_boundary = circuit
        .raw
        .subfield_boundary
        .saturating_sub(circuit.raw.npublic_input);
    let (pad, pad_witness) = new_pad(circuit, rng, ctx.f);
    let mut witness = witness_only.to_vec();
    witness.extend(pad_witness);
    let lqc = setup_lqc(n_witness, circuit);
    let param = LigeroParam::try_new(
        witness.len(),
        circuit.raw.layers.len(),
        config,
        ctx.make_interpolator,
    )
    .ok_or(Error::Internal("Ligero parameters"))?;
    let (ligero, com) = ligero::commit(
        subfield_boundary,
        &witness,
        param,
        ts,
        &lqc,
        ctx.make_interpolator,
        rng,
        ctx.f,
        sf,
    )?;
    let geom = geometry(circuit, &param);
    Ok((
        Committed {
            pad,
            lqc,
            ligero,
            com,
        },
        geom,
    ))
}

/// Google's `ZkProver::prove` of `circuit` from its commitment `c` on `public` (the circuit's
/// public inputs) and `witness_only` (its private inputs, as committed): the sumcheck statement
/// written to `tsp`, the circuit evaluated and the sumcheck prover run on a fork of the
/// transcript ([`super::sumcheck`]), Google's symbolic sumcheck verifier on `tsp` for the linear
/// constraints, then the Ligero proof. A witness that does not satisfy the circuit is refused
/// ([`crate::Error::Unsatisfied`]).
pub(crate) fn prove<const W: usize, F, IF>(
    circuit: &Circuit<F>,
    c: Committed<W, F>,
    public: Vec<ElementOf<F>>,
    witness_only: Vec<ElementOf<F>>,
    tsp: &mut Transcript,
    ctx: &ZkContext<'_, W, F, IF>,
) -> Result<ZkProof<W, F>, Error>
where
    F: ZkField<W> + Sync,
    ElementOf<F>: Send + Sync,
    IF: InterpolatorFactory<W, F>,
    IF::Interpolator: Sync,
{
    let n_witness = witness_count(circuit)?;
    if public.len() != circuit.raw.npublic_input || witness_only.len() != n_witness {
        return Err(DEFECT);
    }
    let mut inputs = Vec::with_capacity(public.len() + n_witness);
    inputs.extend(public.iter().cloned());
    inputs.extend(witness_only);
    // The statement before the fork: the sumcheck prover runs on the fork, the symbolic
    // verifier on `tsp`, as Google's prover runs them.
    tsp.write_sumcheck_statement(circuit, &public, ctx.f);
    let mut ts_sumcheck = tsp.clone();
    let evaluated = sumcheck::eval_circuit(inputs, circuit, ctx.f)?;
    let (proof, aux) = sumcheck::prove_core(evaluated, &c.pad, circuit, &mut ts_sumcheck, ctx.f)?;
    let (a, b) = symbolic_sumcheck_verifier_core(
        n_witness,
        &public,
        circuit,
        &proof,
        Some(&aux),
        tsp,
        ctx.f,
    );
    let com_proof = c.ligero.prove(
        &b,
        tsp,
        &a,
        &DEFAULT_STATEMENT_HASH,
        &c.lqc,
        ctx.make_interpolator,
        ctx.f,
    )?;
    Ok(ZkProof {
        com: c.com,
        sumcheck_proof: proof,
        com_proof,
    })
}

/// One layer's binding inputs (Google's `bind_quad`'s): the layer, the previous layer's `logv`,
/// `nv` and challenges, the layer's `alpha` and `beta`, and its rounds' challenges.
struct Binding<'c, const W: usize, F: ZkField<W>> {
    layer: &'c core_proto::circuit::Layer<F>,
    logv: usize,
    nv: usize,
    hc: [Vec<ElementOf<F>>; 2],
    alpha: ElementOf<F>,
    beta: ElementOf<F>,
    lchal: [Vec<ElementOf<F>>; 2],
}

/// Every layer's bound quad, as Google's symbolic sumcheck verifier would bind it on `tv`'s
/// state (the sumcheck statement written): the transcript replayed on a copy, as the symbolic
/// verifier writes and draws (the circuit's challenges, then per layer alpha and beta, each
/// round's polynomial and challenge per hand, the layer's claims), then every layer's eq table in
/// one region ([`sumcheck::eq_tables`]) and every layer's runs of terms bound in another
/// ([`sumcheck::bind_quads`]). The proof's layer and round counts must be the circuit's, as
/// [`verify`] checks first.
fn bound_quads<const W: usize, F>(
    circuit: &Circuit<F>,
    proof: &SumcheckProof<W, F>,
    tv: &Transcript,
    f: &F,
) -> Result<SumcheckProofAux<W, F>, Error>
where
    F: ZkField<W> + Sync,
    ElementOf<F>: Send + Sync,
{
    let mut t = tv.clone();
    let (_copies, g) = t.begin_circuit(f);
    let mut logv = circuit.raw.logv;
    let mut nv = circuit.raw.noutput;
    let mut hc = [g.clone(), g];
    let mut jobs = Vec::with_capacity(circuit.raw.layers.len());
    for (layer, plr) in circuit.raw.layers.iter().zip(&proof.layers) {
        let (alpha, beta) = t.begin_layer(f);
        let mut lchal = [
            Vec::with_capacity(layer.logw()),
            Vec::with_capacity(layer.logw()),
        ];
        for round in 0..layer.logw() {
            for (hand, chal) in lchal.iter_mut().enumerate() {
                let hp = plr.hp.get(hand).and_then(|h| h.get(round)).ok_or(REFUSED)?;
                chal.push(t.round(hp, f));
            }
        }
        t.end_layer(&plr.claims, f);
        jobs.push(Binding {
            layer,
            logv,
            nv,
            hc: std::mem::replace(&mut hc, lchal.clone()),
            alpha,
            beta,
            lchal,
        });
        logv = layer.logw();
        nv = layer.nw();
    }
    let specs: Vec<sumcheck::EqSpec<'_, ElementOf<F>>> = jobs
        .iter()
        .map(|j| {
            let [g0, g1] = &j.hc;
            sumcheck::EqSpec {
                logv: j.logv,
                nv: j.nv,
                g0,
                g1,
                alpha: &j.alpha,
            }
        })
        .collect();
    let dots = sumcheck::eq_tables(&specs, f)?;
    let runs = jobs
        .iter()
        .map(|j| sumcheck::layer_runs::<W, F>(j.layer))
        .collect::<Result<Vec<_>, _>>()?;
    let quads: Vec<sumcheck::QuadJob<'_, F>> = jobs
        .iter()
        .zip(&dots)
        .zip(&runs)
        .map(|((j, dot), runs)| sumcheck::QuadJob {
            layer: j.layer,
            dot,
            beta: &j.beta,
            runs,
            lchal: &j.lchal,
        })
        .collect();
    Ok(SumcheckProofAux {
        bound_quad: sumcheck::bind_quads(&quads, &circuit.raw.constants, f)?,
    })
}

/// The pads a proof of `circuit` commits after the witness: per layer 4 · logw + 3 (Google's
/// `CircuitPad::pad_size`).
fn pad_size<F: SerializableField>(circuit: &Circuit<F>) -> Result<usize, Error> {
    circuit.raw.layers.iter().try_fold(0usize, |n, l| {
        l.logw()
            .checked_mul(4)
            .and_then(|x| x.checked_add(3))
            .and_then(|x| n.checked_add(x))
            .ok_or(DEFECT)
    })
}

/// Google's `ZkVerifier::verify` of `proof` of `circuit` with `config` against `public`, `tv`
/// past the commitment and the digest: the counts checked (the public inputs, the proof's
/// layers and each layer's rounds), the sumcheck statement written, every layer's quad bound
/// at once ([`bound_quads`]), Google's symbolic sumcheck verifier for the linear constraints,
/// then [`super::ligero::verify`], its rows read at the opened columns by `columns`.
pub(crate) fn verify<const W: usize, F, IF, C>(
    circuit: &Circuit<F>,
    config: LigeroConfig,
    public: Vec<ElementOf<F>>,
    proof: &ZkProof<W, F>,
    tv: &mut Transcript,
    ctx: &ZkContext<'_, W, F, IF>,
    columns: &C,
) -> Result<(), Error>
where
    F: ZkField<W> + Sync,
    ElementOf<F>: Send + Sync,
    IF: InterpolatorFactory<W, F>,
    C: ligero::Columns<W, F>,
{
    let n_witness = witness_count(circuit)?;
    if public.len() != circuit.raw.npublic_input
        || proof.sumcheck_proof.layers.len() != circuit.raw.layers.len()
    {
        return Err(REFUSED);
    }
    let rounds_hold = proof
        .sumcheck_proof
        .layers
        .iter()
        .zip(&circuit.raw.layers)
        .all(|(plr, clr)| plr.hp.iter().all(|h| h.len() == clr.logw()));
    if !rounds_hold {
        return Err(REFUSED);
    }
    tv.write_sumcheck_statement(circuit, &public, ctx.f);
    let aux = bound_quads(circuit, &proof.sumcheck_proof, tv, ctx.f)?;
    let (a, b) = symbolic_sumcheck_verifier_core(
        n_witness,
        &public,
        circuit,
        &proof.sumcheck_proof,
        Some(&aux),
        tv,
        ctx.f,
    );
    let param = LigeroParam::try_new(
        n_witness.checked_add(pad_size(circuit)?).ok_or(DEFECT)?,
        circuit.raw.layers.len(),
        config,
        ctx.make_interpolator,
    )
    .ok_or(DEFECT)?;
    let lqc = setup_lqc(n_witness, circuit);
    ligero::verify(
        &param,
        tv,
        &b,
        &proof.com,
        &proof.com_proof,
        &a,
        &DEFAULT_STATEMENT_HASH,
        &lqc,
        columns,
        ctx.f,
    )
}
