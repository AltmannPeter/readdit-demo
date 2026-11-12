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
//! Google's ZK prover and verifier (`runtime_zk`: `ZkProver::commit`, `ZkProver::prove`,
//! `ZkVerifier::verify`), with the independent work of the Ligero commitment, the sumcheck and
//! the verifier's layer bindings run in parallel. Byte for byte Google's output at any thread
//! count.

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

const DEFECT: Error = Error::Internal("inconsistent");
const REFUSED: Error = Error::Proof("does not verify");

pub(crate) struct Committed<const W: usize, F: ZkField<W>> {
    pad: SumcheckProof<W, F>,
    lqc: Vec<LigeroQuadraticConstraint>,
    ligero: ligero::Committed<ElementOf<F>>,
    com: LigeroCommitment,
}


fn witness_count<F: SerializableField>(circuit: &Circuit<F>) -> Result<usize, Error> {
    circuit
        .raw
        .ninput
        .checked_sub(circuit.raw.npublic_input)
        .ok_or(DEFECT)
}

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
    .ok_or(Error::Internal("capacity"))?;
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

struct Binding<'c, const W: usize, F: ZkField<W>> {
    layer: &'c core_proto::circuit::Layer<F>,
    logv: usize,
    nv: usize,
    hc: [Vec<ElementOf<F>>; 2],
    alpha: ElementOf<F>,
    beta: ElementOf<F>,
    lchal: [Vec<ElementOf<F>>; 2],
}

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

fn pad_size<F: SerializableField>(circuit: &Circuit<F>) -> Result<usize, Error> {
    circuit.raw.layers.iter().try_fold(0usize, |n, l| {
        l.logw()
            .checked_mul(4)
            .and_then(|x| x.checked_add(3))
            .and_then(|x| n.checked_add(x))
            .ok_or(DEFECT)
    })
}

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
