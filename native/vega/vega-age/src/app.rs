//! What the application does around the prover (clauses 4.3, 4.4 and 5.6).
//!
//! 1. Setup builds the keys from blank circuits, once per credential format.
//! 2. The prover computes the witness ([`witness`]): every value of every circuit instance, from
//!    the credential and the presentation, as bellpepper's witness generator records them.
//! 3. The prover prepares once per credential. Preparing commits to the shared table and to the
//!    precommitted segments, which hold the rules that depend only on the credential.
//! 4. The prover proves once per presentation, reusing the prepared state.
//! 5. The verifier accepts a proof when it verifies, when step instance j reports position j,
//!    and when the core circuit reports the values the verifier named.
//!
//! The prover may prepare and prove from the circuits themselves, which synthesizes their values
//! inside the prover, or from a witness computed beforehand, through [`Replay`] circuits that
//! allocate the recorded values. No circuit asks the verifier for a challenge, so every value is
//! known before the prover commits to the first segment, and the two ways give the same
//! commitments to the same values. The second way times the witness apart from the proof.

use std::sync::Arc;

use bellpepper_core::{
  ConstraintSystem, Index, LinearCombination, SynthesisError, Variable, num::AllocatedNum,
};
use ff::Field;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use vega_prover::{
  bellpepper::{r1cs::VegaShape, shape_cs::ShapeCS, solver::SatisfyingAssignment},
  errors::VegaError,
  provider::{T256HyraxEngine, pt256::t256},
  traits::{circuit::VegaCircuit, snark::DigestHelperTrait},
  vega_mc_zkp::{VegaMcPrepZkSNARK, VegaMcProverKey, VegaMcVerifierKey, VegaMcZkSNARK},
};

use crate::step::Step;
use crate::table::{AGE, Layout, Table};

/// The holder's key: the shapes of both circuits and the commitment key. The prover's
/// serialization of it is the prover's own, since the newtype is transparent to serde.
///
/// The serialization leaves out what the key computes from its other fields: the shapes' sparse
/// matrices prepared for products, and the commitment key's fixed-base tables. Setup computes them
/// at once. A key read from its bytes computes them in its first proof, whose fields are private
/// at the pinned prover, so only a proof computes them.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProverKey(VegaMcProverKey<T256HyraxEngine>);

/// The verifier's key. As the prover's, its serialization leaves out its digest and the shapes'
/// prepared matrices. [`VerifierKey::ready`] computes the digest; the first verification computes
/// the matrices.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct VerifierKey(VegaMcVerifierKey<T256HyraxEngine>);

impl VerifierKey {
  /// Computes the key's digest, which every verification absorbs, and keeps it, so that a key
  /// read from its bytes does not compute it during the first verification. Returns it.
  pub fn ready(&self) -> Result<[u8; 32], VegaError> {
    DigestHelperTrait::digest(&self.0)
  }
}

/// The holder's commitments to the shared and precommitted segments of one credential, with the
/// values they commit to.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Prepared(VegaMcPrepZkSNARK<T256HyraxEngine>);

/// A proof, the one thing that travels to the verifier.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Proof(VegaMcZkSNARK<T256HyraxEngine>);

/// The prover's witness values are field elements of 256 bits, so they are not small. With
/// `true` the pinned prover would keep only the low 64 bits of each value.
const SMALL_VALUES: bool = false;

/// A core circuit, and what its format asks of the step instances.
pub trait Core: VegaCircuit<T256HyraxEngine> {
  /// Whether each step instance also scans its block for nbf and exp.
  const SCAN: bool;
  /// The table's layout: the age statement's, or the full statement's
  /// ([`crate::pseudonym`]).
  const LAYOUT: Layout = AGE;
}

/// Builds the keys for a core circuit. All step instances share one shape, so a blank step
/// stands for them.
pub fn setup<C: Core>(core: &C) -> Result<(ProverKey, VerifierKey), VegaError> {
  let step = Step::blank_in(C::LAYOUT, 0, C::SCAN);
  let (pk, vk) = VegaMcZkSNARK::setup(&step, core, C::LAYOUT.instances())?;
  Ok((ProverKey(pk), VerifierKey(vk)))
}

/// The budget of every circuit of the age statement: 2^15 rules, and 2^15 values once the
/// prover pads each of its three segments to a multiple of 2,048 (for the SD-JWT core, a
/// precommitted segment within the 22,528 values that 32,768 leaves beside its other two). Past it
/// the prover pads to 2^16, and the proof and its work double. A layout sets its own
/// ([`Layout::budget`]): the full statement's SD-JWT circuits fit in 2^16.
pub const BUDGET: usize = AGE.budget;

/// Refuses a circuit of `rules` rules and `values` padded values past `budget`.
fn within_budget(
  circuit: &str,
  rules: usize,
  values: usize,
  budget: usize,
) -> Result<(), VegaError> {
  if rules > budget || values > budget {
    let reason = format!("the {circuit} has {rules} rules and {values} values, past {budget}");
    return Err(VegaError::InternalError { reason });
  }
  Ok(())
}

/// The circuits as data: the shapes the prover builds from the blank step and core circuits (the
/// matrices A, B and C with their segment sizes), the step's then the core's, in the prover's
/// serialization (bincode), which is how its keys hold them. Refuses a circuit past the layout's
/// budget.
pub fn shapes<C: Core>(core: &C) -> Result<Vec<u8>, VegaError> {
  let step = Step::blank_in(C::LAYOUT, 0, C::SCAN);
  let step = <ShapeCS<T256HyraxEngine> as VegaShape<T256HyraxEngine>>::r1cs_shape(&step)?;
  let core = <ShapeCS<T256HyraxEngine> as VegaShape<T256HyraxEngine>>::r1cs_shape(core)?;
  for (circuit, shape) in [("step", &step), ("core", &core)] {
    let [_, _, _, _, rules, shared, precommitted, rest, _, _] = shape.sizes();
    within_budget(circuit, rules, shared + precommitted + rest, C::LAYOUT.budget)?;
  }
  bincode::serialize(&(step, core))
    .map_err(|e| VegaError::InternalError { reason: format!("serializing the shapes: {e}") })
}

/// Builds the keys from the circuits as data ([`shapes`]), without the circuits' code. The pinned
/// prover's setup takes circuits, so each stored shape is replayed as a circuit that allocates the
/// shape's variables and adds its rows, coefficient for coefficient, through which the prover
/// builds the same shape again, and the keys of [`setup`] byte for byte. Refuses a circuit past
/// [`BUDGET`].
pub fn setup_from_shapes(bytes: &[u8]) -> Result<(ProverKey, VerifierKey), VegaError> {
  setup_from_shapes_in(&AGE, bytes)
}

/// [`setup_from_shapes`] for the circuits of `layout`: its instances and its budget.
pub fn setup_from_shapes_in(
  layout: &Layout,
  bytes: &[u8],
) -> Result<(ProverKey, VerifierKey), VegaError> {
  let (step, core): (StoredShape, StoredShape) = bincode::deserialize(bytes)
    .map_err(|e| VegaError::InternalError { reason: format!("reading the shapes: {e}") })?;
  for (circuit, s) in [("step", &step), ("core", &core)] {
    let values = s.num_shared + s.num_precommitted + s.num_rest;
    within_budget(circuit, s.num_cons, values, layout.budget)?;
  }
  let (step, core) = (ShapeReplay(&step), ShapeReplay(&core));
  let (pk, vk) = VegaMcZkSNARK::setup(&step, &core, layout.instances())?;
  Ok((ProverKey(pk), VerifierKey(vk)))
}

/// One matrix of a shape in the prover's serialization: compressed sparse rows.
#[derive(Serialize, Deserialize)]
struct StoredMatrix {
  data: Vec<t256::Scalar>,
  indices: Vec<usize>,
  indptr: Vec<usize>,
  cols: usize,
}

/// A circuit's shape in the prover's serialization: its sizes, padded and not, then A, B and C,
/// whose columns are the padded segments' (shared, precommitted, rest), then the constant one and
/// the public values.
#[derive(Serialize, Deserialize)]
struct StoredShape {
  num_cons: usize,
  num_cons_unpadded: usize,
  num_shared_unpadded: usize,
  num_precommitted_unpadded: usize,
  num_rest_unpadded: usize,
  num_shared: usize,
  num_precommitted: usize,
  num_rest: usize,
  num_public: usize,
  num_challenges: usize,
  a: StoredMatrix,
  b: StoredMatrix,
  c: StoredMatrix,
}

impl StoredShape {
  /// The variable of a padded column: a segment's value, or an input (the constant one first).
  fn variable(&self, column: usize) -> Variable {
    let precommitted = self.num_shared;
    let rest = precommitted + self.num_precommitted;
    let inputs = rest + self.num_rest;
    let index = if column < precommitted {
      Index::Aux(column)
    } else if column < rest {
      Index::Aux(self.num_shared_unpadded + column - precommitted)
    } else if column < inputs {
      Index::Aux(self.num_shared_unpadded + self.num_precommitted_unpadded + column - rest)
    } else {
      Index::Input(column - inputs)
    };
    Variable::new_unchecked(index)
  }

  /// Row `r` of a matrix as a weighted sum.
  fn row(&self, m: &StoredMatrix, r: usize) -> LinearCombination<t256::Scalar> {
    (m.indptr[r]..m.indptr[r + 1])
      .fold(LinearCombination::zero(), |lc, i| lc + (m.data[i], self.variable(m.indices[i])))
  }
}

/// A stored shape as a circuit, for setup alone: it allocates the shape's variables in their
/// segments and adds its rows, and has no values.
#[derive(Clone, Copy)]
struct ShapeReplay<'a>(&'a StoredShape);

impl ShapeReplay<'_> {
  /// Allocates `count` values of the segment `segment`, each under its own name, as a constraint
  /// system that checks names asks.
  fn allocate<CS: ConstraintSystem<t256::Scalar>>(
    cs: &mut CS,
    segment: &str,
    count: usize,
  ) -> Result<(), SynthesisError> {
    if cs.is_witness_generator() {
      return Err(SynthesisError::AssignmentMissing);
    }
    for i in 0..count {
      cs.alloc(|| format!("{segment} {i}"), || Err(SynthesisError::AssignmentMissing))?;
    }
    Ok(())
  }
}

impl VegaCircuit<T256HyraxEngine> for ShapeReplay<'_> {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    Err(SynthesisError::AssignmentMissing)
  }

  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    Self::allocate(cs, "shared", self.0.num_shared_unpadded)?;
    Ok(Vec::new())
  }

  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    Self::allocate(cs, "precommitted", self.0.num_precommitted_unpadded)?;
    Ok(Vec::new())
  }

  fn num_challenges(&self) -> usize {
    self.0.num_challenges
  }

  fn synthesize<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<t256::Scalar>],
    _: &[AllocatedNum<t256::Scalar>],
    _: Option<&[t256::Scalar]>,
  ) -> Result<(), SynthesisError> {
    let s = self.0;
    Self::allocate(cs, "rest", s.num_rest_unpadded)?;
    for i in 0..s.num_challenges + s.num_public {
      cs.alloc_input(|| format!("input {i}"), || Err(SynthesisError::AssignmentMissing))?;
    }
    for r in 0..s.num_cons_unpadded {
      let (a, b, c) = (s.row(&s.a, r), s.row(&s.b, r), s.row(&s.c, r));
      cs.enforce(|| format!("row {r}"), |_| a, |_| b, |_| c);
    }
    Ok(())
  }
}

/// One step instance per position of the table's layout.
pub fn steps(table: &Arc<Table>) -> Vec<Step> {
  (0..table.layout.instances()).map(|position| Step::new(position, table.clone())).collect()
}

/// Commits to what depends only on the credential. The step instances are [`Step`]s, or the
/// [`Replay`]s of a witness.
pub fn prepare<S: VegaCircuit<T256HyraxEngine>, C: VegaCircuit<T256HyraxEngine>>(
  pk: &ProverKey,
  steps: &[S],
  core: &C,
) -> Result<Prepared, VegaError> {
  VegaMcZkSNARK::prep_prove(&pk.0, steps, core, SMALL_VALUES).map(Prepared)
}

/// Proves one presentation and returns the prepared state for the next one.
pub fn prove<S: VegaCircuit<T256HyraxEngine>, C: VegaCircuit<T256HyraxEngine>>(
  pk: &ProverKey,
  steps: &[S],
  core: &C,
  prepared: Prepared,
) -> Result<(Proof, Prepared), VegaError> {
  let (proof, prepared) = VegaMcZkSNARK::prove(&pk.0, steps, core, prepared.0, SMALL_VALUES)?;
  Ok((Proof(proof), Prepared(prepared)))
}

/// Why the verifier rejects a proof.
#[derive(Debug)]
pub enum Rejection {
  /// The proof does not verify.
  Invalid(VegaError),
  /// A step instance reports another position than its own.
  Position { instance: usize, reported: Vec<t256::Scalar> },
  /// The core circuit reports other public values than the verifier named.
  PublicValues { reported: Vec<t256::Scalar> },
}

/// Accepts a proof for the public values the verifier named, in the order of
/// [`crate::presentation::Public::values`].
pub fn accept(vk: &VerifierKey, proof: &Proof, expected: &[t256::Scalar]) -> Result<(), Rejection> {
  let core = verified(&AGE, vk, proof)?;
  if core != expected {
    return Err(Rejection::PublicValues { reported: core });
  }
  Ok(())
}

/// Verifies a proof of `layout`'s circuits and its step instances' positions, and returns the
/// public values its core reports.
fn verified(
  layout: &Layout,
  vk: &VerifierKey,
  proof: &Proof,
) -> Result<Vec<t256::Scalar>, Rejection> {
  let (steps, core) = proof.0.verify(&vk.0, layout.instances()).map_err(Rejection::Invalid)?;
  for (instance, reported) in steps.into_iter().enumerate() {
    if reported != [t256::Scalar::from(instance as u64)] {
      return Err(Rejection::Position { instance, reported });
    }
  }
  Ok(core)
}

/// Accepts a proof of the full statement ([`crate::pseudonym`]) for the public values the
/// verifier named, in the order of [`crate::presentation::Public::values`] followed by
/// verifier_input's three ([`crate::pseudonym::NymPublic::verifier_values`]), and returns the
/// pseudonym the proof reveals: the core's last two public values, the one thing it reports
/// beyond the verifier's.
pub fn accept_pseudonym(
  layout: &Layout,
  vk: &VerifierKey,
  proof: &Proof,
  expected: &[t256::Scalar],
) -> Result<[u8; 32], Rejection> {
  let core = verified(layout, vk, proof)?;
  let pseudonym = (core.len() == expected.len() + 2 && core[..expected.len()] == *expected)
    .then(|| crate::pseudonym::pseudonym_of(&core))
    .flatten();
  pseudonym.ok_or(Rejection::PublicValues { reported: core })
}

/// Builds all rules of one circuit instance with their values, in the order the prover does, and
/// returns the first rule the values break, if any, by its path: the namespaces and the rule's
/// name joined by `/`, as bellpepper's `TestConstraintSystem` names it. Unlike that system it keeps
/// no rule and no name, and its first allocation after a broken rule fails, which ends the
/// synthesis there. Tests use it to find the rule that stops a dishonest witness. An error is the
/// synthesis's own, before any rule broke.
pub fn first_broken<C: VegaCircuit<T256HyraxEngine>>(
  circuit: &C,
) -> Result<Option<String>, SynthesisError> {
  let mut cs =
    Check { aux: Vec::new(), inputs: vec![t256::Scalar::ONE], path: Vec::new(), broken: None };
  let synthesis = (|| {
    let shared = circuit.shared(&mut cs.namespace(|| "shared"))?;
    let precommitted = circuit.precommitted(&mut cs.namespace(|| "precommitted"), &shared)?;
    circuit.synthesize(&mut cs.namespace(|| "rest"), &shared, &precommitted, Some(&[]))
  })();
  match cs.broken {
    Some(path) => Ok(Some(path)),
    None => synthesis.map(|()| None),
  }
}

/// The constraint system of [`first_broken`]: the values, the open namespaces, and the path of
/// the first broken rule.
struct Check {
  aux: Vec<t256::Scalar>,
  inputs: Vec<t256::Scalar>,
  path: Vec<String>,
  broken: Option<String>,
}

impl Check {
  fn value(&self, lc: &LinearCombination<t256::Scalar>) -> t256::Scalar {
    lc.iter().fold(t256::Scalar::ZERO, |sum, (variable, coefficient)| {
      let value = match variable.get_unchecked() {
        Index::Input(i) => self.inputs[i],
        Index::Aux(i) => self.aux[i],
      };
      sum + *coefficient * value
    })
  }
}

impl ConstraintSystem<t256::Scalar> for Check {
  type Root = Self;

  fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
  where
    F: FnOnce() -> Result<t256::Scalar, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    if self.broken.is_some() {
      return Err(SynthesisError::Unsatisfiable);
    }
    self.aux.push(f()?);
    Ok(Variable::new_unchecked(Index::Aux(self.aux.len() - 1)))
  }

  fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
  where
    F: FnOnce() -> Result<t256::Scalar, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    if self.broken.is_some() {
      return Err(SynthesisError::Unsatisfiable);
    }
    self.inputs.push(f()?);
    Ok(Variable::new_unchecked(Index::Input(self.inputs.len() - 1)))
  }

  fn enforce<A, AR, LA, LB, LC>(&mut self, name: A, a: LA, b: LB, c: LC)
  where
    A: FnOnce() -> AR,
    AR: Into<String>,
    LA: FnOnce(LinearCombination<t256::Scalar>) -> LinearCombination<t256::Scalar>,
    LB: FnOnce(LinearCombination<t256::Scalar>) -> LinearCombination<t256::Scalar>,
    LC: FnOnce(LinearCombination<t256::Scalar>) -> LinearCombination<t256::Scalar>,
  {
    let (a, b, c) =
      (a(LinearCombination::zero()), b(LinearCombination::zero()), c(LinearCombination::zero()));
    if self.broken.is_none() && self.value(&a) * self.value(&b) != self.value(&c) {
      let name = name().into();
      self.broken = Some(self.path.iter().chain([&name]).cloned().collect::<Vec<_>>().join("/"));
    }
  }

  fn push_namespace<NR, N>(&mut self, name: N)
  where
    NR: Into<String>,
    N: FnOnce() -> NR,
  {
    self.path.push(name().into());
  }

  fn pop_namespace(&mut self) {
    self.path.pop();
  }

  fn get_root(&mut self) -> &mut Self::Root {
    self
  }
}

/// The values one segment of one circuit instance allocates, in the order of allocation: its
/// private values, and the public values it allocates among them. The prover's witness generator
/// keeps the two kinds in two lists, so their interleaving does not matter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Segment {
  pub private: Vec<t256::Scalar>,
  pub public: Vec<t256::Scalar>,
}

impl Segment {
  /// The values `cs` allocated after it held `private` private and `public` public values. The
  /// witness generator's first public value is the constant one, which no segment allocates.
  fn since(cs: &SatisfyingAssignment<T256HyraxEngine>, (private, public): (usize, usize)) -> Self {
    Segment {
      private: cs.aux_slice()[private..].to_vec(),
      public: cs.inputs_slice()[public..].to_vec(),
    }
  }

  /// How many values `cs` holds, for [`Segment::since`].
  fn mark(cs: &SatisfyingAssignment<T256HyraxEngine>) -> (usize, usize) {
    (cs.aux_slice().len(), cs.inputs_slice().len())
  }

  /// Allocates the recorded values in a witness generator, as the circuit allocated them. A
  /// replay has values and no rules, so it refuses any other constraint system: setup builds the
  /// shape from the circuits themselves.
  fn replay<CS: ConstraintSystem<t256::Scalar>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
    if !cs.is_witness_generator() {
      return Err(SynthesisError::AssignmentMissing);
    }
    cs.extend_inputs(&self.public);
    cs.extend_aux(&self.private);
    Ok(())
  }
}

/// The values of one circuit instance besides the shared segment: its precommitted segment, its
/// rest segment, and the public values it reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Instance {
  pub precommitted: Segment,
  pub rest: Segment,
  pub public_values: Vec<t256::Scalar>,
}

/// Every value of one proof: the shared segment, which every instance shares, and the values of
/// each step instance and of the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
  pub shared: Segment,
  pub steps: Vec<Instance>,
  pub core: Instance,
}

impl Assignment {
  /// The step instances that replay the steps' values.
  pub fn steps(&self) -> Vec<Replay<'_>> {
    self.steps.iter().map(|instance| Replay { shared: &self.shared, instance }).collect()
  }

  /// The core instance that replays the core's values.
  pub fn core(&self) -> Replay<'_> {
    Replay { shared: &self.shared, instance: &self.core }
  }

  /// The number of values in each segment kind, summed over the instances: shared, precommitted,
  /// rest, and the public values the segments allocate.
  pub fn counts(&self) -> [usize; 4] {
    let instances = self.steps.iter().chain([&self.core]);
    instances.fold(
      [self.shared.private.len(), 0, 0, self.shared.public.len()],
      |[s, p, r, x], i| {
        let public = i.precommitted.public.len() + i.rest.public.len();
        [s, p + i.precommitted.private.len(), r + i.rest.private.len(), x + public]
      },
    )
  }
}

/// Synthesizes one instance's precommitted and rest segments over the shared values, as the
/// prover does: the precommitted segment when it prepares, the rest when it proves. No circuit
/// takes a challenge, so the rest receives none.
fn instance<C: VegaCircuit<T256HyraxEngine>>(
  circuit: &C,
  shared: &[AllocatedNum<t256::Scalar>],
) -> Result<Instance, SynthesisError> {
  let mut cs = SatisfyingAssignment::<T256HyraxEngine>::new();
  let start = Segment::mark(&cs);
  let precommitted_values = circuit.precommitted(&mut cs, shared)?;
  let precommitted = Segment::since(&cs, start);
  let mark = Segment::mark(&cs);
  circuit.synthesize(&mut cs, shared, &precommitted_values, Some(&[]))?;
  let rest = Segment::since(&cs, mark);
  Ok(Instance { precommitted, rest, public_values: circuit.public_values()? })
}

/// The witness: every value of every circuit instance, as the prover's own witness generator,
/// bellpepper's `SatisfyingAssignment`, records them when it synthesizes the circuits. The shared
/// segment is the first step's, which the prover gives every instance, the core included. The
/// step instances' values are computed natively ([`Step::assignment`]), in parallel, and the core
/// synthesizes beside them, its costly gadgets computing their values natively too
/// ([`crate::gadgets::values`]).
pub fn witness<C: VegaCircuit<T256HyraxEngine>>(
  steps: &[Step],
  core: &C,
) -> Result<Assignment, SynthesisError> {
  let first = steps.first().ok_or(SynthesisError::AssignmentMissing)?;
  let mut cs = SatisfyingAssignment::<T256HyraxEngine>::new();
  let start = Segment::mark(&cs);
  let shared_values = first.shared(&mut cs)?;
  let shared = Segment::since(&cs, start);
  let (steps, core) = rayon::join(
    || steps.par_iter().map(Step::assignment).collect::<Result<Vec<_>, _>>(),
    || instance(core, &shared_values),
  );
  Ok(Assignment { shared, steps: steps?, core: core? })
}

/// The witness of a prover whose prepared state already holds the shared and precommitted
/// segments: the core's rest segment, which the presentation fixes. It needs the facts that the
/// core's precommitted segment computes, so the core synthesizes both. The steps have no rest
/// segment, and carry only the positions they report. Preparing from this witness fails.
pub fn presentation_witness<S: VegaCircuit<T256HyraxEngine>, C: VegaCircuit<T256HyraxEngine>>(
  steps: &[S],
  core: &C,
) -> Result<Assignment, SynthesisError> {
  let mut cs = SatisfyingAssignment::<T256HyraxEngine>::new();
  let start = Segment::mark(&cs);
  let shared_values = core.shared(&mut cs)?;
  let shared = Segment::since(&cs, start);
  let core = instance(core, &shared_values)?;
  let steps = steps
    .iter()
    .map(|step| Ok(Instance { public_values: step.public_values()?, ..Instance::default() }))
    .collect::<Result<_, SynthesisError>>()?;
  Ok(Assignment { shared, steps, core })
}

/// A circuit instance that allocates the recorded values of a witness and adds no rule. The
/// prover's witness generator ignores rules anyway, and the prover takes the rules from the key,
/// so preparing and proving from a replay commit to the same values as from the circuit. A replay
/// returns no slots to pass from one segment to the next, so a state prepared from replays proves
/// only through replays.
#[derive(Clone, Copy, Debug)]
pub struct Replay<'a> {
  shared: &'a Segment,
  instance: &'a Instance,
}

impl VegaCircuit<T256HyraxEngine> for Replay<'_> {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    Ok(self.instance.public_values.clone())
  }

  /// The prover passes the returned values back to the other two segments, which a replay does
  /// not read.
  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    self.shared.replay(cs)?;
    Ok(Vec::new())
  }

  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    self.instance.precommitted.replay(cs)?;
    Ok(Vec::new())
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<t256::Scalar>],
    _: &[AllocatedNum<t256::Scalar>],
    _: Option<&[t256::Scalar]>,
  ) -> Result<(), SynthesisError> {
    self.instance.rest.replay(cs)
  }
}
