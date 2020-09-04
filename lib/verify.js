const schnorr = require('./schnorr-proof')
const curve = require('./curve')
const assert = require('nanoassert')
const hash = require('../experiment/challenge')

const rand = curve.randomScalar
const { G1, G2, F, F12 } = curve

const optsG1 = {
  add: (a, b) => G1.add(a, b),
  mul: (a, b) => G1.mulScalar(a, b),
  eq: (a, b) => G1.eq(a, b)
}

const optsF12 = {
  add: (a, b) => F12.mul(a, b),
  mul: (a, b) => F12.exp(a, b),
  eq: (a, b) => F12.eq(a, b)
}

module.exports = {
  verifyWitness,
  verifyCredential
}

function verifyWitness (proof, pk, challenge, rev, id) {
  const [g0, g1, g2, g3, g4] = pk.basepoints

  const { U, C, C1, C2, proofs, blinds } = proof

  if (G1.eq(U[3], G1.zero)) return false

  const generatorsF12 = [
    pk.e.gg,
    curve.pairing(g1, pk.a),
    curve.pairing(g1, pk.g2),
    F12.inv(curve.pairing(U[1], pk.g2))
  ]

  let valid = true
  valid &= verify([g0, g1], U[0], proofs[0])
  valid &= verify([pk.u], C1, proofs[1])
  valid &= verify([pk.v], C2, proofs[2])
  valid &= verify([G1.neg(U[0]), g0, g1], G1.zero, proofs[3])
  valid &= verify([g2, g3], U[2], proofs[4])
  valid &= verify([U[2], g2, g3], G1.zero, proofs[5])
  valid &= verify([g4], U[3], proofs[6])
  valid &= verify([g0, g1], C, proofs[7])

  const pairingU2 = F12.div(curve.pairing(U[1], pk.a), pk.e.vg)
  valid &= verify(generatorsF12, pairingU2, proofs[8], optsF12)

  return valid === 1

  function verify (generators, P, proof, { add, mul, eq } = optsG1) {
    const _blinds = proof.indices.map(i => blinds[i])

    const products = generators.map((g, i) => mul(g, _blinds[i]))
    var lhs = products.reduce((acc, el) => add(acc, el))

    var tP = mul(P, challenge)
    var rhs = add(proof.P_, tP)

    return eq(lhs, rhs)
  }
}

function verifyCredential (sig, pk, disclosure, challenge) {
  const attrs = sig._S.map(_ => null)
  for (const [index, encodedAttr] of disclosure) attrs[index] = encodedAttr

  const kNeg = disclosure.map(([_, a]) => F.neg(a))
  const disclosedS = disclosure.map(([i, _]) => sig._S[i])
  const S_C = sig._S.filter((_, i) => attrs[i] === null)

  const D = disclosedS.reduce(mulAddAcc(G1, kNeg), G1.neg(sig.K_))

  const prover = schnorr.prover([sig.C_, sig.S_].concat(S_C))
  assert(prover.verify(D, sig.proof, challenge), 'commitment to D fails validation')

  const r = rand()
  const _r = sig._S.map(rand)

  const sProduct = sig._S.reduce(mulAddAcc(G1, _r), G1.mulScalar(sig.S_, r))
  const aProduct = pk._A.reduce(mulAddAcc(G2, _r), G2.mulScalar(pk.A, r))

  var SQ = [sProduct, pk.Q]
  var KA = [sig.K_, aProduct]

  var TQ = [sig.T_, pk.Q]
  var CZ = [sig.C_, pk.Z]

  return curve.verifyPairEq(SQ, KA) && curve.verifyPairEq(CZ, TQ)
}

function mulAddAcc (G, scalars) {
  return (acc, el, i) => G.add(acc, G.mulScalar(el, scalars[i]))
}
