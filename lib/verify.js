const curve = require('./curve')
const assert = require('nanoassert')
const schnorr = require('./schnorr-proof')

const rand = curve.Fr.random
const { G1, G2, F, F12 } = curve
const ZERO = curve.PointG1.ZERO

module.exports = {
  verifyWitness,
  verifyCredential
}

function verifyWitness (proof, pk, challenge, rev, id) {
  const [g0, g1, g2, g3, g4] = pk.basepoints

  const { U, C, C1, C2, proofs, blinds } = proof

  if (U[3].equals(ZERO)) return false

  const generatorsF12 = [
    pk.e.gg,
    pk.e.g1a,
    pk.e.g1g2,
    curve.pairing(U[1].negate(), pk.g2)
  ]

  const pairingU2 = curve.pairing(U[1], pk.a).div(pk.e.vg)

  // generators and expected value for each proof
  const args = [
    [[g0, g1], U[0]],
    [[pk.u], C1],
    [[pk.v], C2],
    [[U[0].negate(), g0, g1], ZERO],
    [[g2, g3], U[2]],
    [[U[2], g2, g3], ZERO],
    [[g4], U[3]],
    [[g0, g1], C],
    [generatorsF12, pairingU2]
  ]

  proofs.forEach(proof => { proof.blinds = proof.indices.map(i => blinds[i]) })

  const check = proofs.reduce((valid, proof, i) => 
    valid && schnorr.verify(...args[i], proof, challenge), true)

  return check
}

function verifyCredential (sig, pk, disclosure, challenge) {
  const attrs = sig._S.map(_ => null)
  for (const [index, encodedAttr] of disclosure) attrs[index] = encodedAttr

  const kNeg = disclosure.map(([_, a]) => a.negate())
  const disclosedS = disclosure.map(([i, _]) => sig._S[i])
  const S_C = sig._S.filter((_, i) => attrs[i] === null)

  const D = disclosedS.reduce(mulAddAcc(G1, kNeg), sig.K_.negate())

  const generators = [sig.C_, sig.S_].concat(S_C)
  assert(schnorr.verify(generators, D, sig.proof, challenge),
    'commitment to D fails validation')

  const r = rand()
  const _r = sig._S.map(rand)

  const sProduct = sig._S.reduce(mulAddAcc(G1, _r), sig.S_.multiply(r))
  const aProduct = pk._A.reduce(mulAddAcc(G2, _r), pk.A.multiply(r))

  var SQ = [sProduct, pk.Q]
  var KA = [sig.K_, aProduct]

  var TQ = [sig.T_, pk.Q]
  var CZ = [sig.C_, pk.Z]

  return curve.verifyPairEq(SQ, KA) && curve.verifyPairEq(CZ, TQ)
}

function mulAddAcc (G, scalars) {
  return (acc, el, i) => acc.add(el.multiply(scalars[i]))
}
