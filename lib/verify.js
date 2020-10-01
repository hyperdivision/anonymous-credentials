const curve = require('./curve')
const assert = require('nanoassert')
const schnorr = require('./schnorr-proof')

const rand = curve.randomScalar
const { G1, G2, F, F12 } = curve

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
    pk.e.g1a,
    pk.e.g1g2,
    curve.pairing(G1.neg(U[1]), pk.g2)
  ]

  const pairingU2 = F12.div(curve.pairing(U[1], pk.a), pk.e.vg)

  // generators and expected value for each proof
  const args = [
    [[g0, g1], U[0]],
    [[pk.u], C1],
    [[pk.v], C2],
    [[G1.neg(U[0]), g0, g1], G1.zero],
    [[g2, g3], U[2]],
    [[U[2], g2, g3], G1.zero],
    [[g4], U[3]],
    [[g0, g1], C],
    [generatorsF12, pairingU2]
  ]

  const _blinds = proofs.map(proof => proof.indices.map(i => blinds[i]))

  const check = proofs.slice(0, 8).reduce((valid, proof, i) => 
    valid && schnorr.verify(...args[i], proof, _blinds[i], challenge), true)

  return check && schnorr.verify(...args[8], proofs[8], _blinds[8], challenge, 'F12')
}

function verifyCredential (sig, pk, disclosure, challenge) {
  const attrs = sig._S.map(_ => null)
  for (const [index, encodedAttr] of disclosure) attrs[index] = encodedAttr

  const kNeg = disclosure.map(([_, a]) => F.neg(a))
  const disclosedS = disclosure.map(([i, _]) => sig._S[i])
  const S_C = sig._S.filter((_, i) => attrs[i] === null)

  const D = disclosedS.reduce(mulAddAcc(G1, kNeg), G1.neg(sig.K_))

  const generators = [sig.C_, sig.S_].concat(S_C)
  assert(schnorr.verify(generators, D, sig.proof, sig.proof.blinds, challenge),
    'commitment to D fails validation')

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
