const schnorr = require('./schnorr-proof')
const curve = require('./curve')
const assert = require('nanoassert')

const rand = curve.randomScalar
const G1 = curve.G1
const G2 = curve.G2
const F = curve.F

module.exports = function (sig, pk, disclosure) {
  const attrs = sig._S.map(_ => null)
  for (const [k, v] of disclosure) attrs[v] = k

  const kNeg = disclosure.map(([k, _]) => F.neg(k))
  const disclosedS = disclosure.map(([_, i]) => sig._S[i])
  const S_C = sig._S.filter((_, i) => attrs[i] === null)

  const D = disclosedS.reduce(mulAddAcc(G1, kNeg), G1.neg(sig.K_))

  const prover = schnorr([sig.C_, sig.S_].concat(S_C))
  assert(prover.verify(D, sig.proof), 'commitment to D fails validation')

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
