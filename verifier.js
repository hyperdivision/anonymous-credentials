const schnorr = require('./schnorr-proof')
const curve = require('./curve')
const assert = require('nanoassert')

const rand = curve.randomScalar
const G1 = curve.G1
const G2 = curve.G2
const F = curve.F

module.exports = function (sig, pk, disclosure, challenge) {
  const attrs = sig._S.map(_ => null)
  for (const [k, v] of disclosure) attrs[v] = k

  const D = disclosure.reduce((acc, el, i) => {
    const [k, index] = el
    return G1.add(acc, G1.mulScalar(sig._S[index], F.neg(k)))
  }, G1.neg(sig.K_))

  const S_C = sig._S.filter((_, i) => attrs[i] === null)

  const prover = schnorr([sig.C_, sig.S_].concat(S_C))
  assert(prover.verify(D, sig.proof), 'commitment to D fails validation')

  const r = rand()
  const _r = sig._S.map(rand)

  const sProduct = sig._S.reduce((acc, el, i) => {
    return G1.add(acc, G1.mulScalar(el, _r[i]))
  }, G1.mulScalar(sig.S_, r))

  const aProduct = pk._A.reduce((acc, el, i) => {
    return G2.add(acc, G2.mulScalar(el, _r[i]))
  }, G2.mulScalar(pk.A, r))

  var pairSQ = curve.pairing(sProduct, pk.Q)
  var pairKA = curve.pairing(sig.K_, aProduct)

  var pairTQ = curve.pairing(sig.T_, pk.Q)
  var pairCZ = curve.pairing(sig.C_, pk.Z)

  return curve.bn128.F12.eq(pairSQ, pairKA) && curve.bn128.F12.eq(pairCZ, pairTQ)
}
