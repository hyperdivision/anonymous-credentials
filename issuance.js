const assert = require('nanoassert')
const curve = require('./lib/curve')
const schnorr = require('./lib/schnorr-proof')
const attributes = require('./lib/gen-attributes')
const { IssuanceSetup, IssuanceResponse } = require('./wire')

const rand = curve.randomScalar
const G1 = curve.G1

module.exports = IssuingProtocol

function IssuingProtocol (keys, attr) {
  if (!(this instanceof IssuingProtocol)) return new IssuingProtocol(keys, attr)

  const K_ = curve.randomPointG1()
  const S_ = G1.mulScalar(K_, keys.sk.a)
  const S0_ = G1.mulScalar(K_, keys.sk._a[0])

  const k = attr.map(a => a.toString()).map(attributes.encode)

  const setup = new IssuanceSetup(k, K_, S_, S0_)
  const response = respond(keys, k, S_)

  return {
    setup,
    attr,
    response,
  }
}

function respond (keys, attr, S_) {
  return (res) => {
    const prover = schnorr.prover([res.S, res.S0])
    assert(prover.verify(res.R, res.proof), 'commitment to R fails validation.')

    const inv_a = curve.F.inv(keys.sk.a)
    const K = G1.mulScalar(res.S, inv_a)

    const inv_a0 = curve.F.inv(keys.sk._a[0])
    const S0_inv_a0 = G1.mulScalar(res.S0, inv_a0)

    assert(!G1.eq(res.S, S_), 'S and S_ should be distinct.')
    assert(G1.eq(K, S0_inv_a0), 'K and S0_inv_a0 should be equal.')

    const kappa = rand()

    const _S = attr.map((_, i) => G1.mulScalar(K, keys.sk._a[i + 1]))

    const SKappa2 = G1.mulScalar(res.S, kappa)
    const C = _S.reduce((acc, el, i) => G1.add(acc, G1.mulScalar(el, attr[i])),
      G1.add(res.R, G1.add(K, SKappa2)))

    const T = G1.mulScalar(C, keys.sk.z)

    return new IssuanceResponse(kappa, K, _S, T)
  }
}
