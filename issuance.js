const assert = require('nanoassert')
const curve = require('./lib/curve')
const hash = require('./lib/challenge')
const attributes = require('./lib/gen-attributes')
const { verify } = require('./lib/schnorr-proof')
const { IssuanceSetup, IssuanceResponse } = require('./wire')

const rand = curve.randomScalar
const G1 = curve.G1

const opsG1 = {
  add: (a, b) => G1.add(a, b),
  mul: (a, b) => G1.mulScalar(a, b),
  eq: (a, b) => G1.eq(a, b)
}

module.exports = IssuingProtocol

function IssuingProtocol (keys, attr) {
  if (!(this instanceof IssuingProtocol)) return new IssuingProtocol(keys, attr)

  const K_ = curve.randomPointG1()
  const S_ = G1.mulScalar(K_, keys.sk.a)
  const S0_ = G1.mulScalar(K_, keys.sk._a[0])

  const k0 = curve.randomScalar()
  const k = [k0].concat(attr.map(a => a.toString()).map(attributes.encode))

  const setup = new IssuanceSetup(k, K_, S_, S0_)
  const response = respond(keys, k.slice(1), S_)

  return {
    setup,
    attr,
    response,
  }
}

function respond (keys, attr, S_) {
  return (res) => {
    const challenge = hash(res.S, res.S0)

    const proof = res.proof
    assert(verify([res.S, res.S0], res.R, proof, proof.blinds, challenge),
      'commitment to R fails validation.')

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
