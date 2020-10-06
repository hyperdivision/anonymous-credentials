const assert = require('nanoassert')
const curve = require('../lib/curve')
const hash = require('../lib/challenge')
const attributes = require('../lib/gen-attributes')
const { verify } = require('../lib/schnorr-proof')
const { IssuanceSetup, IssuanceResponse } = require('../lib/wire')

const rand = curve.Fr.random
const G1 = curve.G1

module.exports = IssuingProtocol

function IssuingProtocol (keys, attr) {
  if (!(this instanceof IssuingProtocol)) return new IssuingProtocol(keys, attr)

  const K_ = curve.PointG1.random()
  const S_ = K_.multiply(keys.sk.a)
  const S0_ = K_.multiply(keys.sk._a[0])

  const k0 = curve.Fr.random()
  const k = [k0].concat(attr.map(a => a.toString()).map(attributes.encode))

  const setup = new IssuanceSetup(k, K_, S_, S0_)
  const response = respond(keys, k.slice(1), S_)

  return {
    setup,
    attr,
    response
  }
}

function respond (keys, attr, S_) {
  return (res) => {
    const challenge = hash(res.S, res.S0)

    const proof = res.proof
    assert(verify([res.S, res.S0], res.R, proof, challenge),
      'commitment to R fails validation.')

    const inv_a = keys.sk.a.invert()
    const K = res.S.multiply(inv_a)

    const inv_a0 = keys.sk._a[0].invert()
    const S0_inv_a0 = res.S0.multiply(inv_a0)

    assert(!res.S.equals(S_), 'S and S_ should be distinct.')
    assert(K.equals(S0_inv_a0), 'K and S0_inv_a0 should be equal.')

    const kappa = rand()

    const _S = attr.map((_, i) => K.multiply(keys.sk._a[i + 1]))

    const SKappa2 = res.S.multiply(kappa)
    const C = _S.reduce((acc, el, i) => acc.add(el.multiply(attr[i])),
      res.R.add(K).add(SKappa2))

    const T = C.multiply(keys.sk.z)

    return new IssuanceResponse(kappa, K, _S, T)
  }
}
