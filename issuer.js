const assert = require('nanoassert')
const curve = require('./curve')
const keygen = require('./keygen')
const schnorr = require('./schnorr-proof')

const rand = curve.randomScalar
const G1 = curve.G1

module.exports = function (attr) {
  const keys = keygen(attr.length + 1)
  const cache = {}
  
  function one () {
    const K_ = curve.randomPointG1()
    const S_ = G1.mulScalar(K_, keys.sk.a)
    const S0_ = G1.mulScalar(K_, keys.sk._a[0])

    cache.S_ = S_

    return {
      S_,
      K_,
      S0_
    }
  }

  function two (res) {
    const prover = schnorr([res.S, res.S0])
    assert(prover.verify(res.R, res.proof), 'commitment to R fails validation.')

    const inv_a = curve.F.inv(keys.sk.a)
    const K = G1.mulScalar(res.S, inv_a)

    const inv_a0 = curve.F.inv(keys.sk._a[0])
    const S0_inv_a0 = G1.mulScalar(res.S0, inv_a0)

    assert(!G1.eq(res.S, cache.S_), 'S and S_ should be distinct.')
    assert(G1.eq(K, S0_inv_a0), 'K and S0_inv_a0 should be equal.')

    const kappa2 = rand()

    const _S = attr.map((_, i) => G1.mulScalar(K, keys.sk._a[i + 1]))

    const SKappa2 = G1.mulScalar(res.S, kappa2)
    let C = _S.reduce((acc, el, i) => {
      return G1.add(acc, G1.mulScalar(el, attr[i]))
    }, G1.add(res.R, G1.add(K, SKappa2)))

    const T = G1.mulScalar(C, keys.sk.z)

    return {
      kappa2,
      K,
      _S,
      T
    }
  }

  function getPk () {
    return keys.pk
  }

  function getSk () {
    return keys.sk
  }

  return {
    one,
    two,
    getPk,
    getSk
  }
}
