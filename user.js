const schnorr = require('./schnorr-proof')
const curve = require('./curve')

const G1 = curve.G1
const G2 = curve.G2
const F1 = curve.F1
const F2 = curve.F2
const F = curve.F
const rand = curve.randomScalar

module.exports = class {
  constructor (attr) {
    this.k = [rand()].concat(attr)
    this.attributes = attr

    this.kappa1 = null
    this.S = null
    this.S0 = null

    this.credential = null
  }

  issuance (init) {
    const alpha = rand()
    const kappa1 = rand()

    const S = G1.mulScalar(init.S_, alpha)
    const S0 = G1.mulScalar(init.S0_, alpha)

    const R1 = G1.mulScalar(S, kappa1)
    const R2 = G1.mulScalar(S0, this.k[0])
    const R = G1.add(R1, R2)

    const prover = schnorr([S, S0])
    var proof = prover.genProof([kappa1, this.k[0]])

    this.kappa1 = kappa1
    this.S = S
    this.S0 = S0

    return {
      S,
      S0,
      R,
      proof
    }
  }

  store (final) {
    const kappa = F.normalize(F.add(this.kappa1, final.kappa2))
    const K = final.K
    const _S = [this.S0].concat(final._S)
    const T = final.T

    const C = _S.reduce((acc, el, i) => {
      return G1.add(acc, G1.mulScalar(el, this.k[i]))
    }, G1.add(K, G1.mulScalar(this.S, kappa)))

    this.credential = {
      k: this.k,
      kappa,
      K,
      S: this.S,
      _S,
      T,
      C
    }

    return this.credential
  }

  show (toShow) {
    const cred = this.credential
    const disclosed = toShow.map(findIndexIn(this.k))

    const alpha = rand()
    const beta = rand()

    const K_ = G1.mulScalar(cred.K, alpha)
    const S_ = G1.mulScalar(cred.S, alpha)

    const _S = cred._S.map(el => G1.mulScalar(el, alpha))

    const negA_B = F.neg(F.mul(alpha, F.inv(beta)))

    const C_ = G1.mulScalar(cred.C, negA_B)
    const T_ = G1.mulScalar(cred.T, negA_B)

    const S_C = _S.filter((_, i) => !disclosed.includes(i))
    const k_C = this.k.filter((_, i) => !disclosed.includes(i))

    const prover = schnorr([C_, S_, ...S_C])
    const proof = prover.genProof([beta, cred.kappa, ...k_C])

    return {
      K_,
      S_,
      _S,
      C_,
      T_,
      proof
    }
  }
}

function findIndexIn (arr) {
  return attr => arr.findIndex(a => curve.F.eq(a, attr))
}
