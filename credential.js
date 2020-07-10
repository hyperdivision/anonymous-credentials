const schnorr = require('./schnorr-proof')
const curve = require('./curve')

const G1 = curve.G1
const F = curve.F
const rand = curve.randomScalar

module.exports = class {
  constructor (length) {
    this.k = new Array(length + 1)
    this.kappa = null
    this.K = null
    this.S = null
    this._S = new Array(length)
    this.T = null
    this.C = null
  }

  obtain (init) {
    const alpha = rand()
    this.kappa = rand()

    this.k[0] = rand()
    init.k.forEach((val, i) => this.k[i + 1] = val)

    this.S = G1.mulScalar(init.S_, alpha)
    this._S[0] = G1.mulScalar(init.S0_, alpha)

    const R1 = G1.mulScalar(this.S, this.kappa)
    const R2 = G1.mulScalar(this._S[0], this.k[0])
    const R = G1.add(R1, R2)

    const prover = schnorr([this.S, this._S[0]])
    var proof = prover.genProof([this.kappa, this.k[0]])

    return {
      S: this.S,
      S0: this._S[0],
      R,
      proof
    }
  }

  finalize (final) {
    const k = this.k

    this.kappa = F.normalize(F.add(this.kappa, final.kappa))
    this.K = final.K
    final._S.forEach((val , i) => this._S[i + 1] = val)
    this.T = final.T

    this.C = this._S.reduce(accumulator, mulAdd(this.K, this.S, this.kappa))

    return this

    function accumulator (a, e, i) {
      return mulAdd(a, e, k[i])
    }
  }

  show (attributes) {
    const disclosed = attributes.map(findIndexIn(this.k))

    // randomly generate blinding constants
    const alpha = rand()
    const beta = rand()

    // blinded by alpha
    const blindK = G1.mulScalar(this.K, alpha)
    const blindS = G1.mulScalar(this.S, alpha)

    const blindedS_ = this._S.map(el => G1.mulScalar(el, alpha))

    const blindingFactor = F.neg(F.mul(alpha, F.inv(beta)))

    // blinded by div(alpha, beta)
    const dBlindC = G1.mulScalar(this.C, blindingFactor)
    const dBlindT = G1.mulScalar(this.T, blindingFactor)

    const undisclosed = {}
    undisclosed.S = blindedS_.filter((_, i) => !disclosed.includes(i))
    undisclosed.k = this.k.filter((_, i) => !disclosed.includes(i))

    const prover = schnorr([dBlindC, blindS, ...undisclosed.S])
    const proof = prover.genProof([beta, this.kappa, ...undisclosed.k])

    return {
      K_: blindK,
      S_: blindS,
      _S: blindedS_,
      C_: dBlindC,
      T_: dBlindT,
      proof
    }
  }
}

function mulAdd (sum, element, scalar) {
  return G1.add(sum, G1.mulScalar(element, scalar))
}

function findIndexIn (arr) {
  return attr => arr.findIndex(a => curve.F.eq(a, attr))
}
