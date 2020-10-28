const curve = require('../lib/curve')
const hash = require('../lib/challenge')
const schnorr = require('../lib/schnorr-proof')
const { ObtainInfo, Showing } = require('../lib/wire')

const G1 = curve.G1
const F = curve.F
const rand = curve.Fr.random

module.exports = class Credential {
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

    init.k.forEach((val, i) => { this.k[i] = val })

    this.S = init.S_.multiply(alpha)
    this._S[0] = init.S0_.multiply(alpha)

    const R1 = this.S.multiply(this.kappa)
    const R2 = this._S[0].multiply(this.k[0])
    const R = R1.add(R2)

    const generators = [this.S, this._S[0]]
    const secrets = [this.kappa, this.k[0]]
    const challenge = hash(...generators)

    const proof = schnorr.prove(generators, secrets, challenge, R)

    return new ObtainInfo(this.S, this._S[0], R, proof)
  }

  finalize (final) {
    const k = this.k

    this.kappa = this.kappa.add(final.kappa)
    this.K = final.K

    final._S.forEach((val, i) => { this._S[i + 1] = val })
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
    const K_ = this.K.multiply(alpha)
    const S_ = this.S.multiply(alpha)
    const _S = this._S.map(el => el.multiply(alpha))

    const blindingFactor = alpha.multiply(beta.invert()).negate()

    // blinded by div(alpha, beta)
    const C_ = this.C.multiply(blindingFactor)
    const T_ = this.T.multiply(blindingFactor)

    const undisclosed = {}
    undisclosed.S = _S.filter((_, i) => !disclosed.includes(i))
    undisclosed.k = this.k.filter((_, i) => !disclosed.includes(i))

    const generators = [C_, S_, ...undisclosed.S]
    const secrets = [beta, this.kappa, ...undisclosed.k]

    return {
      prove,
      generators,
      secrets
    }

    function prove (challenge) {
      const proof = schnorr.prove(generators, secrets, challenge)

      return new Showing({
        K_,
        S_,
        _S,
        C_,
        T_,
        proof
      })
    }
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeScalars(this.k, buf, offset)
    offset += curve.encodeScalars.bytes

    this.kappa.encode(buf, offset)
    offset += this.kappa.encode.bytes

    this.K.encode(buf, offset)
    offset += this.K.encode.bytes

    this.S.encode(buf, offset)
    offset += this.S.encode.bytes

    for (const S of this._S) {
      S.encode(buf, offset)
      offset += S.encode.bytes
    }

    this.T.encode(buf, offset)
    offset += this.T.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 0

    len += 8
    len += 32 * (this.k.length + 1)
    len += this._S[0].encodingLength() * (this._S.length + 3)

    return len
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const k = curve.decodeScalars(buf, offset)
    offset += curve.decodeScalars.bytes

    // here k[0] is encoded rather than generated, so give (kLen - 1)
    const cred = new this(k.length - 1)
    cred.k = k

    cred.kappa = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    cred.K = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    cred.S = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    for (let i = 0; i < k.length; i++) {
      cred._S[i] = curve.PointG1.decode(buf, offset)
      offset += curve.PointG1.decode.bytes
    }

    cred.T = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    cred.C = cred._S.reduce(accumulator, mulAdd(cred.K, cred.S, cred.kappa))

    this.decode.bytes = offset - startIndex
    return cred

    function accumulator (a, e, i) {
      return mulAdd(a, e, cred.k[i])
    }
  }
}

function mulAdd (sum, element, scalar) {
  return sum.add(element.multiply(scalar))
}

function findIndexIn (arr) {
  return attr => arr.findIndex(a => a.equals(attr))
}
