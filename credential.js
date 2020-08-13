const schnorr = require('./lib/schnorr-proof')
const curve = require('./lib/curve')

const G1 = curve.G1
const F = curve.F
const rand = curve.randomScalar

class Credential {
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

    const prover = schnorr.prover([this.S, this._S[0]])
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

    const prover = schnorr.prover([dBlindC, blindS, ...undisclosed.S])
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

  serialize (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt32LE(this.k.length, offset)
    offset += 4

    for (let k of this.k) {
      curve.encodeScalar(k, buf, offset)
      offset += curve.encodeScalar.bytes
    }

    curve.encodeScalar(this.kappa, buf, offset)
    offset += curve.encodeScalar.bytes

    curve.encodeG1(this.K, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.S, buf, offset)
    offset += curve.encodeG1.bytes

    for (let S of this._S) {
      curve.encodeG1(k, buf, offset)
      offset += curve.encodeG1.bytes
    }

    curve.encodeG1(this.T, buf, offset)
    offset += curve.encodeG1.bytes

    this.serialize.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = o

    len += 8
    len += 32 * (this.k.length + 1)
    len += 96 * (this._S.length + 3)

    return len
  }

  static parse (buf, offset) {
    if (!offset) offset = 0

    const kLen = buf.readUInt32LE(offset)
    offset += 4

    const cred = new Credential(kLen)

    for (let i = 0; i < kLen; i++) {
      cred.k[i] = curve.decodeScalar(buf, offset)
      offset += curve.decodeScalar.bytes
    }

    cred.kappa = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    cred.K = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    cred.S = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    for (let i = 0; i < kLen - 1; i++) {
      cred._S[i] = curve.decodeG1(buf, offset)
      offset += curve.decodeG1.bytes
    }

    cred.T = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    cred.C = cred._S.reduce(accumulator, mulAdd(cred.K, cred.S, cred.kappa))

    Credential.parse.bytes = offset - startIndex
    return cred

    function accumulator (a, e, i) {
      return mulAdd(a, e, cred.k[i])
    }
  }
}

function mulAdd (sum, element, scalar) {
  return G1.add(sum, G1.mulScalar(element, scalar))
}

function findIndexIn (arr) {
  return attr => arr.findIndex(a => curve.F.eq(a, attr))
}

function serializeObtain (transcript, buf, offset) {
  if (!buf) buf = Buffer.alloc(obtainEncodingLength(transcript))
  if (!offset) offset = 0
  var startIndex = offset

  curve.encodeG1(transcript.S, buf, offset)
  offset += curve.encodeG1.bytes

  curve.encodeG1(transcript.S0, buf, offset)
  offset += curve.encodeG1.bytes

  curve.encodeG1(transcript.R, buf, offset)
  offset += curve.encodeG1.bytes

  schnorr.serialize(transcript.proof, buf, offset)
  offset += schnorr.serialize.bytes

  serializeObtain.bytes = offset - startIndex
  return buf
}

function parseObtain (buf, offset) {
  if (!buf) buf = Buffer.alloc(obtainEncodingLength(transcript))
  if (!offset) offset = 0
  var startIndex = offset
  
  const transcript = {}
  transcript.S = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  transcript.S0 = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  transcript.R = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  transcript.proof = schnorr.parse(buf, offset)
  offset += schnorr.serialize.bytes

  serializeObtain.bytes = offset - startIndex
  return transcript
}

function obtainEncodingLength (transcript) {
  let len = 0

  len += 96 * 3
  len += schnorr.encodingLength(transcript.proof)

  return len
}

function serializeShowing (showing, buf, offset) {
  if (!buf) buf = Buffer.alloc(showingEncodingLength(showing))
  if (!offset) offset = 0
  const startIndex = offset

  curve.encodeG1(showing.K_, buf, offset)
  offset += curve.encodeG1.bytes

  curve.encodeG1(showing.S_, buf, offset)
  offset += curve.encodeG1.bytes

  buf.writeUInt32LE(showing._S.length, offset)
  offset += 4

  for (let k of showing._S) {
    curve.encodeG1(k, buf, offset)
    offset += curve.encodeG1.bytes
  }

  curve.encodeG1(showing.C_, buf, offset)
  offset += curve.encodeG1.bytes

  curve.encodeG1(showing.T_, buf, offset)
  offset += curve.encodeG1.bytes

  schnorr.serialize(showing.proof, buf, offset)
  offset += schnorr.serialize.bytes

  serializeShowing.bytes = offset - startIndex
  return buf
}

function parseShowing (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const showing = {}
  showing.K_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  showing.S_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  sLen = buf.readUInt32LE(offset)
  offset += 4

  showing._S = []
  for (let i = 0; i < sLen; i++) {
    showing._S.push(curve.decodeG1(buf, offset))
    offset += curve.decodeG1.bytes
  }

  showing.C_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  showing.T_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  showing.proof = schnorr.parse(buf, offset)
  offset += schnorr.parse.bytes

  parseShowing.bytes = offset - startIndex
  return showing
}

function showingEncodingLength (showing) {
  let len = 4

  len += 96 * (showing._S.length + 4)
  len += schnorr.encodingLength(showing.proof)

  return len 
}

module.exports = {
  Credential,
  serializeObtain,
  parseObtain,
  obtainEncodingLength,
  serializeShowing,
  parseShowing,
  showingEncodingLength
}
