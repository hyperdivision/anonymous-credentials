const curve = require('./curve')

class CredentialPublicKey {
  constructor (opts = {}) {
    this.A = opts.A
    this._A = opts._A
    this.Z = opts.Z
    this.Q = opts.Q
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeG2(this.A, buf, offset)
    offset += curve.encodeG2.bytes

    buf.writeUInt32LE(this._A.length, offset)
    offset += 4

    for (const k of this._A) {
      curve.encodeG2(k, buf, offset)
      offset += curve.encodeG2.bytes
    }

    curve.encodeG2(this.Z, buf, offset)
    offset += curve.encodeG2.bytes

    curve.encodeG2(this.Q, buf, offset)
    offset += curve.encodeG2.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const keys = {}

    keys.A = curve.decodeG2(buf, offset)
    offset += curve.decodeG2.bytes

    const aLen = buf.readUInt32LE(offset)
    offset += 4

    keys._A = new Array(aLen)
    for (let i = 0; i < aLen; i++) {
      keys._A[i] = curve.decodeG2(buf, offset)
      offset += curve.decodeG2.bytes
    }

    keys.Z = curve.decodeG2(buf, offset)
    offset += curve.decodeG2.bytes

    keys.Q = curve.decodeG2(buf, offset)
    offset += curve.decodeG2.bytes

    CredentialPublicKey.decode.bytes = offset - startIndex
    return new CredentialPublicKey(keys)
  }

  encodingLength () {
    return 192 * (3 + this._A.length) + 4
  }
}

class CertificatePublicKey {
  constructor (opts = {}) {
    this.acc = opts.acc
    this.credential = opts.credential
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.acc.encode(buf, offset)
    offset += this.acc.encode.bytes

    this.credential.encode(buf, offset)
    offset += this.credential.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const acc = AccumulatorPublicKey.decode(buf, offset)
    offset += AccumulatorPublicKey.decode.bytes

    const credential = CredentialPublicKey.decode(buf, offset)
    offset += CredentialPublicKey.decode.bytes

    CertificatePublicKey.decode.bytes = offset - startIndex
    return new CertificatePublicKey({ acc, credential })
  }

  encodingLength () {
    let len = this.acc.encodingLength()
    len += this.credential.encodingLength()

    return len
  }
}

class AccumulatorPublicKey {
  constructor (opts = {}) {
    this.g1 = opts.g1
    this.u = opts.u || curve.randomPointG1()

    this.h = opts.h || curve.G1.mulScalar(this.u, opts.secrets.xi1)
    this.v = opts.v || curve.G1.mulScalar(this.h, curve.F.inv(opts.secrets.xi2))

    this.g2 = opts.g2
    this.a = opts.a || curve.G2.mulScalar(this.g2, opts.secrets.alpha)

    if (Object.hasOwnProperty.call(opts, 'basepoints')) {
      this.basepoints = opts.basepoints
    } else {
      this.basepoints = new Array(5)
      this.basepoints.fill(1).map((_, i, arr) => { arr[i] = curve.randomPointG1() })
      this.basepoints[1] = this.h
    }

    this.currentAccumulator = opts.current

    this.e = {}
    this.e.gg = curve.pairing(this.g1, this.g2)
    this.e.vg = curve.pairing(this.currentAccumulator, this.g2)
    this.e.hg = curve.pairing(this.h, this.g2)
    this.e.ha = curve.pairing(this.h, this.a)
    this.e.g1a = curve.pairing(this.basepoints[1], this.a)
    this.e.g1g2 = curve.pairing(this.basepoints[1], this.g2)
  }

  updateAccumulator (info) {
    this.currentAccumulator = info.updatedAcc
    this.e.vg = curve.pairing(this.currentAccumulator, this.g2)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeG1(this.g1, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.u, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.v, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.h, buf, offset)
    offset += curve.encodeG1.bytes

    for (let i = 0; i < this.basepoints.length; i++) {
      if (i === 1) continue

      curve.encodeG1(this.basepoints[i], buf, offset)
      offset += curve.encodeG1.bytes
    }

    curve.encodeG1(this.currentAccumulator, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG2(this.g2, buf, offset)
    offset += curve.encodeG2.bytes

    curve.encodeG2(this.a, buf, offset)
    offset += curve.encodeG2.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}
    opts.g1 = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.u = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.v = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.h = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.basepoints = []
    for (let i = 0; i < 5; i++) {
      if (i === 1) {
        opts.basepoints.push(opts.h)
      } else {
        opts.basepoints.push(curve.decodeG1(buf, offset))
        offset += curve.decodeG1.bytes
      }
    }

    opts.current = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.g2 = curve.decodeG2(buf, offset)
    offset += curve.decodeG2.bytes

    opts.a = curve.decodeG2(buf, offset)
    offset += curve.decodeG2.bytes

    AccumulatorPublicKey.decode.bytes = offset - startIndex
    return new AccumulatorPublicKey(opts)
  }

  encodingLength () {
    return 1344
  }
}

module.exports = {
  CredentialPublicKey,
  CertificatePublicKey,
  AccumulatorPublicKey
}
