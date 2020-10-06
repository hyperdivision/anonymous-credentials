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

    this.A.encode(buf, offset)
    offset += this.A.encode.bytes

    buf.writeUInt32LE(this._A.length, offset)
    offset += 4

    for (const k of this._A) {
      k.encode(buf, offset)
      offset += k.encode.bytes
    }

    this.Z.encode(buf, offset)
    offset += this.Z.encode.bytes

    this.Q.encode(buf, offset)
    offset += this.Q.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const keys = {}

    keys.A = curve.PointG2.decode(buf, offset)
    offset += curve.PointG2.decode.bytes

    const aLen = buf.readUInt32LE(offset)
    offset += 4

    keys._A = new Array(aLen)
    for (let i = 0; i < aLen; i++) {
      keys._A[i] = curve.PointG2.decode(buf, offset)
      offset += curve.PointG2.decode.bytes
    }

    keys.Z = curve.PointG2.decode(buf, offset)
    offset += curve.PointG2.decode.bytes

    keys.Q = curve.PointG2.decode(buf, offset)
    offset += curve.PointG2.decode.bytes

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
    this.u = opts.u || curve.PointG1.random()

    this.h = opts.h || this.u.multiply(opts.secrets.xi1)
    this.v = opts.v || this.h.multiply(opts.secrets.xi2.invert())

    this.g2 = opts.g2
    this.a = opts.a || this.g2.multiply(opts.secrets.alpha)
    // console.log(require('util').inspect(this.a, false, null, true))

    if (Object.hasOwnProperty.call(opts, 'basepoints')) {
      this.basepoints = opts.basepoints
    } else {
      this.basepoints = new Array(5)
      this.basepoints.fill(1).map((_, i, arr) => { arr[i] = curve.PointG1.random() })
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

    this.g1.encode(buf, offset)
    offset += this.g1.encode.bytes

    this.u.encode(buf, offset)
    offset += this.u.encode.bytes

    this.v.encode(buf, offset)
    offset += this.v.encode.bytes

    this.h.encode(buf, offset)
    offset += this.h.encode.bytes

    for (let i = 0; i < this.basepoints.length; i++) {
      if (i === 1) continue

      this.basepoints[i].encode(buf, offset)
      offset += this.basepoints[i].encode.bytes
    }

    this.currentAccumulator.encode(buf, offset)
    offset += this.currentAccumulator.encode.bytes

    this.g2.encode(buf, offset)
    offset += this.g2.encode.bytes

    this.a.encode(buf, offset)
    offset += this.a.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}
    opts.g1 = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    opts.u = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    opts.v = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    opts.h = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    opts.basepoints = []
    for (let i = 0; i < 5; i++) {
      if (i === 1) {
        opts.basepoints.push(opts.h)
      } else {
        opts.basepoints.push(curve.PointG1.decode(buf, offset))
        offset += curve.PointG1.decode.bytes
      }
    }

    opts.current = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    opts.g2 = curve.PointG2.decode(buf, offset)
    offset += curve.PointG2.decode.bytes

    opts.a = curve.PointG2.decode(buf, offset)
    offset += curve.PointG2.decode.bytes

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
