const assert = require('nanoassert')
const { SchnorrProof } = require('./schnorr-proof')
const curve = require('./curve')
const { AccumulatorPublicKey } = require('./keygen')

class SetupMessage {
  constructor (tag, setup) {
    this.tag = tag
    this.setup = setup
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.write(this.tag, offset, 'hex')
    offset += this.tag.length / 2

    this.setup.encode(buf, offset)
    offset += this.setup.encode.bytes

    this.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 6 + this.setup.encodingLength()
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const msg = new SetupMessage()

    msg.tag = buf.subarray(offset, offset + 6).toString('hex')
    offset += 6

    msg.setup = IssuanceSetup.decode(buf, offset)
    offset += IssuanceSetup.decode.bytes

    SetupMessage.decode.bytes = offset - startIndex
    return msg
  }
}

class ObtainMessage {
  constructor (tag, details) {
    this.tag = tag
    this.details = details
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.write(this.tag, offset, 'hex')
    offset += 6

    this.details.encode(buf, offset)
    offset += this.details.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 6 + this.details.encodingLength()
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const msg = new ObtainMessage()

    msg.tag = buf.subarray(offset, offset + 6).toString('hex')
    offset += 6

    msg.details = ObtainInfo.decode(buf, offset)
    offset += ObtainInfo.decode.bytes

    this.decode.bytes = offset - startIndex
    return msg
  }
}

class StoreMessage {
  constructor (tag, info, identity) {
    this.tag = tag
    this.info = info
    this.identity = identity
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.write(this.tag, offset, 'hex')
    offset += 6

    this.info.encode(buf, offset)
    offset += this.info.encode.bytes

    this.identity.encode(buf, offset)
    offset += this.identity.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 6 + this.info.encodingLength() + this.identity.encodingLength()
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const msg = new StoreMessage()
    msg.tag = buf.subarray(offset, offset + 6).toString('hex')
    offset += 6

    msg.info = IssuanceResponse.decode(buf, offset)
    offset += IssuanceResponse.decode.bytes

    msg.identity = {}
    msg.identity.y = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    msg.identity.witness = {}
    msg.identity.witness.c = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    msg.identity.witness.d = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    msg.pk = AccumulatorPublicKey.decode(buf, offset)
    offset += AccumulatorPublicKey.decode.bytes

    StoreMessage.decode.bytes = offset - startIndex
    return msg
  }
}

class Application {
  constructor (tag, certId, details) {
    this.tag = tag
    this.certId = certId
    this.details = details
  }

  encode (buf, offset) {
    const json = JSON.stringify(this.details)

    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.write(this.tag, offset, 'hex')
    offset += 6

    buf.write(this.certId, offset, 'hex')
    offset += 32

    buf.writeUInt32LE(json.length, offset)
    offset += 4

    buf.write(json, offset)
    offset += json.length

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const app = new Application()

    app.tag = buf.subarray(offset, offset + 6).toString('hex')
    offset += 6

    app.certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    const len = buf.readUInt32LE(offset)
    offset += 4

    const json = buf.subarray(offset, offset + len).toString()
    offset += len

    app.details = JSON.parse(json)

    Application.decode.bytes = offset - startIndex
    return app
  }

  encodingLength () {
    const json = JSON.stringify(this.details)
    return json.length + 42
  }
}

class IssuanceSetup {
  constructor (k, K_, S_, S0_, type) {
    this.k = k
    this.K_ = K_
    this.S_ = S_
    this.S0_ = S0_
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeScalars(this.k, buf, offset)
    offset += curve.encodeScalars.bytes

    this.K_.encode(buf, offset)
    offset += this.K_.encode.bytes

    this.S_.encode(buf, offset)
    offset += this.S_.encode.bytes

    this.S0_.encode(buf, offset)
    offset += this.S0_.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 96 * 3 + 4 + 32 * this.k.length
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const setup = new IssuanceSetup()

    setup.k = curve.decodeScalars(buf, offset)
    offset += curve.decodeScalars.bytes

    setup.K_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    setup.S_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    setup.S0_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    IssuanceSetup.decode.bytes = offset - startIndex
    return setup
  }
}

class IssuanceResponse {
  constructor (kappa, K, _S, T) {
    this.kappa = kappa
    this.K = K
    this._S = _S
    this.T = T
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.kappa.encode(buf, offset)
    offset += this.kappa.encode.bytes

    this.K.encode(buf, offset)
    offset += this.K.encode.bytes

    buf.writeUInt32LE(this._S.length, offset)
    offset += 4

    for (const el of this._S) {
      el.encode(buf, offset)
      offset += el.encode.bytes
    }

    this.T.encode(buf, offset)
    offset += this.T.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 36 + 96 * (this._S.length + 2)
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const res = new IssuanceResponse()

    res.kappa = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    res.K = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    const len = buf.readUInt32LE(offset)
    offset += 4

    res._S = []
    for (let i = 0; i < len; i++) {
      res._S.push(curve.PointG1.decode(buf, offset))
      offset += curve.PointG1.decode.bytes
    }

    res.T = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    IssuanceResponse.decode.bytes = offset - startIndex
    return res
  }
}

class Presentation {
  constructor (opts = {}) {
    this.disclosed = opts.disclosed
    this.showing = opts.showing
    this.witness = opts.witness
    this.certId = opts.certId
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt32LE(Object.values(this.disclosed).length, offset)
    offset += 4

    for (const e of Object.entries(this.disclosed)) {
      const [k, v] = e.map(a => a.toString())

      buf.writeUInt8(k.length, offset)
      offset++

      buf.write(k, offset)
      offset += k.length

      buf.writeUInt8(v.length, offset)
      offset++

      buf.write(v, offset)
      offset += v.length
    }

    this.showing.encode(buf, offset)
    offset += this.showing.encode.bytes

    this.witness.encode(buf, offset)
    offset += this.witness.encode.bytes

    buf.write(this.certId, offset, 'hex')
    offset += this.certId.byteLength

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const p = new Presentation()
    p.disclosed = {}

    const len = buf.readUInt32LE(offset)
    offset += 4

    for (let i = 0; i < len; i++) {
      const klen = buf.readUInt8(offset)
      offset++

      const k = buf.subarray(offset, offset + klen).toString()
      offset += klen

      const vlen = buf.readUInt8(offset)
      offset++

      const v = buf.subarray(offset, offset + vlen).toString()
      offset += vlen

      p.disclosed[k] = v
    }

    p.showing = Showing.decode(buf, offset)
    offset += Showing.decode.bytes

    p.witness = WitnessProof.decode(buf, offset)
    offset += WitnessProof.decode.bytes

    p.certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    Presentation.decode.bytes = offset - startIndex
    return p
  }

  encodingLength () {
    let len = 0

    len += 4

    for (const e of Object.entries(this.disclosed)) {
      const [k, v] = e.map(a => a.toString())

      len += 2
      len += k.length
      len += v.length
    }

    len += this.showing.encodingLength()
    len += this.witness.encodingLength()
    len += 32

    return len
  }
}

class Showing {
  constructor (opts = {}) {
    this.K_ = opts.K_
    this.S_ = opts.S_
    this._S = opts._S
    this.C_ = opts.C_
    this.T_ = opts.T_
    this.proof = opts.proof
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.K_.encode(buf, offset)
    offset += this.K_.encode.bytes

    this.S_.encode(buf, offset)
    offset += this.S_.encode.bytes

    buf.writeUInt32LE(this._S.length, offset)
    offset += 4

    for (const k of this._S) {
      k.encode(buf, offset)
      offset += k.encode.bytes
    }

    this.C_.encode(buf, offset)
    offset += this.C_.encode.bytes

    this.T_.encode(buf, offset)
    offset += this.T_.encode.bytes

    this.proof.encode(buf, offset)
    offset += this.proof.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4

    len += 96 * (this._S.length + 4)
    len += this.proof.encodingLength()

    return len
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const showing = new Showing()

    showing.K_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    showing.S_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    const sLen = buf.readUInt32LE(offset)
    offset += 4

    showing._S = []
    for (let i = 0; i < sLen; i++) {
      showing._S.push(curve.PointG1.decode(buf, offset))
      offset += curve.PointG1.decode.bytes
    }

    showing.C_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    showing.T_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    showing.proof = SchnorrProof.decode(buf, offset)
    offset += SchnorrProof.decode.bytes

    Showing.decode.bytes = offset - startIndex
    return showing
  }
}

class ObtainInfo {
  constructor (S, S0, R, proof) {
    this.S = S
    this.S0 = S0
    this.R = R
    this.proof = proof
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    var startIndex = offset

    this.S.encode(buf, offset)
    offset += this.S.encode.bytes

    this.S0.encode(buf, offset)
    offset += this.S0.encode.bytes

    this.R.encode(buf, offset)
    offset += this.R.encode.bytes

    this.proof.encode(buf, offset)
    offset += this.proof.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    var startIndex = offset

    const msg = new ObtainInfo()

    msg.S = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    msg.S0 = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    msg.R = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    msg.proof = SchnorrProof.decode(buf, offset)
    offset += SchnorrProof.decode.bytes

    ObtainInfo.decode.bytes = offset - startIndex
    return msg
  }

  encodingLength () {
    let len = 0

    len += 96 * 3
    len += this.proof.encodingLength()

    return len
  }
}

class PublicCertification {
  constructor (opts) {
    this.pk = opts.pk
    this.certId = opts.certId
    this.revocationListKey = opts.revocationListKey
    this.schema = opts.schema
  }

  validate (application) {
    for (const [field, type] of Object.entries(this.schema)) {
      assert(Object.prototype.hasOwnProperty.call(application, field), `${field} is required.`)
      assert(typeof application[field] === type)
    }
  }

  encode (buf, offset) {
    const serializedSchema = Buffer.from(JSON.stringify(this.schema))

    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.pk.encode(buf, offset)
    offset += this.pk.encode.bytes

    buf.write(this.certId, offset, 'hex')
    offset += this.certId.length / 2

    buf.set(this.revocationListKey, offset)
    offset += this.revocationListKey.byteLength

    buf.writeUInt32LE(serializedSchema.byteLength, offset)
    offset += 4

    buf.set(serializedSchema, offset)
    offset += serializedSchema.byteLength

    this.encode.bytes = startIndex - offset
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}

    opts.pk = CertificatePublicKey.decode(buf, offset)
    offset += CertificatePublicKey.decode.bytes

    opts.certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    opts.revocationListKey = buf.subarray(offset, offset + 32)
    offset += 32

    const schemaLen = buf.readUInt32LE(offset)
    offset += 4

    opts.schema = JSON.parse(buf.subarray(offset, offset + schemaLen).toString())
    offset += schemaLen

    PublicCertification.decode.bytes = offset - startIndex
    return new PublicCertification(opts)
  }

  encodingLength () {
    let len = 0

    len += this.pk.encodingLength()
    len += 68
    len += Buffer.from(JSON.stringify(this.schema)).byteLength

    return len
  }
}

class Identifier {
  constructor (id = {}, pk) {
    this.y = id.y
    this.w = id.witness || {}
    this.pk = pk
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.y.encode(buf, offset)
    offset += this.y.encode.bytes

    this.w.c.encode(buf, offset)
    offset += this.w.c.encode.bytes

    this.w.d.encode(buf, offset)
    offset += this.w.d.encode.bytes

    this.pk.encode(buf, offset)
    offset += this.pk.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const id = new this()

    id.y = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    id.w.c = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    id.w.d = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    id.pk = AccumulatorPublicKey.decode(buf, offset)
    offset += AccumulatorPublicKey.decode.bytes

    this.decode.bytes = offset - startIndex
    return id
  }

  encodingLength () {
    return 160 + this.pk.encodingLength()
  }
}

class SimpleProof {
  constructor (P_, indices, enc) {
    this.P_ = P_
    this.indices = indices
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    try {
      this.P_.encode(buf, offset)
      offset += this.P_.encode.bytes
    } catch {
      curve.encodeF12(this.P_, buf, offset)
      offset += curve.encodeF12.bytes
    }

    buf.writeUInt8(this.indices.length, offset++)
    for (const i of this.indices) buf.writeUInt8(i, offset++)

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset, decoder = curve.PointG1.decode) {
    if (!offset) offset = 0
    const startIndex = offset

    const P_ = decoder(buf, offset)
    offset += decoder.bytes

    const indexLen = buf.readUInt8(offset++)

    const indices = []
    for (let i = 0; i < indexLen; i++) {
      indices.push(buf.readUInt8(offset++))
    }

    SimpleProof.decode.bytes = offset - startIndex
    return new SimpleProof(P_, indices)
  }

  encodingLength () {
    const pBytes = this.P_.length === 3 ? 96 : 384
    return pBytes + this.indices.length + 1
  }
}

class WitnessProof {
  constructor (opts = {}) {
    this.U = opts.U
    this.C = opts.C
    this.C1 = opts.C1
    this.C2 = opts.C2

    this.proofs = opts.proofs
    this.blinds = opts.blinds
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    for (const u of this.U) {
      u.encode(buf, offset)
      offset += u.encode.bytes
    }

    this.C.encode(buf, offset)
    offset += this.C.encode.bytes

    this.C1.encode(buf, offset)
    offset += this.C1.encode.bytes

    this.C2.encode(buf, offset)
    offset += this.C2.encode.bytes

    for (let i = 0; i < this.proofs.length; i++) {
      this.proofs[i].encode(buf, offset)
      offset += this.proofs[i].encode.bytes
    }

    curve.encodeScalars(this.blinds, buf, offset)
    offset += curve.encodeScalars.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    const U = []
    for (let i = 0; i < 4; i++) {
      U.push(curve.PointG1.decode(buf, offset))
      offset += curve.PointG1.decode.bytes
    }

    const C = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    const C1 = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    const C2 = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    const proofs = new Array(9)
    for (let i = 0; i < 8; i++) {
      proofs[i] = SimpleProof.decode(buf, offset)
      offset += SimpleProof.decode.bytes
    }

    proofs[8] = SimpleProof.decode(buf, offset, curve.decodeF12)
    offset += SimpleProof.decode.bytes

    const blinds = curve.decodeScalars(buf, offset)
    offset += curve.decodeScalars.bytes

    WitnessProof.decode.bytes = offset - startIndex
    return new WitnessProof({ U, C, C1, C2, proofs, blinds })
  }

  encodingLength () {
    return 13 * 32 + 7 * 96 + this.proofs.map(p => p.encodingLength()).reduce((acc, l) => acc + l)
  }
}

class RevocationInfo {
  constructor (opts = {}) {
    this.acc = opts.acc
    this.updatedAcc = opts.updatedAcc
    this.y = opts.y
    this.certId = opts.certId
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.acc.encode(buf, offset)
    offset += this.acc.encode.bytes

    this.updatedAcc.encode(buf, offset)
    offset += this.updatedAcc.encode.bytes

    this.y.encode(buf, offset)
    offset += this.y.encode.bytes

    buf.write(this.certId, offset, 'hex')
    offset += 32

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const info = new RevocationInfo()

    info.acc = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    info.updatedAcc = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    info.y = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    info.certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    RevocationInfo.decode.bytes = offset - startIndex
    return info
  }

  encodingLength () {
    return 256
  }
}

module.exports = {
  SetupMessage,
  ObtainMessage,
  StoreMessage,
  Application,
  IssuanceSetup,
  IssuanceResponse,
  Presentation,
  Showing,
  ObtainInfo,
  PublicCertification,
  Identifier,
  SimpleProof,
  WitnessProof,
  RevocationInfo
}
