const sodium = require('sodium-native')
const schnorr = require('./lib/schnorr-proof')
const curve = require('./lib/curve')

var SetupMessage = module.exports.SetupMessage = class SetupMessage {
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

var ObtainMessage = module.exports.ObtainMessage = class ObtainMessage {
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

var StoreMessage = module.exports.StoreMessage = class StoreMessage {
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
    msg.identity.y = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    msg.identity.witness = {}
    msg.identity.witness.c = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    msg.identity.witness.d = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    msg.pk = AccumulatorPublicKey.decode(buf, offset)
    offset += AccumulatorPublicKey.decode.bytes

    StoreMessage.decode.bytes = offset - startIndex
    return msg
  }
}

const AccumulatorPublicKey = module.exports.AccumulatorPublicKey = class AccumulatorPublicKey {
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
      this.basepoints.fill(1).map((_, i, arr) => arr[i] = curve.randomPointG1())
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

  encodingLength () {
    return 1344
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
}

var Application = module.exports.Application = class Application {
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

var IssuanceSetup = module.exports.IssuanceSetup = class IssuanceSetup {
  constructor (k, K_, S_, S0_) {
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

    curve.encodeG1(this.K_, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.S_, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.S0_, buf, offset)
    offset += curve.encodeG1.bytes

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

    setup.K_ = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    setup.S_ = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    setup.S0_ = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    IssuanceSetup.decode.bytes = offset - startIndex
    return setup
  }
}

var IssuanceResponse = module.exports.IssuanceResponse = class IssuanceResponse {
  constructor (kappa, K, _S, T) {
    this.kappa = kappa
    this.K = K
    this._S = _S
    this.T = T
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeScalar(this.kappa, buf, offset)
    offset += curve.encodeScalar.bytes

    curve.encodeG1(this.K, buf, offset)
    offset += curve.encodeG1.bytes

    buf.writeUInt32LE(this._S.length, offset)
    offset += 4

    for (let el of this._S) {
      curve.encodeG1(el, buf, offset)
      offset += curve.encodeG1.bytes
    }

    curve.encodeG1(this.T, buf, offset)
    offset += curve.encodeG1.bytes

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

    res.kappa = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    res.K = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    const len = buf.readUInt32LE(offset)
    offset += 4

    res._S = []
    for (let i = 0; i < len; i++) {
      res._S.push(curve.decodeG1(buf, offset))
      offset += curve.decodeG1.bytes
    }

    res.T = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    IssuanceResponse.decode.bytes = offset - startIndex
    return res
  }
}

const WitnessProof = module.exports.WitnessProof = class WitnessProof {
  constructor ({ T, challenge, cBlinds }) {
    this.T = T || []
    this.challenge = challenge || null
    this.cBlinds = cBlinds || []
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    for (let i = 0; i < this.T.length; i++) {
      curve.encodeG1(this.T[i], buf, offset)
      offset += curve.encodeG1.bytes
    }

    curve.encodeScalar(this.challenge, buf, offset)
    offset += curve.encodeScalar.bytes

    for (let i = 0; i < this.cBlinds.length; i++) {
      curve.encodeScalar(this.cBlinds[i], buf, offset)
      offset += curve.encodeScalar.bytes
    }

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 832
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const T = []
    for (let i = 0; i < 6; i++) {
      T.push(curve.decodeG1(buf, offset))
      offset += curve.decodeG1.bytes
    }

    const challenge = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    const cBlinds = []
    for (let i = 0; i < 7; i++) {
      cBlinds.push(curve.decodeScalar(buf, offset))
      offset += curve.decodeScalar.bytes
    }

    WitnessProof.decode.bytes = offset - startIndex
    return new WitnessProof({ T, challenge, cBlinds })
  }
}

var Presentation = module.exports.Presentation = class Presentation {
  constructor (disclosed, showing, witness, certId) {
    this.disclosed = disclosed
    this.showing = showing
    this.witness = witness
    this.certId = certId
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt32LE(Object.values(this.disclosed).length, offset)
    offset += 4

    for (let e of Object.entries(this.disclosed)) {
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

    const show = this.showing.encode(buf, offset)
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

    for (let e of Object.entries(this.disclosed)) {
      const [k, v] = e.map(a => a.toString())

      len += 2
      len += k.length
      len += v.length
    }

    len += this.showing.encodingLength()
    console.log(len)
    len += this.witness.encodingLength()
    console.log(len)
    len += 32

    return len    
  }
}

var Showing = module.exports.Showing = class Showing {
  constructor (K_, S_, _S, C_, T_, proof) {
    this.K_ = K_
    this.S_ = S_
    this._S = _S
    this.C_ = C_
    this.T_ = T_
    this.proof = proof
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeG1(this.K_, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.S_, buf, offset)
    offset += curve.encodeG1.bytes

    buf.writeUInt32LE(this._S.length, offset)
    offset += 4

    for (let k of this._S) {
      curve.encodeG1(k, buf, offset)
      offset += curve.encodeG1.bytes
    }

    curve.encodeG1(this.C_, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.T_, buf, offset)
    offset += curve.encodeG1.bytes

    schnorr.encode(this.proof, buf, offset)
    offset += schnorr.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4

    len += 96 * (this._S.length + 4)
    len += schnorr.encodingLength(this.proof)

    return len 
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const showing = new Showing()
    showing.K_ = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    showing.S_ = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    const sLen = buf.readUInt32LE(offset)
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

    showing.proof = schnorr.decode(buf, offset)
    offset += schnorr.decode.bytes

    Showing.decode.bytes = offset - startIndex
    return showing
  }
}

var ObtainInfo = module.exports.ObtainInfo = class ObtainInfo {
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

    curve.encodeG1(this.S, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.S0, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.R, buf, offset)
    offset += curve.encodeG1.bytes

    schnorr.encode(this.proof, buf, offset)
    offset += schnorr.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    var startIndex = offset
    
    const msg = new ObtainInfo
    msg.S = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    msg.S0 = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    msg.R = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    msg.proof = schnorr.decode(buf, offset)
    offset += schnorr.decode.bytes

    ObtainInfo.decode.bytes = offset - startIndex
    return msg    
  }

  encodingLength () {
    let len = 0

    len += 96 * 3
    len += schnorr.encodingLength(this.proof)

    return len
  }
}

var Signature = module.exports.Signature = class Signature {
  constructor (sig, pk, certSig) {
    this.sig = sig
    this.pk = Buffer.from(pk)
    this.certSig = Buffer.from(certSig)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.set(this.sig, offset)
    offset += this.sig.byteLength

    buf.set(this.pk, offset)
    offset += this.pk.byteLength

    buf.set(this.certSig, offset)
    offset += this.certSig.byteLength

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 2 * sodium.crypto_sign_BYTES + sodium.crypto_sign_PUBLICKEYBYTES
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const sig = buf.subarray(offset, offset + sodium.crypto_sign_BYTES)
    offset += sodium.crypto_sign_BYTES

    const pk = buf.subarray(offset, offset + sodium.crypto_sign_PUBLICKEYBYTES)
    offset += sodium.crypto_sign_PUBLICKEYBYTES

    const certSig = buf.subarray(offset, offset + sodium.crypto_sign_BYTES)
    offset += sodium.crypto_sign_BYTES

    Signature.decode.bytes = offset - startIndex
    return new Signature(sig, pk, certSig)
  }

  // [inspect] () {
    
  // }

  // toJSON () {
  //   return {
  //     s: s.toString('base64')
  //     bi: bi.toString()
  //   }
  // }

  // static fromJSON () {}
}
