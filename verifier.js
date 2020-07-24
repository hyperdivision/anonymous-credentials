const assert = require('nanoassert')
const sodium = require('sodium-native')
const RevocationList = require('./revocation-list')
const verify = require('./lib/verify')
const attributes = require('./lib/gen-attributes')
const { PublicCertification } = require('./certification')

module.exports = class Verifier {
  constructor (storage) {
    this.certifications = {}
    this._storage = storage
  }

  validate ({ disclosed, sig, showing, certId }, cb) {
    const cert = this.certifications[certId]
    if (cert === undefined) return new Error('certification not recognised.')

    // check for revoked credential
    if (cert.revocationList.has(sig.pk)) return cb(new Error('credential has been revoked'))

    const disclosure = Object.entries(disclosed).map(format)
    const toVerify = Buffer.from(serialize(showing), 'hex')

    if (!sodium.crypto_sign_verify_detached(sig.certSig, sig.pk, cert.pk.org)) {
      return cb(new Error('user key not certified'))
    }

    if (!sodium.crypto_sign_verify_detached(sig.signature, toVerify, sig.pk))  {
      return cb(new Error('user signature failed'))
    }

    if (!verify(showing, cert.pk.credential, disclosure)) {
      return cb(new Error('credential cannot be verified'))
    }

    return cb(null, true)

    // move attributes away from here, disclosed should give all info needed
    function format ([k, v]) {
      var attr = attributes.encode(v.toString())
      var index = Object.keys(cert.schema).indexOf(k) + 1

      return [
        attr,
        index
      ]
    }
  }

  addCertification (info, cb) {
    const cert = PublicCertification.parse(info)
    console.log(cert)
    const self = this
    cert.revocationList = new RevocationList(this._storage, cert.certId, {
      key: cert.revocationListKey
    })
    cert.revocationList.init(() => {
      self.certifications[cert.certId] = cert
      cb()
    })
  }
}

function decodeShowing (buf, offset) {
  if (!buf) buf = Buffer.alloc(encodingLength(proof))
  if (!offset) offset = 0
  const startIndex = offset

  showing.K_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  showing.S_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  sLen = buf.readUInt32LE(buf, offset)
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

  decodeShowing.bytes = offset - startIndex
  return buf
}

// write proper encoding library
function serialize (obj) {
  let result = ''

  if (obj.buffer) result += obj.buffer.toString('hex')
  else if (Array.isArray(obj)) {
    for (let entry of obj) result += serialize(entry)
  } else if (typeof obj === 'object') {
    for (let item of Object.values(obj)) {
      result += serialize(item)
    }
  } else {
    try {
      result += obj.toString(16)
    } catch {
      result += obj.toString('hex')
    }
  }

  return result
}
