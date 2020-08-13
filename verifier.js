const assert = require('nanoassert')
const sodium = require('sodium-native')
const RevocationList = require('./revocation-list')
const verify = require('./lib/verify')
const attributes = require('./lib/gen-attributes')
const { parseShowing, serializeShowing } = require('./credential')
const { PublicCertification } = require('./certification')

module.exports = class Verifier {
  constructor (storage) {
    this.certifications = {}
    this._storage = storage
  }

  validate (buf, cb) {
    const { disclosed, sig, showing, certId } = parsePresent(buf.buf)

    const cert = this.certifications[certId]
    if (cert === undefined) return new Error('certification not recognised.')

    // check for revoked credential
    if (cert.revocationList.has(sig.pk)) return cb(new Error('credential has been revoked'))

    const disclosure = Object.entries(disclosed).map(format)
    const toVerify = Buffer.from(serializeShowing(showing), 'hex')

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
    function format ([attribute, value]) {
      var encodedAttr = attributes.encode(value.toString())
      var index = Object.keys(cert.schema).indexOf(attribute) + 1

      return [
        index,
        encodedAttr
      ]
    }
  }

  addCertification (info, cb) {
    const cert = PublicCertification.parse(info)
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

function parsePresent (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const ret = {}
  ret.disclosed = {}

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

    ret.disclosed[k] = v
  }

  ret.showing = parseShowing(buf, offset)
  offset += parseShowing.bytes

  ret.sig = {}
  ret.sig.signature = buf.subarray(offset, offset + sodium.crypto_sign_BYTES)
  offset += sodium.crypto_sign_BYTES

  ret.sig.pk = buf.subarray(offset, offset + sodium.crypto_sign_PUBLICKEYBYTES)
  offset += sodium.crypto_sign_PUBLICKEYBYTES

  ret.sig.certSig = buf.subarray(offset, offset + sodium.crypto_sign_BYTES)
  offset += sodium.crypto_sign_BYTES

  ret.certId = buf.subarray(offset, offset + 32).toString('hex')
  offset += 32

  parsePresent.bytes = offset - startIndex
  return ret
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
