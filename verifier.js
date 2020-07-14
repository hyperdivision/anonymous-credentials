const assert = require('nanoassert')
const sodium = require('sodium-native')
const RevocationList = require('./revocation-list')
const verify = require('./lib/verify')
const attributes = require('./lib/gen-attributes')

module.exports = class Verifier {
  constructor (storage) {
    this.certifications = {}
    this._storage = storage
  }

  validate ({ disclosed, sig, showing, certId }, cb) {
    const cert = this.certifications[certId]
    if (cert === undefined) return new Error('certification not recognised.')

    // check for revoked credential
    if (cert.revocationList.revoked(sig.pk)) return cb(new Error('credential has been revoked'))

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

  addCertification (cert, cb) {
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
