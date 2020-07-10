const assert = require('nanoassert')
const sodium = require('sodium-native')
const verify = require('./verify.js')
const attributes = require('./gen-attributes')

module.exports = class {
  constructor () {
    this.certifications = {}
  }

  validate ({ disclosed, sig, showing, certId }) {
    const cert = this.certifications[certId]
    if (cert === undefined) return new Error('certification not recognised.')

    // check for revvoked credential
    for (let key of cert.blacklist) {
      if (Buffer.compare(key, sig.pk) === 0) return new Error('this credential has been revoked')
    }

    const disclosure = Object.entries(disclosed).map(format)

    const toVerify = Buffer.from(serialize(showing), 'hex')

    assert(sodium.crypto_sign_verify_detached(sig.certSig, sig.pk, cert.pk.org))
    assert(sodium.crypto_sign_verify_detached(sig.signature, toVerify, sig.pk))
    assert(verify(showing, cert.pk.credential, disclosure))

    return true

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

  addCertification (certification) {
    this.certifications[certification.certId] = certification
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
