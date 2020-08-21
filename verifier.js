const assert = require('nanoassert')
const sodium = require('sodium-native')
const RevocationList = require('./revocation-list')
const verify = require('./lib/verify')
const attributes = require('./lib/gen-attributes')
const { Presentation } = require('./wire')
const { PublicCertification } = require('./certification')

module.exports = class Verifier {
  constructor (storage) {
    this.certifications = {}
    this._storage = storage
  }

  validate (buf, cb) {
    const { disclosed, sig, showing, certId } = Presentation.decode(buf)

    const cert = this.certifications[certId]
    if (cert === undefined) return cb(new Error('certification not recognised.'))

    // check for revoked credential
    if (cert.revocationList.has(sig.pk)) return cb(new Error('credential has been revoked'))

    const disclosure = Object.entries(disclosed).map(format)
    const toVerify = Buffer.from(showing.encode())

    if (!sodium.crypto_sign_verify_detached(sig.certSig, sig.pk, cert.pk.org)) {
      return cb(new Error('user key not certified'))
    }

    if (!sodium.crypto_sign_verify_detached(sig.sig, toVerify, sig.pk))  {
      return cb(new Error('user signature failed'))
    }

    if (!verify(showing, cert.pk.credential, disclosure)) {
      return cb(new Error('credential cannot be verified'))
    }

    // identifier should be stored and used to report a user to the issuer
    const identifier = {
      pk: sig.pk,
      certId
    }

    return cb(null, identifier)

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

  registerCertification (info, cb) {
    const cert = PublicCertification.decode(info)
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
