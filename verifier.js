const assert = require('nanoassert')
const sodium = require('sodium-native')
const RevocationList = require('./revocation-list')
const verify = require('./lib/verify')
const verifyWitness = require('./experiment/revoker').verify
const attributes = require('./lib/gen-attributes')
const { Presentation } = require('./wire')
const { PublicCertification } = require('./certification')

module.exports = class Verifier {
  constructor (storage) {
    this.certifications = {}
    // this._storage = storage
  }

  validate (buf, cb) {
    const { disclosed, witness, showing, certId } = Presentation.decode(buf)

    const cert = this.certifications[certId]
    if (cert === undefined) return cb(new Error('certification not recognised.'))

    // check for revoked credential
    console.log('**************************************************', verifyWitness(witness, cert.pk.acc), '*****************************************************************')
    if (!verifyWitness(witness, cert.pk.acc)) return cb(new Error('credential has been revoked'))

    const disclosure = Object.entries(disclosed).map(format)

    console.log(showing, cert.pk.credential)
    if (!verify(showing, cert.pk.credential, disclosure)) {
      return cb(new Error('credential cannot be verified'))
    }

    // identifier should be stored and used to report a user to the issuer
    const identifier = {
      witness,
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
    this.certifications[cert.certId] = cert

    cb()    
    // cert.revocationList = new RevocationList(this._storage, cert.certId, {
    //   key: cert.revocationListKey
    // })
    // cert.revocationList.init(() => {
    //   self.certifications[cert.certId] = cert
    //   cb()
    // })
  }
}
