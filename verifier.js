const assert = require('nanoassert')
const sodium = require('sodium-native')
const RevocationList = require('./revocation-list')
const { verifyCredential, verifyWitness } = require('./lib/verify')
const attributes = require('./lib/gen-attributes')
const { Presentation } = require('./wire')
const hash = require('./lib/challenge')
const { PublicCertification } = require('./certification')

module.exports = class Verifier {
  constructor (storage) {
    this.certifications = {}
    // this._storage = storage
  }

  validate (buf, cb) {
    const { showing, witness, disclosed, certId } = buf
    // const { showing, witness, certId } = Presentation.decode(buf)

    const cert = this.certifications[certId]

    if (cert === undefined) return cb(new Error('certification not recognised.'))

    const index = Object.keys(disclosed).map(k => Object.keys(cert.schema).indexOf(k) + 1)
    const undisclosed = showing._S.filter((_, i) => !index.includes(i))
    const generators = [showing.C_, showing.S_, ...undisclosed]

    const challenge = hash(...generators, ...witness.U, witness.C)

    // check for revoked credential
    if (!verifyWitness(witness, cert.pk.acc, challenge)) {
      return cb(new Error('credential has been revoked'))
    }

    const disclosure = Object.entries(disclosed).map(format)

    if (!verifyCredential(showing, cert.pk.credential, disclosure, challenge, generators)) {
      return cb(new Error('credential cannot be verified'))
    }

    // identifier should be stored and used to report a user to the issuer
    const identifier = {
      witness,
      challenge,
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
