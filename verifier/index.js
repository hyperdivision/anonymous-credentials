const RevocationList = require('../revocation-list')
const { verifyCredential, verifyWitness } = require('../lib/verify')
const attributes = require('../lib/gen-attributes')
const { RevocationInfo, Presentation } = require('../lib/wire')
const PublicCertification = require('../lib/public-certification')
const hash = require('../lib/challenge')

module.exports = class Verifier {
  constructor (opts = {}) {
    this.certifications = opts.certifications || []
    // this._storage = opts.storage
  }

  validate (buf, cb) {
    const { showing, witness, disclosed, certId } = Presentation.decode(buf)

    const cert = this.certifications.find(c => c.certId === certId)

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
      var encodedAttr = attributes.encode(attribute + value)
      var index = Object.keys(cert.schema).indexOf(attribute) + 1

      return [
        index,
        encodedAttr
      ]
    }
  }

  registerCertification (info, cb) {
    const cert = PublicCertification.decode(info)
    
    this.certifications.push(cert)

    cb()
    // cert.revocationList = new RevocationList(this._storage, cert.certId, {
    //   key: cert.revocationListKey
    // })
    // cert.revocationList.init(() => {
    //   self.certifications[cert.certId] = cert
    //   cb()
    // })
  }

  updateCertifications (revinfo) {
    const info = RevocationInfo.decode(revinfo)
    this.certifications.find(c => c.certId === info.certId).updateAccumulator(info)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt32LE(this.certifications.length)
    offset += 4

    for (let cert of this.certifications) {
      cert.encode(buf, offset)
      offset += cert.encode.bytes
    }

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const len = buf.readUInt32LE(offset)
    offset += 4

    const certifications = []
    for (let i = 0; i < len; i++) {
      certifications.push(PublicCertification.decode(buf, offset))
      offset += PublicCertification.decode.bytes
    }

    Verifier.decode.bytes = offset - startIndex
    return new Verifier({ certifications })
  }

  encodingLength () {
    let len = 4
    for (let cert of this.certifications) len += cert.encodingLength()
    return len
  }
}
