const { Application, SetupMessage, ObtainMessage, StoreMessage } = require('../lib/wire')
const { PrivateCertification } = require('./certification')

module.exports = class Issuer {
  constructor (opts) {
    this.certifications = opts.certifications || []
    this.issuances = opts.issuances || []
    this._storage = opts.storage
  }

  addIssuance (buf) {
    const application = Application.decode(buf)

    const cert = this.certifications.find(c => c.certId === application.certId)

    const issuance = cert.issue(application.details)
    this.issuances.push(issuance)
    issuance.setup.tag = application.tag

    const setupMessage = new SetupMessage(application.tag, issuance.setup)
    return setupMessage.encode()
  }

  grantCredential (buf) {
    const res = ObtainMessage.decode(buf)

    const issuance = this.issuances.find(i => i.setup.tag === res.tag)
    const cert = this.certifications.find(c => c.certId === issuance.certId)
    const info = issuance.response(res.details)

    // assertion will throw on bad input before we execute following code
    const identity = cert.genIdentifier(issuance.setup.k[0])

    cert.addCredential({
      attr: issuance.attr,
      identifier: identity
    })

    const finalizeMessage = new StoreMessage(res.tag, info, identity)
    return finalizeMessage.encode()
  }

  addCertification (schema, cb) {
    const certification = new PrivateCertification({
      schema,
      storage: this._storage
    })

    this.certifications.push(certification)
    cb(certification.certId)
  }

  revokeCredential (identifier, cb) {
    const cert = this.certifications.find(c => c.certId === identifier.certId)
    cert.revoke(identifier, cb)
  }

  getPublicCert (certId) {
    const cert =  this.certifications.find(c => c.certId === certId)
    return cert.toPublicCertificate()
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt32LE(this.certifications.length, offset)
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
      certifications.push(PrivateCertification.decode(buf, offset))
      offset += PrivateCertification.decode.bytes
    }

    Issuer.decode.bytes = offset - startIndex
    return new Issuer({ certifications })
  }

  encodingLength () {
    let len = 4
    for (let cert of this.certifications) len += cert.encodingLength()

    return len
  }
}
