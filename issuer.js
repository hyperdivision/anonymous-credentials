const assert = require('nanoassert')
const curve = require('./lib/curve')
const credential = require('./credential')
const keys = require('./lib/keygen')
const { Application, SetupMessage, ObtainMessage, StoreMessage } = require('./wire')
const { PrivateCertification } = require('./certification')

module.exports = class Issuer {
  constructor (storage) {
    assert(typeof storage === 'string', 'storage must be string')
    this.certifications = {}
    this.issuances = []
    this._storage = storage
  }

  beginIssuance (app) {
    assert(Buffer.isBuffer(app), 'application must be buffer')
    const application = Application.decode(app)

    const cert = this.certifications[application.certId]

    const issuance = cert.issue(application.details)
    this.issuances.push(issuance)
    issuance.setup.tag = application.tag

    const setupMessage = new SetupMessage(application.tag, issuance.setup)
    return setupMessage.encode()
  }

  grantCredential (buf) {
    const res = ObtainMessage.decode(buf)

    const issuance = this.issuances.find(i => i.setup.tag === res.tag)
    const cert = this.certifications[issuance.certId]
    const info = issuance.response(res.details)

    // assertion will throw on bad input before we execute following code
    const identity = cert.genIdentity()

    cert.addCredential({
      attr: issuance.attr,
      root: identity.root
    })

    const finalizeMessage = new StoreMessage(res.tag, info, identity)
    return finalizeMessage.encode()
  }

  addCertification (schema, cb) {
    const certification = new PrivateCertification({
      schema,
      storage: this._storage,
      oninit: () => {
        this.certifications[certification.certId] = certification
        cb(null, certification.certId)
      }
    })
  }

  revokeCredential (identifier, cb) {
    const cert = this.certifications[identifier.certId]
    cert.revoke(identifier.pk, cb)
  }

  getPublicCert (certId) {
    return this.certifications[certId].toPublicCertificate()
  }

  * getPublicCerts () {
    for (var key of Object.keys(this.certifications)) {
      yield [key, this.getPublicCert(key)]
    }
  }
}
