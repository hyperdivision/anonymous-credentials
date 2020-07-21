const assert = require('nanoassert')
const keys = require('./lib/keygen')
const { PrivateCertification } = require('./certification')

module.exports = class Issuer {
  constructor (storage) {
    this.certifications = {}
    this.issuances = []
    this._storage = storage
  }

  addIssuance (application) {
    const cert = this.certifications[application.certId]

    const issuance = cert.issue(application.details)
    this.issuances.push(issuance)
    issuance.setup.tag = application.tag

    return issuance.setup
  }

  grantCredential (res) {
    const issuance = this.issuances.find(i => i.setup.tag === res.tag)
    const cert = this.certifications[issuance.certId]

    const info = issuance.response(res.details)

    // assertion will throw on bad input before we execute following code
    const identity = cert.genIdentity()

    cert.addCredential({
      attr: issuance.attr,
      root: identity.root
    })

    return {
      info,
      identity,
      tag: res.tag
    }
  }

  registerCertification (schema, cb) {
    const certification = new PrivateCertification({
      schema,
      storage: this._storage,
      oninit: () => {
        this.certifications[certification.certId] = certification
        cb(certification.certId)
      }
    })
  }

  revokeCredential (revokeKey, certId, cb) {
    const cert = this.certifications[certId]
    cert.revoke(revokeKey, cb)
  }

  getPublicCert (certId) {
    return this.certifications[certId].toPublicCertificate()
  }
}
