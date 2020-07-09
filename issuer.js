const assert = require('nanoassert')
const keys = require('./keygen')
const IssuingProtocol = require('./issuance.js')
const hash = require('sha256-wasm')
const hasProperty = Object.prototype.hasOwnProperty

module.exports = class {
  constructor () {
    this.certifications = {}
    this.signingKeys = keys.signingKeys()
    this.issuances = []
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
    const identity = keys.userIds(this.signingKeys.sk)

    cert.credentials.push({
      attr: issuance.attr,
      root: identity.root
    })

    return {
      info,
      identity,
      tag: res.tag
    }
  }

  registerCertification (schema) {
    const certKeys = keys.issuingKeys(Object.keys(schema).length + 1)
    const blacklist = []
    const credentials = []

    const certId = shasum(JSON.stringify(schema)).toString('hex')

    function getPk () {
      return certKeys.pk
    }

    function issue (details) {
      for (let field of Object.keys(schema)) assert(hasProperty.call(details, field))
      const issuance = new IssuingProtocol(certKeys, Object.values(details))
      issuance.certId = certId

      return issuance
    }

    const certification = {
      getPk,
      issue,
      blacklist,
      credentials,
      certId
    }

    this.certifications[certId] = certification

    return certId
  }

  revokeCredential (revokeId, pk) {
    const cert = this.certifications.find(c => Buffer.compare(c.getPk(), pk) === 0)

    const identity = cert.credentials.find(keys.findRoot(revokeId))
    cert.blacklist.push(identity.root)

    return identity
  }
}

function shasum (data) {
  return hash().update(data).digest()
}
