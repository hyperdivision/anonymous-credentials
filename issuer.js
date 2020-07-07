const assert = require('nanoassert')
const keys = require('./keygen')
const IssuingProtocol = require('./issuance.js')

module.exports = class {
  constructor () {
    this.certifications = {}
    this.signingKeys = keys.signingKeys()
    this.issuances = []
  }

  addIssuance (cert, attributes) {
    const issuance = cert.issue(attributes)
    this.issuances.push(issuance)

    return issuance
  }

  grantCredential (res) {
    const issuance = this.issuances.find(i => i.tag === res.tag)

    const credential = issuance.response(res)

    // assertion will throw on bad input before we execute following code
    const identity = keys.userIds(this.signingKeys.sk)

    this.certification.credentials.push({
      attr: issuance.attr,
      root: identity.root
    })

    return {
      credential,
      identity
    }
  }

  newCertification (fields) {
    const certKeys = keys.issuingKeys(fields.length + 1)
    const blacklist = []
    const credentials = []

    function getPk () {
      return certKeys.pk
    }

    function issue (attributes) {
      assert(attributes.length === fields.length)
      const issuance = new IssuingProtocol(keys, fields)

      return issuance
    }

    const certification = {
      getPk,
      issue,
      blacklist,
      credentials
    }

    this.certifications.push(certification)

    return certification
  }

  revokeCredential (revokeId, pk) {
    const cert = this.certifications.find(c => Buffer.compare(c.getPk(), pk) === 0)

    const identity = cert.credentials.find(keys.findRoot(revokeId))
    cert.blacklist.push(identity.root)

    return identity
  }
}
