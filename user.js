const curve = require('./lib/curve')
const Identity = require('./identity')
const crypto = require('crypto')

module.exports = class User {
  constructor () {
    this.applications = []
    this.identities = []
  }

  apply (details, certId) {
    // cert.validate(application)

    const identity = new Identity(details, certId)
    const tag = rand().toString('hex')

    this.applications.push({
      tag,
      identity
    })

    return {
      details,
      certId,
      tag
    }
  }

  obtain (msg) {
    const id = this.applications.find(app => app.tag === msg.tag).identity
    const details = id.credential.obtain(msg)

    return {
      tag: msg.tag,
      details
    }
  }

  store (msg) {
    const index = this.applications.findIndex(app => app.tag === msg.tag)
    const id = this.applications[index].identity
    id.finalize(msg)

    this.identities.push(id)
    this.applications.splice(index, 1)
  }

  present (attributes) {
    const id = this.findId(attributes)
    return id.present(attributes)
  }

  findId (required) {
    return this.identities.find(id => hasAttributes(id.attributes, required))
  }
}

function hasAttributes(id, attrs) {
  return attrs.reduce((b, a) => b && Object.prototype.hasOwnProperty.call(id, a))
}

function rand () {
  return crypto.randomBytes(6)
}
