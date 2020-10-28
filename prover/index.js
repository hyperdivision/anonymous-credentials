const Identity = require('./identity')
const crypto = require('crypto')
const { Application, SetupMessage, ObtainMessage, StoreMessage, RevocationInfo } = require('../lib/wire')

module.exports = class Prover {
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

    const app = new Application(tag, certId, details)
    return app.encode()
  }

  obtain (buf) {
    const setupMessage = SetupMessage.decode(buf)

    const id = this.applications.find(app => app.tag === setupMessage.tag).identity
    const details = id.credential.obtain(setupMessage.setup)

    const obtainMessage = new ObtainMessage(setupMessage.tag, details)

    return obtainMessage.encode()
  }

  store (buf) {
    const msg = StoreMessage.decode(buf)

    const index = this.applications.findIndex(app => app.tag === msg.tag)
    const id = this.applications[index].identity
    id.finalize(msg)

    this.identities.push(id)
    this.applications.splice(index, 1)
  }

  present (attributes, certId) {
    const id = this.findId(attributes, certId)
    const presentation = id.present(attributes)

    return presentation.encode()
  }

  findId (required, certId) {
    const subset = this.identities.filter(id => certId === undefined ? true : id.certId === certId)
    return subset.find(id => hasAttributes(id.attributes, required))
  }

  updateNonRevocationWitnesses (revinfo) {
    const info = RevocationInfo.decode(revinfo)

    this.identities.filter(id => id.certId === info.certId).forEach(id => id.updateWitness(info))
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt32LE(this.identities.length, offset)
    offset += 4

    for (const id of this.identities) {
      id.encode(buf, offset)
      offset += id.encode.bytes
    }

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4
    for (const id of this.identities) len += id.encodingLength()

    return len
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const user = new this()

    const ids = buf.readUInt32LE(offset)
    offset += 4

    for (let i = 0; i < ids; i++) {
      user.identities.push(Identity.decode(buf, offset))
      offset += Identity.decode.bytes
    }

    this.decode.bytes = offset - startIndex
    return user
  }
}

function hasAttributes (id, attrs) {
  return attrs.reduce((b, a) => b && Object.prototype.hasOwnProperty.call(id, a))
}

function rand () {
  return crypto.randomBytes(6)
}
