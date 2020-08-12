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

  obtain (buf) {
    const msg = decodeSetup(buf)

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

function decodeSetup (buf, offset) {
  if (!buf) buf = encodingLength(setup)
  if (!offset) offset = 0
  const startIndex = offset

  const setup = {}

  setup.tag = buf.subarray(offset, offset + 6)
  offset += 6

  setup.k = curve.decodeScalars(buf, offset)
  offset += curve.decodeScalars.bytes

  setup.K_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  setup.S_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  setup.S0_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  decodeSetup.bytes = offset - startIndex
  return buf
}
