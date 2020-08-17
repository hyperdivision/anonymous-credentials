const curve = require('./lib/curve')
const Identity = require('./identity')
const credential = require('./credential')
const keys = require('./lib/keygen')
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

    const app = {
      details,
      certId,
      tag
    }

    return encodeApplication(app)
  }

  obtain (buf) {
    const msg = decodeSetup(buf)

    const id = this.applications.find(app => app.tag === msg.tag).identity
    const details = id.credential.obtain(msg)

    const info = {
      tag: msg.tag,
      details
    }

    return encodeObtain(info)
  }

  store (buf) {
    const msg = decodeStoreMsg(buf)

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

  setup.tag = buf.subarray(offset, offset + 6).toString('hex')
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
  return setup
}

function encodeObtain (obtain, buf, offset) {
  if (!buf) buf = Buffer.alloc(6 + credential.obtainEncodingLength(obtain.details))
  if (!offset) offset = 0
  const startIndex = offset

  buf.write(obtain.tag, offset, 'hex')
  offset += 6

  credential.serializeObtain(obtain.details, buf, offset)
  offset += credential.serializeObtain.bytes

  encodeObtain.bytes = offset - startIndex
  return buf
}

function decodeStoreMsg (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const msg = {}
  msg.tag = buf.subarray(offset, offset + 6).toString('hex')
  offset += 6

  msg.info = decodeIssuanceResponse(buf, offset)
  offset += decodeIssuanceResponse.bytes

  msg.identity = keys.decodeUserIds(buf, offset)
  offset += keys.decodeUserIds.bytes

  decodeStoreMsg.bytes = offset - startIndex
  return msg
}

function decodeIssuanceResponse (buf, offset) {
  if (!buf) buf = Buffer.alloc(36 + 96 * (_S.length + 2))
  if (!offset) offset = 0
  const startIndex = offset

  const response = {}

  response.kappa = curve.decodeScalar(buf, offset)
  offset += curve.decodeScalar.bytes

  response.K = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  const len = buf.readUInt32LE(offset)
  offset += 4

  response._S = []
  for (let i = 0; i < len; i++) {
    response._S.push(curve.decodeG1(buf, offset))
    offset += curve.decodeG1.bytes
  }

  response.T = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  decodeIssuanceResponse.bytes = offset - startIndex
  return response
}

function encodeApplication (app, buf, offset) {
  const json = JSON.stringify(app.details)

  if (!buf) buf = Buffer.alloc(json.length + 42)
  if (!offset) offset = 0
  const startIndex = offset
  
  buf.write(app.tag, offset, 'hex')
  offset += 6

  buf.write(app.certId, offset, 'hex')
  offset += 32

  buf.writeUInt32LE(json.length, offset)
  offset += 4

  buf.write(json, offset)
  offset += json.length

  encodeApplication.bytes = offset - startIndex
  return buf
}
