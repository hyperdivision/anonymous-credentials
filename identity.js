const assert = require('nanoassert')
const sodium = require('sodium-native')
const keygen = require('./lib/keygen')
const { Credential, serializeShowing, showingEncodingLength } = require('./credential')
const attributes = require('./lib/gen-attributes')

module.exports = class Identity {
  constructor (attrs, certId) {
    this.credential = new Credential(Object.keys(attrs).length)
    this.pseudonym = null
    this.attributes = attrs
    this.certId = certId
  }

  finalize ({ identity, info }) {
    this.pseudonym = new Pseudonym(identity)
    this.credential.finalize(info)
  }

  present (disclosure) {
    const disclosed = {}
    for (let item of disclosure) disclosed[item] = this.attributes[item]

    // TODO: validate against credential
    const encoded = Object.values(disclosed).map(v =>
      attributes.encode(v.toString()))

    const showing = this.credential.show(encoded)
    const toSign = serializeShowing(showing)

    const sig = this.pseudonym.sign(Buffer.from(toSign, 'hex'))
    this.pseudonym.update()

    const presentation = {
      disclosed,
      showing,
      sig,
      certId: this.certId
    }

    return encodePresent(presentation)
  }

  serialize (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    const json = JSON.stringify(this.attributes)
    buf.writeUInt32LE(json.length, offset)
    offset += 4

    buf.write(json, offset)
    offset += json.length

    buf.write(this.certId, offset, 'hex')
    offset += 32

    this.credential.serialize(buf, offset)
    offset += this.credential.serialize.bytes

    this.pseudonym.serialize(buf, offset)
    offset += this.pseudonym.serialize.bytes

    this.serialize.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    let len = 4
    const json = JSON.stringify(this.attributes)

    len += json.length
    len += 32
    len += this.credential.encodingLength()
    len += this.pseudonym.encodingLength()

    return len
  }

  static parse (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const jsonLen = buf.readUInt32LE(offset)
    offset += 4

    const attrs = JSON.parse(buf.subarray(offset, offset + jsonLen).toString())
    offset += jsonLen

    const certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    const id = new Identity(attrs, certId)

    id.credential = Credential.parse(buf, offset)
    offset += Credential.parse.bytes

    id.pseudonym = Pseudonym.parse(buf, offset)
    offset += Pseudonym.parse.bytes

    Identity.parse.bytes = offset - startIndex
    return id
  }
}

class Pseudonym {
  constructor ({ root, sigs, certKey }, count) {
    this.count = count || 0
    this.seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
    this.maxDepth = Math.ceil(Math.log2(sigs.length))

    this.root = root
    this.sigs = sigs
    this.certKey = certKey

    this.keys = {
      pk: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
      sk: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES),
      certSig: null
    }

    for (let i = 0; i < sigs.length; i++) {
      this.loadIdentity(i)
      assert(sodium.crypto_sign_verify_detached(sigs[i], this.keys.pk, certKey), i)
    }

    this.loadIdentity(this.count, this.keys)
  }

  update () {
    this.loadIdentity(++this.count, this.keys)
    return this
  }

  getSubIdentity (prefix, depth) {
    return keygen.genIdentifier(root, prefix, depth)
  }

  loadIdentity (counter, keypair) {
    if (keypair === undefined) return this.loadIdentity(counter, this.keys)
    if (!keypair.pk) keypair.pk = Buffer.alloc(32)
    if (!keypair.sk) keypair.sk = Buffer.alloc(32)

    const seed = keygen.genIdentifier(this.root, counter, this.maxDepth)
    sodium.crypto_sign_seed_keypair(keypair.pk, keypair.sk, seed)
    if (Object.prototype.hasOwnProperty.call(keypair, 'certSig'))  keypair.certSig = this.sigs[counter]

    return keypair
  }

  serialize (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.writeUInt16LE(this.count, offset)
    offset += 2

    buf.writeUInt16LE(this.maxDepth, offset)
    offset += 2

    buf.set(this.root, offset)
    offset += this.root.byteLength

    for (let sig of this.sigs) {
      buf.set(sig, offset)
      offset += sig.byteLength
    }

    buf.set(this.certKey, offset)
    offset += this.certKey.length

    this.serialize.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 4 + (2 * this.sigs.length + 2) * 32
  }

  static parse (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const count = buf.readUInt16LE(offset)
    offset += 2

    const maxDepth = buf.readUInt16LE(offset)
    offset += 2

    const root = buf.subarray(offset, offset + 32)
    offset += 32

    const sigs = []
    for (let i = 0; i < 2 ** maxDepth; i++) {
      sigs.push(buf.subarray(offset, offset + sodium.crypto_sign_BYTES))
      offset += sodium.crypto_sign_BYTES
    }

    const certKey = buf.subarray(offset, offset + sodium.crypto_sign_PUBLICKEYBYTES)
    offset += sodium.crypto_sign_PUBLICKEYBYTES

    Pseudonym.parse.bytes = offset - startIndex
    return new Pseudonym({ root, sigs, certKey }, count)
  }

  sign (msg) {
    const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    const pk = Buffer.from(this.keys.pk)
    const certSig = Buffer.from(this.keys.certSig)

    sodium.crypto_sign_detached(sig, msg, this.keys.sk)

    function encode (buf, offset) {
      if (!buf) buf = Buffer.alloc(encodingLength())
      if (!offset) offset = 0
      const startIndex = offset

      buf.set(sig, offset)
      offset += sig.byteLength

      buf.set(pk, offset)
      offset += pk.byteLength

      buf.set(certSig, offset)
      offset += certSig.byteLength

      encode.bytes = offset - startIndex
      return buf
    }

    function encodingLength () {
      return 2 * sodium.crypto_sign_BYTES + sodium.crypto_sign_PUBLICKEYBYTES
    }

    return {
      signature: sig,
      pk,
      certSig,
      encode,
      encodingLength
    }
  }

  validate () {
    for (let i = 0; i < this.sigs.length; i++) {
      const { pk } = this.loadIdentity(i)
      assert(sodium.crypto_sign_verify_detached(sigs[i], pk, certKey))
    }
  }
}

function encodePresent (present, buf, offset) {
  if (!buf) buf = Buffer.alloc(presentEncodingLength(present))
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt32LE(Object.values(present.disclosed).length, offset)
  offset += 4

  for (let e of Object.entries(present.disclosed)) {
    const [k, v] = e.map(a => a.toString())

    buf.writeUInt8(k.length, offset)
    offset++

    buf.write(k, offset)
    offset += k.length

    buf.writeUInt8(v.length, offset)
    offset++

    buf.write(v, offset)
    offset += v.length
  }

  const show = serializeShowing(present.showing, buf, offset)
  offset += serializeShowing.bytes

  present.sig.encode(buf, offset)
  offset += present.sig.encode.bytes

  buf.write(present.certId, offset, 'hex')
  offset += present.certId.byteLength

  encodePresent.bytes = offset - startIndex
  return buf
}

function presentEncodingLength (present) {
  let len = 0

  len += 4

  for (let e of Object.entries(present.disclosed)) {
    const [k, v] = e.map(a => a.toString())

    len += 2
    len += k.length
    len += v.length
  }

  len += showingEncodingLength(present.showing)
  len += present.sig.encodingLength()
  len += 32

  return len
}
