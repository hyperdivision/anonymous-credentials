const assert = require('nanoassert')
const sodium = require('sodium-native')
const keygen = require('./lib/keygen')
const Credential = require('./credential')
const { Presentation, Signature } = require('./wire')
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
    const toSign = showing.encode()

    const sig = this.pseudonym.sign(Buffer.from(toSign, 'hex'))

    return new Presentation(disclosed, showing, sig, this.certId)
  }

  encode (buf, offset) {
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

    this.credential.encode(buf, offset)
    offset += this.credential.encode.bytes

    this.pseudonym.encode(buf, offset)
    offset += this.pseudonym.encode.bytes

    this.encode.bytes = offset - startIndex
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

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const jsonLen = buf.readUInt32LE(offset)
    offset += 4

    const attrs = JSON.parse(buf.subarray(offset, offset + jsonLen).toString())
    offset += jsonLen

    const certId = buf.subarray(offset, offset + 32).toString('hex')
    offset += 32

    const id = new this(attrs, certId)

    id.credential = Credential.decode(buf, offset)
    offset += Credential.decode.bytes

    id.pseudonym = Pseudonym.decode(buf, offset)
    offset += Pseudonym.decode.bytes

    Identity.decode.bytes = offset - startIndex
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

  sign (msg) {
    const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, msg, this.keys.sk)

    const signature = new Signature(sig, this.keys.pk, this.keys.certSig)
    this.update()

    return signature
  }

  validate () {
    for (let i = 0; i < this.sigs.length; i++) {
      const { pk } = this.loadIdentity(i)
      assert(sodium.crypto_sign_verify_detached(sigs[i], pk, certKey))
    }
  }

  encode (buf, offset) {
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

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return 4 + (2 * this.sigs.length + 2) * 32
  }

  static decode (buf, offset) {
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

    Pseudonym.decode.bytes = offset - startIndex
    return new this({ root, sigs, certKey }, count)
  }
}
