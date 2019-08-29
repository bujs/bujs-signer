'use strict'

const account = require('bujs-account')

const nacl = require('./vendor/nacl')
const sjcl = require('./vendor/sjcl')

/**
 * Generate the signature
 *
 * @param {String} message
 * @param {String} privateKey
 * @returns {String}
 */
function sign (message, privateKey) {
  if (typeof message !== 'string') {
    throw new TypeError('message must be a string')
  }
  const rawPrivateKey = account.parsePrivateKey(privateKey)
  let keyPair = nacl.sign.keyPair.fromSeed(rawPrivateKey)
  let signBytes = nacl.sign.detached(message, keyPair.secretKey)
  return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(signBytes))
}

/**
 * Verify the signature
 *
 * @param  {String} message
 * @param  {String} signature
 * @param  {String} publicKey
 * @returns {Boolean}
 */
function verify (message, signature, publicKey) {
  if (typeof message !== 'string') {
    throw new TypeError('message must be a string')
  }
  if (typeof signature !== 'string') {
    throw new TypeError('signature must be a string')
  }
  const rawPublicKey = account.parsePublicKey(publicKey)

  const signatureBytes = sjcl.codec.bytes.fromBits(
    sjcl.codec.hex.toBits(signature)
  )

  return nacl.sign.detached.verify(
    message,
    signatureBytes,
    rawPublicKey
  )
}

module.exports = {
  sign,
  verify
}
