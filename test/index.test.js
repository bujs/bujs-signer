'use strict'

const signer = require('../lib')

/* eslint-env jest */
test('signer.sign()', () => {
  const message = '123'
  const privateKey = 'privbtritxkpPzRxK7KFrrzbewMavnFHMvyx5qfp4cYK6ZFcAF5heDYZ'
  const signature = 'e1a897ac5b77e9970f6309c472624b41668e683575974adb3e80b2ebf0a14d699bc09ea9bbe13455cdd885ec94dd1b5ef03b381252400adb23407d0d81b43b07'
  expect(signer.sign(message, privateKey)).toBe(signature)
})

test('signer.sign(), with bad message', () => {
  let message = 123
  const privateKey = 'privbtritxkpPzRxK7KFrrzbewMavnFHMvyx5qfp4cYK6ZFcAF5heDYZ'
  expect(() => {
    signer.sign(message, privateKey)
  }).toThrow('message must be a string')
})

test('signer.sign(), with bad privateKey', () => {
  const message = '123'
  const privateKey = 'btritxkpPzRxK7KFrrzbewMavnFHMvyx5qfp4cYK6ZFcAF5heDYZpriv'
  expect(() => {
    signer.sign(message, privateKey)
  }).toThrow('invalid privateKey')
})

test('signer.verify()', () => {
  const message = '123'
  const publicKey = 'b00194aea1bb70e3a4784f504670f2aee5ce8d5b70debfa2d2f704361767d8baa1b730576e2b'
  const signature = 'e1a897ac5b77e9970f6309c472624b41668e683575974adb3e80b2ebf0a14d699bc09ea9bbe13455cdd885ec94dd1b5ef03b381252400adb23407d0d81b43b07'
  expect(signer.verify(message, signature, publicKey)).toBeTruthy()
})

test('signer.verify(), with bad message', () => {
  let message = '1230'
  const publicKey = 'b00194aea1bb70e3a4784f504670f2aee5ce8d5b70debfa2d2f704361767d8baa1b730576e2b'
  const signature = 'e1a897ac5b77e9970f6309c472624b41668e683575974adb3e80b2ebf0a14d699bc09ea9bbe13455cdd885ec94dd1b5ef03b381252400adb23407d0d81b43b07'
  expect(signer.verify(message, signature, publicKey)).toBeFalsy()

  message = 123
  expect(() => {
    signer.verify(message, signature, publicKey)
  }).toThrow('message must be a string')
})

test('signer.verify(), with bad publicKey', () => {
  const message = '123'
  const publicKey = '194aea1bb70e3a4784f504670f2aee5ce8d5b70debfa2d2f704361767d8baa1b730576e2bb00'
  const signature = 'e1a897ac5b77e9970f6309c472624b41668e683575974adb3e80b2ebf0a14d699bc09ea9bbe13455cdd885ec94dd1b5ef03b381252400adb23407d0d81b43b07'
  expect(() => {
    signer.verify(message, signature, publicKey)
  }).toThrow('invalid publicKey')
})

test('signer.verify(), with bad signature', () => {
  const message = '123'
  const publicKey = 'b00194aea1bb70e3a4784f504670f2aee5ce8d5b70debfa2d2f704361767d8baa1b730576e2b'
  let signature = '94dd1b5ef03b381252400adb23407d0d81b43b07'
  expect(signer.verify(message, signature, publicKey)).toBeFalsy()

  signature = ''
  expect(signer.verify(message, signature, publicKey)).toBeFalsy()

  signature = 123
  expect(() => {
    signer.verify(message, signature, publicKey)
  }).toThrow('signature must be a string')
})
