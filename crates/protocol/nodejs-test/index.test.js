const protocol = require('entropy-protocol')
const test = require('tape')

test('Convert Uint8Array to and from hex', function (t) {
  t.plan(2)

  const empty = new Uint8Array(32)
  const emptyHex = protocol.toHex(empty)
  t.equal(Buffer.from(empty).toString('hex'), emptyHex)
  const emptyArray = protocol.fromHex(emptyHex)
  t.true(protocol.constantTimeEq(empty, emptyArray))
})

test('Encrypt, decrypt with X25519Chacha20Poly1305', function (t) {
  t.plan(7)

  const { generateSigningKey, publicKeyFromSecret, encryptAndSign, decryptAndVerify } = protocol.Hpke

  const aliceSk = generateSigningKey()
  const alicePk = publicKeyFromSecret(aliceSk)

  const bobSk = generateSigningKey()
  const bobPk = publicKeyFromSecret(bobSk)

  const plaintext = new Uint8Array(32)

  // Alice encrypts and signs the message to bob.
  const encryptedAndSignedMessage = encryptAndSign(aliceSk, plaintext, bobPk)

  const { sig, pk, a, nonce, msg, recip } = JSON.parse(encryptedAndSignedMessage)
  t.equals(protocol.fromHex(sig).length, 64)
  t.equals(nonce.length, 12)
  t.equals(pk.length, 32)
  t.true(protocol.constantTimeEq(a, alicePk))
  t.true(protocol.constantTimeEq(recip, bobPk))
  t.equals(protocol.fromHex(msg).length, plaintext.length + 16) // MAC is 16 bytes

  // Bob decrypts the message.
  const decryptedPlaintext = decryptAndVerify(bobSk, encryptedAndSignedMessage)

  // Check the original plaintext equals the decrypted plaintext.
  t.true(protocol.constantTimeEq(decryptedPlaintext, plaintext))
})
