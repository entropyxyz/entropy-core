const protocol = require('entropy-protocol')
const test = require('tape')

test('Convert Uint8Array to and from hex', function (t) {
  t.plan(2)

  const empty = new Uint8Array(32)
  const emptyHex = protocol.to_hex(empty)
  t.equal(Buffer.from(empty).toString('hex'), emptyHex)
  const emptyArray = protocol.from_hex(emptyHex)
  t.true(protocol.constant_time_eq(empty, emptyArray))
})

test('Encrypt, decrypt', function (t) {
  t.plan(7)
  const aliceSk = protocol.gen_signing_key()
  const alicePk = protocol.public_key_from_secret(aliceSk)

  const bobSk = protocol.gen_signing_key()
  const bobPk = protocol.public_key_from_secret(bobSk)

  const plaintext = new Uint8Array(32)

  // Alice encrypts and signs the message to bob.
  const encryptedAndSignedMessage = protocol.encrypt_and_sign(aliceSk, plaintext, bobPk)

  const { sig, pk, a, nonce, msg, recip } = JSON.parse(encryptedAndSignedMessage)
  t.equals(protocol.from_hex(sig).length, 64)
  t.equals(nonce.length, 12)
  t.equals(pk.length, 32)
  t.true(protocol.constant_time_eq(a, alicePk))
  t.true(protocol.constant_time_eq(recip, bobPk))
  t.equals(protocol.from_hex(msg).length, plaintext.length + 16) // MAC is 16 bytes

  // Bob decrypts the message.
  const decryptedPlaintext = protocol.decrypt_and_verify(bobSk, encryptedAndSignedMessage)

  // Check the original plaintext equals the decrypted plaintext.
  t.true(protocol.constant_time_eq(decryptedPlaintext, plaintext))
})
