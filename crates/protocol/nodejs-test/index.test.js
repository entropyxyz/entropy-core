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

test('Encrypt, decrypt with HPKE', function (t) {
  t.plan(2)

  const { generateSigningKey, publicKeyFromSecret, encryptAndSign, decryptAndVerify } = protocol.Hpke

  const aliceSk = generateSigningKey()

  const bobSk = generateSigningKey()
  const bobPk = publicKeyFromSecret(bobSk)

  const plaintext = new Uint8Array(32)

  // Alice encrypts and signs the message to bob.
  const encryptedAndSignedMessage = encryptAndSign(aliceSk, plaintext, bobPk)

  // Bob decrypts the message.
  const decryptedPlaintext = decryptAndVerify(bobSk, encryptedAndSignedMessage)

  // Check the original plaintext equals the decrypted plaintext.
  t.true(protocol.constantTimeEq(decryptedPlaintext, plaintext))

  const mallorySk = generateSigningKey()

  // Malloy cannot decrypt the message.
  let error
  try {
      decryptAndVerify(mallorySk, encryptedAndSignedMessage)
  } catch (e) {
      error = e.toString()
  }
  t.equals(error, 'Error: Hpke: HPKE Error: OpenError')
})
