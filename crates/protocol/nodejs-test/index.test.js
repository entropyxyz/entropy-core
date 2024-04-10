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

  const { generateSigningKey, encryptAndSign, decryptAndVerify } = protocol.Hpke

  const aliceSk = generateSigningKey()

  const bobX25519Keypair = protocol.X25519Keypair.generate()

  const plaintext = new Uint8Array(32)

  // Alice encrypts and signs the message to bob.
  const encryptedAndSignedMessage = encryptAndSign(aliceSk, plaintext, bobX25519Keypair.publicKey())

  // Bob decrypts the message.
  const decryptedPlaintext = decryptAndVerify(bobX25519Keypair.secretKey(), encryptedAndSignedMessage)

  // Check the original plaintext equals the decrypted plaintext.
  t.true(protocol.constantTimeEq(decryptedPlaintext, plaintext))

  const malloryX25519Keypair = protocol.X25519Keypair.generate()

  // Malloy cannot decrypt the message.
  let error
  try {
    decryptAndVerify(malloryX25519Keypair.secretKey(), encryptedAndSignedMessage)
  } catch (e) {
    error = e.toString()
  }
  t.equals(error, 'Error: Hpke: HPKE Error: OpenError')
})
