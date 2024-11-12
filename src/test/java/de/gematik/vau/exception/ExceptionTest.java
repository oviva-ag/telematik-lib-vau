/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.vau.exception;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mockStatic;

import de.gematik.vau.lib.VauClientStateMachine;
import de.gematik.vau.lib.VauServerStateMachine;
import de.gematik.vau.lib.crypto.EllipticCurve;
import de.gematik.vau.lib.crypto.KEM;
import de.gematik.vau.lib.crypto.KyberEncoding;
import de.gematik.vau.lib.data.EccKyberKeyPair;
import de.gematik.vau.lib.data.KdfMessage;
import de.gematik.vau.lib.data.SignedPublicVauKeys;
import de.gematik.vau.lib.data.VauPublicKeys;
import de.gematik.vau.lib.exceptions.VauKyberCryptoException;
import de.gematik.vau.lib.exceptions.VauProtocolException;
import de.gematik.vau.lib.util.DigestUtils;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.BigIntegers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class ExceptionTest {
  @BeforeEach
  public void removeBCProviders() {
    removeBCProvider(new BouncyCastlePQCProvider());
    removeBCProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  @Test
  void testEccProviderException() {
    Security.addProvider(new BouncyCastlePQCProvider());
    Arrays.stream(Security.getProviders())
        .toList()
        .indexOf(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    removeBCProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    assertThatThrownBy(EllipticCurve::generateKeyPair)
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("NoSuchProviderException");
  }

  @Test
  void testKyberGenerationProviderException() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    assertThatThrownBy(KyberEncoding::generateKeyPair).isInstanceOf(VauKyberCryptoException.class);
  }

  @Test
  void testKyberGenerateEncryptionProviderException() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    Security.addProvider(new BouncyCastlePQCProvider());
    Arrays.stream(Security.getProviders()).toList().indexOf(new BouncyCastlePQCProvider());
    var publicKey = KyberEncoding.generateKeyPair().getPublic();
    removeBCProvider(new BouncyCastlePQCProvider());
    assertThatThrownBy(() -> KyberEncoding.pqcGenerateEncryptionKey(publicKey))
        .isInstanceOf(VauKyberCryptoException.class);
  }

  @Test
  void testKyberGenerateDecryptionProviderException() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    int index = Security.addProvider(new BouncyCastlePQCProvider()) - 1;
    var privateKey = KyberEncoding.generateKeyPair().getPrivate();
    for (Object a : Security.getProviders()[index].values()) {
      Security.removeProvider(a.toString());
    }
    byte[] encapsulatedKeyDoesNotMatter = new byte[0];
    assertThatThrownBy(
            () -> KyberEncoding.pqcGenerateDecryptionKey(privateKey, encapsulatedKeyDoesNotMatter))
        .isInstanceOf(VauKyberCryptoException.class);
  }

  @Test
  void testSignatureException() throws Exception {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EdDSA");
    KeyPair keyPair = keyGen.generateKeyPair();
    PrivateKey serverAutPrivateKey = keyPair.getPrivate();
    final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.generateRandom();
    final VauPublicKeys serverVauKeys =
        VauPublicKeys.withValidity(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));

    byte[] servAutCertificate = Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der"));
    byte[] ocspReponseAutCertificate =
        Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der"));

    assertThatThrownBy(
            () ->
                SignedPublicVauKeys.sign(
                    servAutCertificate,
                    serverAutPrivateKey,
                    ocspReponseAutCertificate,
                    1,
                    serverVauKeys))
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("generating signature");
  }

  @Test
  void testEccGetSharedSecretIllegalPrivateKeyException() throws Exception {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyPairGenerator wrongKeyGen = KeyPairGenerator.getInstance("EdDSA");
    KeyPair wrongkeyPair = wrongKeyGen.generateKeyPair();
    PrivateKey wrongPrivateKey = wrongkeyPair.getPrivate();
    ECPublicKey correctPublicKey = (ECPublicKey) EllipticCurve.generateKeyPair().getPublic();
    assertThatThrownBy(() -> EllipticCurve.getSharedSecret(correctPublicKey, wrongPrivateKey))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void testExtractVauKeysException() {
    var keys = SignedPublicVauKeys.builder().build();
    assertThatThrownBy(keys::extractVauKeys)
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("extracting VauKeys");
  }

  @Test
  void testVauAndClientNotEqualException() throws Exception {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyFactory keyFactory = KeyFactory.getInstance("EC", "SunEC");
    PKCS8EncodedKeySpec privateSpec =
        new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.generateRandom();
    final VauPublicKeys serverVauKeys =
        VauPublicKeys.withValidity(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
    var signedPublicVauKeys =
        SignedPublicVauKeys.sign(
            Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")),
            serverAutPrivateKey,
            Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
            1,
            serverVauKeys);

    VauServerStateMachine server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
    VauClientStateMachine client = new VauClientStateMachine();
    final byte[] message1Encoded = client.generateMessage1();
    final byte[] message2Encoded = server.receiveMessage(message1Encoded);
    final byte[] message3Encoded = client.receiveMessage2(message2Encoded);
    byte[] message4Encoded = server.receiveMessage(message3Encoded);

    byte[] incorrectHash = new byte[10];

    try (MockedStatic<KEM> utilities = mockStatic(KEM.class)) {
      utilities
          .when(() -> KEM.decryptAead(any(byte[].class), any(byte[].class)))
          .thenReturn(incorrectHash);
      assertThatThrownBy(() -> client.receiveMessage4(message4Encoded))
          .cause()
          .isInstanceOf(InvalidKeyException.class);
    }
  }

  @Test
  void testIatExpException() throws Exception {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PKCS8EncodedKeySpec privateSpec =
        new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.generateRandom();
    final VauPublicKeys serverVauKeys =
        VauPublicKeys.withValidity(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(31));

    var signedPublicVauKeys =
        SignedPublicVauKeys.sign(
            Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")),
            serverAutPrivateKey,
            Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
            1,
            serverVauKeys);

    assertThatThrownBy(() -> new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            "Dates of initialization and expiration of server keys can be only up to 30 days apart.");
  }

  @Test
  void testVauServerHashDoNotEqualException() throws Exception {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyFactory keyFactory = KeyFactory.getInstance("EC", "SunEC");
    PKCS8EncodedKeySpec privateSpec =
        new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.generateRandom();
    final VauPublicKeys serverVauKeys =
        VauPublicKeys.withValidity(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
    var signedPublicVauKeys =
        SignedPublicVauKeys.sign(
            Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")),
            serverAutPrivateKey,
            Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
            1,
            serverVauKeys);

    VauServerStateMachine server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
    VauClientStateMachine client = new VauClientStateMachine();
    final byte[] message1Encoded = client.generateMessage1();
    final byte[] message2Encoded = server.receiveMessage(message1Encoded);
    final byte[] message3Encoded = client.receiveMessage2(message2Encoded);

    byte[] incorrectHash = new byte[10];

    try (MockedStatic<DigestUtils> utilities = mockStatic(DigestUtils.class)) {
      utilities.when(() -> DigestUtils.sha256(any(byte[].class))).thenReturn(incorrectHash);
      assertThatThrownBy(() -> server.receiveMessage(message3Encoded))
          .isInstanceOf(VauProtocolException.class)
          .hasMessageContaining("Client transcript hash and vau calculation do not equal.");
    }
  }

  @Test
  void testKdfMessageNull() {
    assertThatThrownBy(() -> KEM.kdf(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Kdf Message was null.");
  }

  @Test
  void testKdfMessageEcdhSharedSecretNull() {
    byte[] someSharedSecret = new byte[3];
    KdfMessage kdfMessage = new KdfMessage(null, null, null, null, someSharedSecret);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Ecdh Shared Secret was null.");
  }

  @Test
  void testKdfMessageKyberSharedSecretNull() {
    byte[] someSharedSecret = new byte[3];
    KdfMessage kdfMessage = new KdfMessage(null, null, someSharedSecret, null, null);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Kyber Shared Secret was null.");
  }

  @Test
  void testKdfMessage1Null() {
    KdfMessage kdfMessage2 = new KdfMessage(null, null, null, null, null);
    assertThatThrownBy(() -> KEM.kdf(null, kdfMessage2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Kdf Message 1 was null.");
  }

  @Test
  void testKdfMessage2Null() {
    byte[] someSecret = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(1000));
    KdfMessage kdfMessage1 = new KdfMessage(null, null, someSecret, null, someSecret);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage1, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Kdf Message 2 was null.");
  }

  @Test
  void testKdfMessage1EcdhSharedSecretNull() {
    byte[] someSecret = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(1000));
    KdfMessage kdfMessage1 = new KdfMessage(null, null, null, null, someSecret);
    KdfMessage kdfMessage2 = new KdfMessage(null, null, someSecret, null, someSecret);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage1, kdfMessage2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Ecdh Shared Secret of Message 1 was null.");
  }

  @Test
  void testKdfMessage1EcdhSharedSecretIllegalLength() {
    byte[] someSecret = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(1000));
    KdfMessage kdfMessage1 =
        new KdfMessage(null, null, BigInteger.valueOf(1000).toByteArray(), null, someSecret);
    KdfMessage kdfMessage2 = new KdfMessage(null, null, someSecret, null, someSecret);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage1, kdfMessage2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Length of Ecdh Shared Secret of Message 1 must be 32.");
  }

  @Test
  void testKdfMessage1KyberSharedSecretNull() {
    byte[] someSecret = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(1000));
    KdfMessage kdfMessage1 = new KdfMessage(null, null, someSecret, null, null);
    KdfMessage kdfMessage2 = new KdfMessage(null, null, someSecret, null, someSecret);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage1, kdfMessage2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Kyber Shared Secret of Message 1 was null.");
  }

  @Test
  void testKdfMessage2EcdhSharedSecretNull() {
    byte[] someSecret = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(1000));
    KdfMessage kdfMessage1 = new KdfMessage(null, null, someSecret, null, someSecret);
    KdfMessage kdfMessage2 = new KdfMessage(null, null, null, null, someSecret);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage1, kdfMessage2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Ecdh Shared Secret of Message 2 was null.");
  }

  @Test
  void testKdfMessage2EcdhSharedSecretIllegalLength() {
    byte[] someSecret = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(1000));
    byte[] illegalLength = BigInteger.valueOf(1000).toByteArray();
    KdfMessage kdfMessage1 = new KdfMessage(null, null, someSecret, null, someSecret);
    KdfMessage kdfMessage2 = new KdfMessage(null, null, illegalLength, null, someSecret);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage1, kdfMessage2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Length of Ecdh Shared Secret of Message 2 must be 32.");
  }

  @Test
  void testKdfMessage2KyberSharedSecretNull() {
    byte[] someSecret = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(1000));
    KdfMessage kdfMessage1 = new KdfMessage(null, null, someSecret, null, someSecret);
    KdfMessage kdfMessage2 = new KdfMessage(null, null, someSecret, null, null);
    assertThatThrownBy(() -> KEM.kdf(kdfMessage1, kdfMessage2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Kyber Shared Secret of Message 2 was null.");
  }

  @Test
  void testReceiveMessage2CborExceptionMessage() {
    byte[] whatever = new byte[0];
    VauClientStateMachine client = new VauClientStateMachine();
    assertThatThrownBy(() -> client.receiveMessage2(whatever))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Could not CBOR decode Message 2 when receiving it at client. ");
  }

  @Test
  void testReceiveMessage4CborExceptionMessage() {
    byte[] whatever = new byte[0];
    VauClientStateMachine client = new VauClientStateMachine();
    assertThatThrownBy(() -> client.receiveMessage4(whatever))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Could not CBOR decode Message 4 when receiving it at client. ");
  }

  @Test
  void testEllipticCurveGetSharedSecret() throws Exception {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    KeyFactory keyFactory = KeyFactory.getInstance("EC", "SunEC");
    PKCS8EncodedKeySpec privateSpec =
        new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    final EccKyberKeyPair serverVauKeyPair = EccKyberKeyPair.generateRandom();
    final VauPublicKeys serverVauKeys =
        VauPublicKeys.withValidity(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
    var signedPublicVauKeys =
        SignedPublicVauKeys.sign(
            Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")),
            serverAutPrivateKey,
            Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
            1,
            serverVauKeys);

    VauServerStateMachine server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
    VauClientStateMachine client = new VauClientStateMachine();
    final byte[] message1Encoded = client.generateMessage1();

    BigInteger illegalBigInteger = BigInteger.valueOf(1000);
    byte[] illegalBigIntegerBytes = illegalBigInteger.toByteArray();

    try (MockedStatic<EllipticCurve> utilities =
        mockStatic(EllipticCurve.class, Mockito.CALLS_REAL_METHODS)) {
      utilities
          .when(
              () -> EllipticCurve.getSharedSecret(any(ECPublicKey.class), any(ECPrivateKey.class)))
          .thenReturn(illegalBigIntegerBytes);
      assertDoesNotThrow(() -> server.receiveMessage(message1Encoded));
    }
  }

  private void removeBCProvider(Provider provider) {
    int index = Arrays.stream(Security.getProviders()).toList().indexOf(provider);
    if (index != -1) {
      for (Object a : Security.getProviders()[index].values()) {
        Security.removeProvider(a.toString());
      }
    }
  }
}
