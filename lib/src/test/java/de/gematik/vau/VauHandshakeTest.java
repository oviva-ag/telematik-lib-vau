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

package de.gematik.vau;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.vau.lib.VauClientStateMachine;
import de.gematik.vau.lib.VauServerStateMachine;
import de.gematik.vau.lib.data.EccKyberKeyPair;
import de.gematik.vau.lib.data.SignedPublicVauKeys;
import de.gematik.vau.lib.data.VauPublicKeys;
import de.gematik.vau.lib.exceptions.VauProtocolException;
import de.gematik.vau.lib.util.ArrayUtils;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class VauHandshakeTest {

  // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#A_24608
  private static final int VAU_CID_MAX_BYTE_LENGTH = 200;
  private static final Pattern VAU_CID_PATTERN = Pattern.compile("/[A-Za-z0-9-/]+");

  private static final int KYBER_768_BYTE_LENGTH = 1184;
  private static final String TGR_FILENAME = "target/vau3traffic.tgr";

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  private final org.slf4j.Logger log = LoggerFactory.getLogger(this.getClass());

  private int msgNumber = 0;

  @BeforeEach
  public void setUp() {
    final Logger logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    logger.setLevel(Level.TRACE);
  }

  private HttpClient httpClient = HttpClient.newHttpClient();

  @Test
  void rise_RU() throws IOException, InterruptedException {

    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#7.1

    // https://github.com/gematik/lib-vau/issues/18
    var url = URI.create("https://e4a-rt.deine-epa.de/VAU");

    var client = new VauClientStateMachine();

    // handshake - start
    var msg1 = client.generateMessage1();
    var msg2 = postMsg1(url, msg1);

    var cid = msg2.cid();
    validateCid(cid);

    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#A_24623
    var msg3 = client.receiveMessage2(msg2.body());

    var sessionUrl = url.resolve(cid);

    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#A_24623
    var msg4 = post(sessionUrl, msg3);

    client.receiveMessage4(msg4);

    // handshake - end

  }

  private void validateCid(String cid) {
    if (cid == null) {
      throw new VauProtocolException("missing VAU-CID in handshake");
    }
    if (cid.length() > VAU_CID_MAX_BYTE_LENGTH) {
      throw new VauProtocolException(
          "invalid VAU-CID in handshake, too long %d > %d "
              .formatted(cid.length(), VAU_CID_MAX_BYTE_LENGTH));
    }
    if (!VAU_CID_PATTERN.matcher(cid).matches()) {
      throw new VauProtocolException("invalid VAU-CID in handshake: '%s'".formatted(cid));
    }
  }

  private byte[] post(URI uri, byte[] body) throws IOException, InterruptedException {

    var req =
        HttpRequest.newBuilder(uri)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .header("Content-Type", "application/cbor")
            .build();

    var res = httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray());
    if (res.statusCode() != 200) {
      System.out.println(
          """
                    %s
                    """.formatted(new String(res.body())));
      throw new IllegalStateException("unexpected status %d != 200".formatted(res.statusCode()));
    }

    var vauCid = res.headers().firstValue("VAU-CID");
    System.out.println(vauCid);

    return res.body();
  }

  private Msg2 postMsg1(URI uri, byte[] body) throws IOException, InterruptedException {

    var res = postCbor(uri, body);
    var vauCid = res.headers().firstValue("VAU-CID");
    return new Msg2(res.body(), vauCid.orElse(null));
  }

  record Msg2(byte[] body, String cid) {}

  private HttpResponse<byte[]> postCbor(URI uri, byte[] body)
      throws IOException, InterruptedException {

    var req =
        HttpRequest.newBuilder(uri)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .header("Content-Type", "application/cbor")
            .build();

    var res = httpClient.send(req, HttpResponse.BodyHandlers.ofByteArray());
    if (res.statusCode() != 200) {
      throw new IllegalStateException("unexpected status %d != 200".formatted(res.statusCode()));
    }

    return res;
  }

  @Test
  void testHandshake_simple() throws Exception {

    var server = setupServer();
    var client = new VauClientStateMachine();

    // when: client -> server
    var message1Encoded = client.generateMessage1();

    var message2Encoded = server.receiveMessage(message1Encoded);

    var message3Encoded = client.receiveMessage2(message2Encoded);

    var message4Encoded = server.receiveMessage(message3Encoded);

    client.receiveMessage4(message4Encoded);

    var plaintextRequest = "Ping?";

    var encryptedClientVauMessage = client.encryptVauMessage(plaintextRequest.getBytes());

    var decryptedClientVauMessage = server.decryptVauMessage(encryptedClientVauMessage);

    // then
    assertThat(decryptedClientVauMessage).isEqualTo(plaintextRequest.getBytes());

    // when: server -> client
    var plaintextResponse = "Pong!";
    var encryptedServerVauMessage = server.encryptVauMessage(plaintextResponse.getBytes());

    var decryptedServerVauMessage = client.decryptVauMessage(encryptedServerVauMessage);

    // then
    assertThat(decryptedServerVauMessage).isEqualTo(plaintextResponse.getBytes());
  }

  private VauServerStateMachine setupServer()
      throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

    var keyFactory = KeyFactory.getInstance("EC");
    var privateSpec =
        new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    var serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    var serverVauKeyPair =
        EccKyberKeyPair.readFromFile(Path.of("src/test/resources/vau_server_keys.cbor"));
    var serverVauKeys =
        VauPublicKeys.withValidity(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
    var signedPublicVauKeys =
        SignedPublicVauKeys.sign(
            Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")),
            serverAutPrivateKey,
            Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
            1,
            serverVauKeys);

    return new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
  }

  @Test
  void testHandshake() throws Exception {
    Files.deleteIfExists(Path.of(TGR_FILENAME));

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PKCS8EncodedKeySpec privateSpec =
        new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/test/resources/vau-sig-key.der")));
    PrivateKey serverAutPrivateKey = keyFactory.generatePrivate(privateSpec);
    final EccKyberKeyPair serverVauKeyPair =
        EccKyberKeyPair.readFromFile(Path.of("src/test/resources/vau_server_keys.cbor"));
    final VauPublicKeys serverVauKeys =
        VauPublicKeys.withValidity(serverVauKeyPair, "VAU Server Keys", Duration.ofDays(30));
    var signedPublicVauKeys =
        SignedPublicVauKeys.sign(
            Files.readAllBytes(Path.of("src/test/resources/vau_sig_cert.der")),
            serverAutPrivateKey,
            Files.readAllBytes(Path.of("src/test/resources/ocsp-response-vau-sig.der")),
            1,
            serverVauKeys);

    assertThat(serverVauKeyPair.eccKeyPair().getPublic().getAlgorithm()).startsWith("EC");
    assertThat(serverVauKeyPair.eccKeyPair().getPrivate().getAlgorithm()).startsWith("EC");

    assertThat(assertPublicKeyAlgorithm(serverVauKeyPair.eccKeyPair().getPublic())).isTrue();
    assertThat(assertPrivateKeyAlgorithm(serverVauKeyPair.eccKeyPair().getPrivate())).isTrue();

    assertThat(serverVauKeyPair.kyberKeyPair().getPublic().getAlgorithm()).isEqualTo("KYBER768");
    assertThat(serverVauKeyPair.kyberKeyPair().getPrivate().getAlgorithm()).isEqualTo("KYBER768");
    assertThat(
            ((BCKyberPublicKey) serverVauKeyPair.kyberKeyPair().getPublic())
                .getParameterSpec()
                .getName())
        .isEqualTo("KYBER768");
    assertThat(
            ((BCKyberPrivateKey) serverVauKeyPair.kyberKeyPair().getPrivate())
                .getParameterSpec()
                .getName())
        .isEqualTo("KYBER768");

    VauServerStateMachine server = new VauServerStateMachine(signedPublicVauKeys, serverVauKeyPair);
    VauClientStateMachine client = new VauClientStateMachine();

    final byte[] message1Encoded = client.generateMessage1();
    final JsonNode message1Tree = new CBORMapper().readTree(message1Encoded);
    assertThat(message1Tree.get("MessageType").textValue()).isEqualTo("M1");
    assertThat(containsKyberEncodedOfLength(message1Tree.get("Kyber768_PK").binaryValue()))
        .isTrue();

    final byte[] message2Encoded = server.receiveMessage(message1Encoded);
    final JsonNode message2Tree = new CBORMapper().readTree(message2Encoded);
    assertThat(message2Tree.get("MessageType").textValue()).isEqualTo("M2");
    assertThat(message2Tree.get("Kyber768_ct").binaryValue()).hasSize(1088);
    log.debug("AEAD_ct length: {}", message2Tree.get("AEAD_ct").binaryValue().length);
    assertThat(message2Tree.get("AEAD_ct").binaryValue()).hasSizeBetween(1549, 1557);
    log.debug("x: {}", Hex.toHexString(message1Tree.get("ECDH_PK").get("x").binaryValue()));
    log.debug("y: {}", Hex.toHexString(message1Tree.get("ECDH_PK").get("y").binaryValue()));

    final byte[] message3Encoded = client.receiveMessage2(message2Encoded);

    assertThat(client.getKdfClientKey1().serverToClient()).isEqualTo(server.getS2c());
    assertThat(client.getKdfClientKey1().clientToServer()).isEqualTo(server.getC2s());

    byte[] message4Encoded = server.receiveMessage(message3Encoded);
    client.receiveMessage4(message4Encoded);

    final byte[] encryptedClientVauMessage = client.encryptVauMessage("Hello World".getBytes());
    final byte[] decryptedClientVauMessage = server.decryptVauMessage(encryptedClientVauMessage);
    assertThat(decryptedClientVauMessage).isEqualTo("Hello World".getBytes());

    final byte[] encryptedServerVauMessage =
        server.encryptVauMessage("Right back at ya!".getBytes());
    final byte[] decryptedServerVauMessage = client.decryptVauMessage(encryptedServerVauMessage);
    assertThat(encryptedClientVauMessage[0]).isEqualTo((byte) 2);
    assertThat(encryptedClientVauMessage[1]).isEqualTo((byte) 0);
    assertThat(encryptedClientVauMessage[2]).isEqualTo((byte) 1);
    assertThat(ArrayUtils.subarray(encryptedClientVauMessage, 3, 3 + 8))
        .isEqualTo(new byte[] {0, 0, 0, 0, 0, 0, 0, 1});
    assertThat(ArrayUtils.subarray(encryptedClientVauMessage, 11, 11 + 32))
        .isEqualTo(client.getKeyId());

    assertThat(decryptedServerVauMessage).isEqualTo("Right back at ya!".getBytes());

    bundleInHttpRequestAndWriteToFile("/vau", message1Encoded);
    final String vauCid =
        "/vau/URL-von-der-VAU-waehrend-des-Handshakes-gewaehlt-abcdefghij1234567890";
    bundleInHttpResponseAndWriteToFile(
        message2Encoded,
        Header.of(
            "VAU-DEBUG-S_K1_s2c", java.util.Base64.getEncoder().encodeToString(server.getS2c())),
        Header.of(
            "VAU-DEBUG-S_K1_c2s", java.util.Base64.getEncoder().encodeToString(server.getC2s())),
        Header.of("VAU-CID", vauCid));
    bundleInHttpRequestAndWriteToFile(vauCid, message3Encoded);
    bundleInHttpResponseAndWriteToFile(message4Encoded);
    bundleInHttpRequestAndWriteToFile(
        vauCid,
        encryptedClientVauMessage,
        Header.of(
            "VAU-nonPU-Tracing",
            Base64.toBase64String(server.getServerKey2().clientToServerAppData())
                + " "
                + Base64.toBase64String(server.getServerKey2().serverToClientAppData())
                + "\n"));
    bundleInHttpResponseAndWriteToFile(encryptedServerVauMessage);

    Files.write(
        Path.of("target/serverEcc.pem"), writeKeyPair(serverVauKeyPair.eccKeyPair()).getBytes());
    Files.write(
        Path.of("target/serverKyber.pem"),
        writeKeyPair(serverVauKeyPair.kyberKeyPair()).getBytes());
  }

  private static boolean containsKyberEncodedOfLength(byte[] encoded) {
    return encoded.length == KYBER_768_BYTE_LENGTH;
  }

  private static boolean assertPublicKeyAlgorithm(PublicKey key) {
    byte[] encoded = key.getEncoded();
    ASN1Sequence asn1 = ASN1Sequence.getInstance(encoded);
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1);
    return publicKeyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey);
  }

  private static boolean assertPrivateKeyAlgorithm(PrivateKey key) {
    byte[] encoded = key.getEncoded();
    ASN1Sequence asn1 = ASN1Sequence.getInstance(encoded);
    PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(asn1);
    return privateKeyInfo
        .getPrivateKeyAlgorithm()
        .getAlgorithm()
        .equals(X9ObjectIdentifiers.id_ecPublicKey);
  }

  private static String writeKeyPair(KeyPair keyPair) throws IOException {
    final StringWriter printer = new StringWriter();
    JcaPEMWriter writer = new JcaPEMWriter(printer);
    PemObject obj =
        new org.bouncycastle.openssl.PKCS8Generator(
                PrivateKeyInfo.getInstance(keyPair.getPrivate().getEncoded()), null)
            .generate();
    writer.writeObject(obj);
    writer.writeObject(keyPair.getPublic());
    writer.flush();
    writer.close();

    return printer.toString();
  }

  private void bundleInHttpRequestAndWriteToFile(
      String path, byte[] payload, Header... additionalHeader) throws IOException {
    String additionalHeaders =
        Stream.of(additionalHeader)
            .map(p -> p.name() + ": " + p.value())
            .collect(Collectors.joining("\r\n"));
    if (!additionalHeaders.isBlank()) {
      additionalHeaders += "\r\n";
    }
    byte[] httpRequest =
        ("POST "
                + path
                + " HTTP/1.1\r\n"
                + "Host: vau.gematik.de\r\n"
                + additionalHeaders
                + "Content-Type: application/cbor\r\n"
                + "Content-Length: "
                + payload.length
                + "\r\n\r\n")
            .getBytes();

    Files.write(
        Path.of(TGR_FILENAME),
        makeTgr(ArrayUtils.addAll(httpRequest, payload)),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND);
  }

  private void bundleInHttpResponseAndWriteToFile(byte[] payload, Header... additionalHeader)
      throws IOException {
    String additionalHeaders =
        Stream.of(additionalHeader)
            .map(p -> p.name() + ": " + p.value())
            .collect(Collectors.joining("\r\n"));
    if (!additionalHeaders.isEmpty()) {
      additionalHeaders += "\r\n";
    }
    byte[] httpRequest =
        ("HTTP/1.1 200 OK\r\n"
                + additionalHeaders
                + "Content-Type: application/cbor\r\n"
                + "Content-Length: "
                + payload.length
                + "\r\n\r\n")
            .getBytes();
    Files.write(
        Path.of(TGR_FILENAME),
        makeTgr(ArrayUtils.addAll(httpRequest, payload)),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND);
  }

  private byte[] makeTgr(byte[] content) {
    String rec, sen;
    if (msgNumber % 2 == 0) {
      rec = "vau.gematik.de";
      sen = "";
    } else {
      rec = "";
      sen = "vau.gematik.de";
    }
    String result =
        "{\"receiverHostname\":\""
            + rec
            + "\","
            + "\"sequenceNumber\":\""
            + msgNumber++
            + "\","
            + "\"senderHostname\":\""
            + sen
            + "\","
            + "\"uuid\":\""
            + UUID.randomUUID()
            + "\","
            + "\"rawMessageContent\":\""
            + Base64.toBase64String(content)
            + "\"}\n";
    return result.getBytes();
  }

  record Header(String name, String value) {
    static Header of(String name, String value) {
      return new Header(name, value);
    }
  }
}
