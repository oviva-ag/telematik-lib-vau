package com.oviva.telematik.vau.httpclient.internal;

import com.oviva.telematik.vau.httpclient.HttpClient;
import de.gematik.vau.lib.VauClientStateMachine;
import de.gematik.vau.lib.exceptions.VauProtocolException;
import java.net.URI;
import java.util.List;
import java.util.regex.Pattern;

public class ConnectionFactory {

  private static final String METHOD_POST = "POST";

  // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#A_24608
  private static final int VAU_CID_MAX_BYTE_LENGTH = 200;
  private static final Pattern VAU_CID_PATTERN = Pattern.compile("/[A-Za-z0-9-/]+");

  private final HttpClient outerClient;
  private final boolean isPu;

  public ConnectionFactory(HttpClient outerClient, boolean isPu) {
    this.outerClient = outerClient;
    this.isPu = isPu;
  }

  /**
   * Initializes a new "Vertrauenswuerdige Ausfuehrungsumgebung" (VAU), roughly translates to a
   * Trusted Execution Environment (TEE).
   *
   * @return a framed connection allowing clients to send binary data to a VAU and receive a binary
   *     response.
   */
  public Connection connect(URI url) {

    var client = new VauClientStateMachine(isPu);

    var result = handshake(client, url);

    return new Connection(outerClient, result.cid(), result.sessionUri(), client);
  }

  /** does the handshake to initialize the trusted environment */
  private HandshakeResult handshake(VauClientStateMachine client, URI vauBaseUri) {

    // handshake - start
    var msg1 = client.generateMessage1();
    var msg2 = postMsg1(outerClient, vauBaseUri, msg1);

    var cid = msg2.cid();
    validateCid(cid);

    var msg3 = client.receiveMessage2(msg2.body());

    var sessionUri = vauBaseUri.resolve(cid);

    var msg4 = postCbor(outerClient, sessionUri, msg3).body();

    client.receiveMessage4(msg4);
    return new HandshakeResult(cid, sessionUri);
  }

  record HandshakeResult(String cid, URI sessionUri) {}

  private Msg2 postMsg1(HttpClient outerClient, URI uri, byte[] body) {

    var res = postCbor(outerClient, uri, body);
    var vauCid =
        res.headers().stream()
            .filter(h -> "VAU-CID".equalsIgnoreCase(h.name()))
            .map(HttpClient.Header::value)
            .findFirst();

    return new Msg2(res.body(), vauCid.orElse(null));
  }

  private HttpClient.Response postCbor(HttpClient outerClient, URI uri, byte[] body) {

    var req =
        new HttpClient.Request(
            uri,
            METHOD_POST,
            List.of(new HttpClient.Header("Content-Type", "application/cbor")),
            body);

    var res = outerClient.call(req);
    if (res.status() != 200) {
      throw new HttpExceptionWithInfo(
          res.status(),
          METHOD_POST,
          uri,
          "bad status got: %d , expected: 200".formatted(res.status()));
    }
    return res;
  }

  private record Msg2(byte[] body, String cid) {}

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
}
