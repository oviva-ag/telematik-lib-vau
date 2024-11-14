package com.oviva.telematik.vau.httpclient.internal;

import com.oviva.telematik.vau.httpclient.HttpClient;
import de.gematik.vau.lib.VauClientStateMachine;
import java.net.URI;
import java.util.List;

public class Connection {

  private static final String METHOD_POST = "POST";

  private final HttpClient outerClient;
  private final String cid;
  private final URI sessionUri;
  private final VauClientStateMachine client;

  public Connection(
      HttpClient outerClient, String cid, URI sessionUri, VauClientStateMachine client) {
    this.outerClient = outerClient;
    this.cid = cid;
    this.sessionUri = sessionUri;
    this.client = client;
  }

  public byte[] call(byte[] requestBody) {

    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#A_24628-01

    var ciphertextRequest = client.encryptVauMessage(requestBody);
    var req =
        new HttpClient.Request(
            sessionUri,
            METHOD_POST,
            List.of(
                new HttpClient.Header("content-type", "application/octet-stream"),
                new HttpClient.Header("accept", "*/*")),
            ciphertextRequest);
    var res = outerClient.call(req);
    if (res.status() != 200) {
      throw new HttpExceptionWithInfo(
          res.status(),
          METHOD_POST,
          sessionUri,
          "bad status code %d != 200, cid=%s".formatted(res.status(), cid));
    }
    var ciphertextResponse = res.body();
    return client.decryptVauMessage(ciphertextResponse);
  }
}
