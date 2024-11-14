package com.oviva.telematik.vau.httpclient;

import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import java.net.URI;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;

class VauHttpClientBuilderTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void t() {

    //    var vauUri = URI.create("https://e4a-rt.deine-epa.de/VAU");
    var vauUri = URI.create("http://localhost:8081/VAU");

    var client =
        VauHttpClientBuilder.builder()
            .outerClient(new JavaHttpClient(java.net.http.HttpClient.newHttpClient()))
            .environment(VauHttpClientBuilder.Environment.REFERENCE)
            .vauBaseUri(vauUri)
            .build();

    var res =
        client.call(
            new HttpClient.Request(
                URI.create("/epa/authz/v1/getNonce"),
                "GET",
                List.of(
                    new HttpClient.Header("host", "e4a-rt15931.deine-epa.de"),
                    new HttpClient.Header("accept", "application/json"),
                    new HttpClient.Header("x-insurantid", "Z987654321")),
                null));
  }
}
