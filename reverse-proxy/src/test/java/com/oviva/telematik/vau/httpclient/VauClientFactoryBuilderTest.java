package com.oviva.telematik.vau.httpclient;

import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VauClientFactoryBuilderTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void t() {

    //    var vauUri = URI.create("https://e4a-rt.deine-epa.de/VAU");
    //    var vauUri = URI.create("http://localhost:8081/VAU");

    var client = new JavaHttpClient(java.net.http.HttpClient.newHttpClient());

    var reverseProxyUri = URI.create("http://localhost:7777/epa/authz/v1/getNonce");

    var res =
        client.call(
            new HttpClient.Request(
                reverseProxyUri,
                "GET",
                List.of(
                    //                    new HttpClient.Header("host", "e4a-rt15931.deine-epa.de"),
                    new HttpClient.Header("accept", "application/json"),
                    new HttpClient.Header("x-insurantid", "Z987654321")),
                null));

    assertEquals(200, res.status());
//    assertEquals("", new String(res.body(), StandardCharsets.UTF_8));
  }
}
