package com.oviva.telematik.vau.httpclient;

import com.oviva.telematik.vau.httpclient.internal.ConnectionFactory;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.httpclient.internal.VauHttpClientImpl;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;

class ConnectionFactoryTest {

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void t() {

    //    var vauUri = URI.create("https://e4a-rt.deine-epa.de/VAU");
    var vauUri = URI.create("http://localhost:8081/VAU");

    var cf = new ConnectionFactory(new JavaHttpClient(HttpClient.newHttpClient()), false);
    var conn = cf.connect(vauUri);

    var httpClient = new VauHttpClientImpl(conn);
    var res =
        httpClient.call(
            new com.oviva.telematik.vau.httpclient.HttpClient.Request(
                URI.create("/epa/authz/v1/getNonce"),
                "GET",
                List.of(
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "host", "e4a-rt15931.deine-epa.de"),
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "accept", "application/json"),
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "x-insurantid", "Z987654321"),
                    new com.oviva.telematik.vau.httpclient.HttpClient.Header(
                        "x-useragent", "Oviva/0.0.1")),
                null));
  }
}
