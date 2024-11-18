package com.oviva.telematik.vau.reverseproxy;

import com.oviva.telematik.vau.httpclient.HttpClient;
import com.oviva.telematik.vau.httpclient.VauClientFactoryBuilder;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import io.undertow.Undertow;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.List;
import java.util.concurrent.Semaphore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

  private static final Logger log = LoggerFactory.getLogger(Main.class);

  static {
    Security.addProvider(new BouncyCastlePQCProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) {
    var app = new Main();
    app.start();
    app.waitForever();
  }

  void start() {

    var vauUri = URI.create("https://e4a-rt.deine-epa.de/VAU");
    //    var vauUri = URI.create("http://localhost:8081/VAU");
    var upstreamBaseUri = URI.create("https://e4a-rt15931.deine-epa.de");

    // connect VAU tunnel (unauthenticated)
    var clientFactory =
        VauClientFactoryBuilder.builder()
            .outerClient(new JavaHttpClient(java.net.http.HttpClient.newHttpClient()))
            .environment(VauClientFactoryBuilder.Environment.REFERENCE)
            .vauBaseUri(vauUri)
            .build();

    var reverseProxy =
        Undertow.builder()
            .addHttpListener(7777, "localhost")
            .setIoThreads(4)
            .setHandler(new VauProxyHandler(clientFactory, upstreamBaseUri))
            .build();
    reverseProxy.start();

    var addr = reverseProxy.getListenerInfo().get(0).getAddress();
    log.info("Reverse-Proxy started at {}", addr);

    var client = new JavaHttpClient(java.net.http.HttpClient.newHttpClient());

    var nonceRes =
        client.call(
            new HttpClient.Request(
                URI.create("http://localhost:7777/epa/authz/v1/getNonce"),
                "GET",
                List.of(
                    //                    new HttpClient.Header("host", "e4a-rt15931.deine-epa.de"),
                    //                    new HttpClient.Header("x-insurantid", "Z987654321"),
                    new HttpClient.Header("accept", "application/json")),
                null));

    System.out.println(nonceRes);
    System.out.println(new String(nonceRes.body(), StandardCharsets.UTF_8));
  }

  private void waitForever() {

    var lock = new Semaphore(0);
    try {
      lock.acquire();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
