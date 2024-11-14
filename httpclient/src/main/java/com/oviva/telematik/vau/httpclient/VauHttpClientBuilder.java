package com.oviva.telematik.vau.httpclient;

import com.oviva.telematik.vau.httpclient.internal.ConnectionFactory;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import com.oviva.telematik.vau.httpclient.internal.VauHttpClientImpl;
import java.net.URI;
import java.time.Duration;

public class VauHttpClientBuilder {

  public static VauHttpClientBuilder builder() {
    return new VauHttpClientBuilder();
  }

  private URI vauBaseUri;
  private Environment environment = Environment.PRODUCTION;

  private HttpClient outerClient =
      new JavaHttpClient(
          java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());

  private VauHttpClientBuilder() {}

  public VauHttpClientBuilder outerClient(HttpClient outerClient) {
    this.outerClient = outerClient;
    return this;
  }

  public VauHttpClientBuilder vauBaseUri(URI vauBaseUri) {
    this.vauBaseUri = vauBaseUri;
    return this;
  }

  public VauHttpClientBuilder environment(Environment environment) {
    this.environment = environment;
    return this;
  }

  /**
   * Returns an HttpClient that uses the VAU transport as documented in <a
   * href="https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.37.0/#7">gemSpec_Krypt</a>.
   * The {@link HttpClient} directly sends requests in the HTTP protocol through the VAU tunnel.
   */
  public HttpClient build() {

    if (vauBaseUri == null) {
      throw new IllegalArgumentException("VAU base_uri missing");
    }

    if (outerClient == null) {
      throw new IllegalArgumentException("outer client missing");
    }

    // does the VAU handshake and encapsulation
    var conn =
        new ConnectionFactory(outerClient, environment == Environment.PRODUCTION)
            .connect(vauBaseUri);

    return new VauHttpClientImpl(conn);
  }

  enum Environment {
    TEST,
    REFERENCE,
    PRODUCTION
  }
}
