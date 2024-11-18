package com.oviva.telematik.vau.httpclient;

import com.oviva.telematik.vau.httpclient.internal.ConnectionFactory;
import com.oviva.telematik.vau.httpclient.internal.JavaHttpClient;
import java.net.URI;
import java.time.Duration;

public class VauClientFactoryBuilder {

  public static VauClientFactoryBuilder builder() {
    return new VauClientFactoryBuilder();
  }

  private URI vauBaseUri;
  private Environment environment = Environment.PRODUCTION;

  private HttpClient outerClient =
      new JavaHttpClient(
          java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());

  private VauClientFactoryBuilder() {}

  public VauClientFactoryBuilder outerClient(HttpClient outerClient) {
    this.outerClient = outerClient;
    return this;
  }

  public VauClientFactoryBuilder vauBaseUri(URI vauBaseUri) {
    this.vauBaseUri = vauBaseUri;
    return this;
  }

  public VauClientFactoryBuilder environment(Environment environment) {
    this.environment = environment;
    return this;
  }

  /**
   * Returns an HttpClient that uses the VAU transport as documented in <a
   * href="https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.37.0/#7">gemSpec_Krypt</a>.
   * The {@link HttpClient} directly sends requests in the HTTP protocol through the VAU tunnel.
   */
  public VauClientFactory build() {

    if (vauBaseUri == null) {
      throw new IllegalArgumentException("VAU base_uri missing");
    }

    if (outerClient == null) {
      throw new IllegalArgumentException("outer client missing");
    }

    return new ConnectionFactory(outerClient, environment == Environment.PRODUCTION, vauBaseUri);
  }

  public enum Environment {
    TEST,
    REFERENCE,
    PRODUCTION
  }
}
