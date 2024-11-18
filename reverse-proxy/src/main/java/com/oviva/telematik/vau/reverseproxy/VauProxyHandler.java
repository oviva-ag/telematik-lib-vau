package com.oviva.telematik.vau.reverseproxy;

import com.oviva.telematik.vau.httpclient.HttpClient;
import com.oviva.telematik.vau.httpclient.VauClientFactory;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HttpString;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class VauProxyHandler implements HttpHandler {

  private final VauClientFactory vauClientFactory;
  private final URI upstreamBaseUri;

  public VauProxyHandler(VauClientFactory vauClientFactory, URI upstreamBaseUri) {
    this.vauClientFactory = vauClientFactory;
    this.upstreamBaseUri = upstreamBaseUri;
  }

  @Override
  public void handleRequest(HttpServerExchange exchange) throws Exception {
    var blocking = exchange.startBlocking();
    if (exchange.isInIoThread()) {
      exchange.dispatch(this);
      return;
    }

    blocking
        .getReceiver()
        .receiveFullBytes(
            (fullBytesEx, requestBytes) -> {

              // open a VAU tunnel
              // TODO: cache that, maybe with attachments?
              var client = vauClientFactory.connect();

              // prepare inner request
              var req = prepareRequest(fullBytesEx, requestBytes);

              // do tunneled request request
              var res = client.call(req);

              // reply proxied request
              sendResponse(fullBytesEx, res);
            });
  }

  private void sendResponse(HttpServerExchange exchange, HttpClient.Response res) {

    for (var h : res.headers()) {
      exchange.getResponseHeaders().add(HttpString.tryFromString(h.name()), h.value());
    }

    exchange.setStatusCode(res.status());
    var body = res.body();
    if (body != null && body.length > 0) {
      exchange.getResponseSender().send(ByteBuffer.wrap(body));
    }
    exchange.endExchange();
  }

  private HttpClient.Request prepareRequest(HttpServerExchange exchange, byte[] body) {
    var method = exchange.getRequestMethod().toString();
    var headers = exchange.getRequestHeaders();

    var path = exchange.getRequestPath();
    var requestUri = upstreamBaseUri.resolve(path);

    var requestHeaders = new ArrayList<HttpClient.Header>();
    for (var h : headers) {
      var name = h.getHeaderName().toString();
      for (var v : h) {
        requestHeaders.add(new HttpClient.Header(name, v));
      }
    }

    return new HttpClient.Request(requestUri, method, requestHeaders, body);
  }
}
