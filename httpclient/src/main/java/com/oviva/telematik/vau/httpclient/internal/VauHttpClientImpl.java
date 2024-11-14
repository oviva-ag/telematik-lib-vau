package com.oviva.telematik.vau.httpclient.internal;

import com.oviva.telematik.vau.httpclient.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** This is a rather basic HTTP/1.1 client specifically to run HTTP over a VAU tunnel. */
public class VauHttpClientImpl implements HttpClient {

  private static final Logger log = LoggerFactory.getLogger(VauHttpClientImpl.class);

  // A_24677 & A_22470
  private final String X_USERAGENT = "Oviva/0.0.1";

  private final Header X_USERAGENT_HEADER = new Header("X-UserAgent", X_USERAGENT);

  private final Connection conn;

  public VauHttpClientImpl(Connection conn) {
    this.conn = conn;
  }

  @Override
  public Response call(Request req) {
    // https://datatracker.ietf.org/doc/html/rfc2616

    var headers = new ArrayList<Header>();
    if (req.headers() != null) {
      headers.addAll(req.headers());
    }

    headers.add(X_USERAGENT_HEADER);

    req = new Request(req.uri(), req.method(), headers, req.body());

    var requestBytes = HttpCodec.encode(req);

    if (log.isDebugEnabled()) {
      log.atDebug().log(
          "outgoing http request in VAU tunnel: \n===\n{}\n===",
          new String(requestBytes, StandardCharsets.UTF_8));
    }

    var rxBytes = conn.call(requestBytes);

    if (log.isDebugEnabled()) {
      log.atDebug().log(
          "incoming http response in VAU tunnel: \n===\n{}\n===",
          new String(rxBytes != null ? rxBytes : new byte[0], StandardCharsets.UTF_8));
    }

    return HttpCodec.decode(rxBytes);
  }
}
