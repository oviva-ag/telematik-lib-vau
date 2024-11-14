package com.oviva.telematik.vau.httpclient;

import java.net.URI;
import java.util.List;

/** Very basic interface for an HttpClient */
public interface HttpClient {

  Response call(Request req);

  record Request(URI uri, String method, List<Header> headers, byte[] body) {}

  record Response(int status, List<Header> headers, byte[] body) {}

  record Header(String name, String value) {}

  class HttpException extends RuntimeException {
    public HttpException(String message) {
      super(message);
    }

    public HttpException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
