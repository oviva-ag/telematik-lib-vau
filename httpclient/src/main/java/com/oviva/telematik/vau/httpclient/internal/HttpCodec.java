package com.oviva.telematik.vau.httpclient.internal;

import com.oviva.telematik.vau.httpclient.HttpClient;
import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class HttpCodec {

  private static final String HTTP_VERSION = "HTTP/1.1";
  private static final byte[] CRLF = "\r\n".getBytes(StandardCharsets.UTF_8);

  private static final Set<String> unsupportedHeaders = Set.of("transfer-coding", "TE");
  private static final Set<String> skipHeaders = Set.of("content-length");
  private static final Set<String> supportedMethods = Set.of("GET", "POST", "PUT", "DELETE");
  private static final Pattern HEADER_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9-_]+");
  private static final Pattern HEADER_VALUE_PATTERN =
      Pattern.compile("[a-zA-Z0-9-_ :;.,/\"'?!(){}\\[\\]@<>=+#$&`|~^%*]+");

  public static HttpClient.Response decode(byte[] bytes) {

    try (var reader =
        new BufferedReader(new StringReader(new String(bytes, StandardCharsets.UTF_8)))) {

      // HTTP/1.1 404 Not Found
      var statusLine = reader.readLine();
      var status = parseStatusLine(statusLine);
      var headers = parseHeaders(reader);

      var baos = new ByteArrayOutputStream();
      try (var bodyReader = reader;
          var w = new OutputStreamWriter(baos)) {
        bodyReader.transferTo(w);
      }

      var body = baos.toByteArray();
      if (body.length != headers.contentLength()) {
        //FIXME: RISE does not honor this!!!
//        throw new HttpClient.HttpException(
//            "content-length '%d' != actual length '%d'"
//                .formatted(headers.contentLength(), body.length));
      }

      return new HttpClient.Response(status, headers.all(), body);

    } catch (IOException e) {
      throw new HttpClient.HttpException("failed to decode response", e);
    }
  }

  private static ResponseHeaders parseHeaders(BufferedReader reader) {

    var headers = new ArrayList<HttpClient.Header>();
    var contentLength = -1;

    try {
      var line = reader.readLine();
      while (line != null) {
        if (line.isEmpty()) {
          contentLength = contentLength == -1 ? 0 : contentLength;
          return new ResponseHeaders(headers, contentLength);
        }

        var h = parseHeader(line);
        if ("content-length".equals(h.name())) {

          // we've already set the content-length!
          if (contentLength >= 0) {
            throw new HttpClient.HttpException("content-length set more than once!");
          }

          try {
            var maybeContentLength = Integer.parseInt(h.value());
            if (maybeContentLength >= 0) {
              contentLength = maybeContentLength;
            } else {
              throw new HttpClient.HttpException(
                  "invalid content-length: '%d'".formatted(maybeContentLength));
            }
          } catch (NumberFormatException e) {
            throw new HttpClient.HttpException("invalid content-length: '%s'".formatted(h.value()));
          }
        }

        line = reader.readLine();
      }
    } catch (IOException e) {
      throw new HttpClient.HttpException("failed to parse headers", e);
    }

    throw new IllegalStateException("unreachable");
  }

  private static HttpClient.Header parseHeader(String line) {
    var splits = line.split(":", 2);
    if (splits.length != 2) {
      throw new HttpClient.HttpException("invalid header line: '%s'".formatted(line));
    }

    var name = canonicalizeHeaderName(splits[0].trim());
    var value = splits[1].trim();
    validateHeader(name, value);
    return new HttpClient.Header(name, value);
  }

  private record ResponseHeaders(List<HttpClient.Header> all, int contentLength) {}

  private static int parseStatusLine(String statusLine) {
    var splits = statusLine.split(" ", 3);
    if (splits.length != 3) {
      throw new HttpClient.HttpException("invalid status line: '%s'".formatted(statusLine));
    }

    try {
      return Integer.parseInt(splits[1]);
    } catch (NumberFormatException e) {
      throw new HttpClient.HttpException(
          "invalid status line, failed to parse status code: '%s'".formatted(statusLine));
    }
  }

  public static byte[] encode(HttpClient.Request req) {

    validateRequest(req);

    var buf = ByteBuffer.allocate(16 * 1024); // 2^14 = 16kb

    addRequestLine(buf, req.uri(), req.method());
    writeHeaders(buf, req);
    writeBody(buf, req.body());

    return toBytes(buf);
  }

  private static byte[] toBytes(ByteBuffer buf) {
    var backingBuffer = buf.array();
    var bytes = new byte[buf.position()];
    System.arraycopy(backingBuffer, 0, bytes, 0, buf.position());
    return bytes;
  }

  private static void writeBody(ByteBuffer buf, byte[] body) {
    if (body == null || body.length == 0) {
      return;
    }
    buf.put(body);
  }

  private static void writeHeaders(ByteBuffer buf, HttpClient.Request req) {
    addHeaders(buf, req.headers());
    addContentLength(buf, req.body() != null ? req.body().length : 0);
    // TODO: should we add host header?

    buf.put(CRLF);
  }

  private static void addRequestLine(ByteBuffer buf, URI uri, String method) {

    // e.g. "GET /here/is/my/path HTTP/1.1\r\n"
    buf.put(asUtf8(method))
        .put((byte) ' ')
        .put(asUtf8(uri.getPath()))
        .put((byte) ' ')
        .put(asUtf8(HTTP_VERSION))
        .put(CRLF);
  }

  private static void addContentLength(ByteBuffer buf, int length) {
    if (length <= 0) {
      return;
    }

    buf.put(asUtf8("content-length: ")).put(asUtf8(Integer.toString(length))).put(CRLF);
  }

  private static void addHeaders(ByteBuffer buf, List<HttpClient.Header> headers) {
    if (headers == null) {
      return;
    }

    for (HttpClient.Header h : headers) {
      var name = canonicalizeHeaderName(h.name());
      if (skipHeaders.contains(name)) {
        continue;
      }
      buf.put(asUtf8(name)).put(asUtf8(": ")).put(asUtf8(h.value())).put(CRLF);
    }
  }

  private static void validateRequest(HttpClient.Request req) {
    if (req == null) {
      throw new HttpClient.HttpException("invalid request: 'null'");
    }
    validateMethod(req.method());

    if (req.uri() == null) {
      throw new HttpClient.HttpException("invalid uri: 'null'");
    }

    if (req.headers() != null) {
      for (HttpClient.Header h : req.headers()) {
        validateHeader(h.name(), h.value());
      }
    }
  }

  private static void validateMethod(String method) {
    if (method == null || (!supportedMethods.contains(method))) {
      throw new HttpClient.HttpException("unsupported method: '%s'".formatted(method));
    }
  }

  private static void validateHeader(String name, String value) {
    name = canonicalizeHeaderName(name);
    if (unsupportedHeaders.contains(name)) {
      throw new HttpClient.HttpException("unsupported header: '%s'".formatted(name));
    }
    if (!HEADER_NAME_PATTERN.matcher(name).matches()) {
      throw new HttpClient.HttpException("invalid header name: '%s'".formatted(name));
    }

    if (!HEADER_VALUE_PATTERN.matcher(value).matches()) {
      throw new HttpClient.HttpException("invalid header value: '%s'".formatted(value));
    }
  }

  private static String canonicalizeHeaderName(String name) {
    // https://www.rfc-editor.org/rfc/rfc9110.html#name-header-fields
    return name.toLowerCase(Locale.US);
  }

  private static byte[] asUtf8(String s) {
    if (s == null) {
      return new byte[0];
    }
    return s.getBytes(StandardCharsets.UTF_8);
  }
}
