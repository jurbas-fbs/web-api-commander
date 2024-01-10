package org.reso.auth;

import org.apache.http.Header;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.olingo.client.core.http.AbstractHttpClientFactory;
import org.apache.olingo.commons.api.http.HttpMethod;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;

/**
 * Extends AbstractHttpClientFactory with one that can accept tokens passed in to make requests.
 */
public class TokenHttpClientFactory extends AbstractHttpClientFactory {
  private static final Logger LOG = LogManager.getLogger(TokenHttpClientFactory.class);
  String token;
  HttpClientConnectionManager connectionManager = null;

  /**
   * Constructor for use with tokens.
   *
   * @param token the token to be used for server requests.
   */
  public TokenHttpClientFactory(String token) {
    this.token = token;
  }

  @Override
  public CloseableHttpClient create(final HttpMethod method, final URI uri) {
    BasicHeader authHeader = new BasicHeader("Authorization", "Bearer " + token);
    List<Header> headers = new ArrayList<>();
    headers.add(authHeader);

    connectionManager = new BasicHttpClientConnectionManager(trusted_registry());

    return HttpClientBuilder.create()
        .setUserAgent(USER_AGENT)
        .setDefaultHeaders(headers)
        .setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build())
        .setConnectionManager(connectionManager)
        .build();
  }

  @Override
  public void close(final HttpClient httpClient) {
    try {
      connectionManager.shutdown();
    } catch (Exception ex) {
      LOG.error(ex.toString());
    }
  }

  public Registry<ConnectionSocketFactory> trusted_registry() {
    TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{
      new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
          return null;
        }
        public void checkClientTrusted(
          X509Certificate[] certs, String authType) {
        }
        public void checkServerTrusted(
          X509Certificate[] certs, String authType) {
        }
      }
    };

    try {
      SSLContext ctx = SSLContext.getInstance("TLS");
      ctx.init(null, trustAllCerts, null);
      SSLConnectionSocketFactory ssf = new org.apache.http.conn.ssl.SSLConnectionSocketFactory(ctx, org.apache.http.conn.ssl.SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
      return RegistryBuilder.<ConnectionSocketFactory>create().register("https", ssf).build();
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }
}
