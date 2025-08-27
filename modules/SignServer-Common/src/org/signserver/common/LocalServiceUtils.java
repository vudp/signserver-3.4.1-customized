/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

/**
 *
 * @author mobileid
 */
public class LocalServiceUtils {

    private static final Logger LOG = Logger.getLogger(LocalServiceUtils.class);

    public static byte[] downloadCrl(String crlUrl) {
        int crlRetry = 3;
        byte[] crlData = null;

        crlUrl = checkRedirectUrl(crlUrl);

        while (crlRetry > 0) {
            try {
                crlData = getUrl(crlUrl);
                break;
            } catch (Exception e) {
                e.printStackTrace();
                --crlRetry;
                LOG.error("Failed to download CRL. Retry " + crlRetry);
            }
        }
        return crlData;
    }

    private static byte[] getUrl(String crlUrl) throws Exception {
        URL url = new URL(crlUrl);
        URLConnection con;
        boolean isHTTPS = false;
        try {
            con = url.openConnection();
            if (url.toString().contains("https://")) {
                isHTTPS = true;
                ((HttpsURLConnection) con).setHostnameVerifier(new HostnameVerifier() {

                    @Override
                    public boolean verify(String string, SSLSession ssls) {
                        return true;
                    }
                });
            }
        } catch (IOException e) {
            throw new Exception(
                    "Error opening connection for fetching CRL from address : "
                    + url.toString(), e);
        }
        con.setConnectTimeout(5000);
        con.setDoOutput(true);
        OutputStream out = con.getOutputStream();
        boolean redirect = false;
        int status;
        if (isHTTPS) {
            status = ((HttpsURLConnection) con).getResponseCode();
        } else {
            status = ((HttpURLConnection) con).getResponseCode();
        }
        if (status != HttpURLConnection.HTTP_OK) {
            if (status == HttpURLConnection.HTTP_MOVED_TEMP
                    || status == HttpURLConnection.HTTP_MOVED_PERM
                    || status == HttpURLConnection.HTTP_SEE_OTHER) {
                redirect = true;
            }
        }

        if (redirect) {
            String newUrl = con.getHeaderField("Location");
            return getUrl(newUrl);
        }

        if (status != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Unexpected HTTP code while calling CRL: " + status);
        }
        InputStream in = (InputStream) con.getContent();
        return IOUtils.toByteArray(in);
    }

    public static byte[] checkOcsp(String ocspUrl, byte[] requestData) {
        int ocspRetry = 3;
        byte[] ocspResp = null;

        ocspUrl = checkRedirectUrl(ocspUrl);

        while (ocspRetry > 0) {
            try {
                ocspResp = postUrl(ocspUrl, requestData);
                break;
            } catch (Exception e) {
                e.printStackTrace();
                --ocspRetry;
                LOG.error("Failed to reuqest OCSP. Retry " + ocspRetry);
            }
        }
        return ocspResp;
    }

    private static String checkRedirectUrl(String url) {
        try {
            URL obj = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) obj.openConnection();
            conn.setReadTimeout(5000);
            conn.addRequestProperty("Accept-Language", "en-US,en;q=0.8");
            conn.addRequestProperty("User-Agent", "Mozilla");
            conn.addRequestProperty("Referer", "google.com");
            boolean redirect = false;
            // normally, 3xx is redirect
            int status = conn.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                if (status == HttpURLConnection.HTTP_MOVED_TEMP
                        || status == HttpURLConnection.HTTP_MOVED_PERM
                        || status == HttpURLConnection.HTTP_SEE_OTHER) {
                    redirect = true;
                }
            }
            if (redirect) {
                String newUrl = conn.getHeaderField("Location");
                String cookies = conn.getHeaderField("Set-Cookie");
                conn = (HttpURLConnection) new URL(newUrl).openConnection();
                conn.setRequestProperty("Cookie", cookies);
                conn.addRequestProperty("Accept-Language", "en-US,en;q=0.8");
                conn.addRequestProperty("User-Agent", "Mozilla");
                conn.addRequestProperty("Referer", "google.com");
                url = newUrl;
                LOG.info("URL redirecting to " + newUrl);
            }
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error("Error while checking redirect URL");
        }
        return url;
    }

    private static byte[] postUrl(String ocspUrl, byte[] data) throws Exception {
        URL url = new URL(ocspUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        con.setRequestProperty("Accept", "application/ocsp-response");
        con.setConnectTimeout(5000);
        con.setDoOutput(true);
        OutputStream out = con.getOutputStream();
        DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
        dataOut.write(data);
        dataOut.flush();
        dataOut.close();

        boolean redirect = false;
        int status = con.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            if (status == HttpURLConnection.HTTP_MOVED_TEMP
                    || status == HttpURLConnection.HTTP_MOVED_PERM
                    || status == HttpURLConnection.HTTP_SEE_OTHER) {
                redirect = true;
            }
        }

        if (redirect) {
            String newUrl = con.getHeaderField("Location");
            return postUrl(newUrl, data);
        }

        if (status != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Unexpected HTTP code while calling OCSP: " + status);
        }
        InputStream in = (InputStream) con.getContent();
        return IOUtils.toByteArray(in);
    }
}
