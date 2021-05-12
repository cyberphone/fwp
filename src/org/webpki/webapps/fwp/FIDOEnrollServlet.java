/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webapps.fwp;

import java.io.IOException;

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

import org.webpki.webutil.ServletUtil;

public class FIDOEnrollServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    static final String HTTP_PRAGMA              = "Pragma";
    static final String HTTP_EXPIRES             = "Expires";
    static final String HTTP_ACCEPT_HEADER       = "Accept";
    static final String HTTP_CONTENT_TYPE_HEADER = "Content-Type";

    static final String JSON_CONTENT_TYPE        = "application/json";

    static Logger logger = Logger.getLogger(FIDOEnrollServlet.class.getName());

    static JSONObjectReader getJSON(HttpServletRequest request) throws IOException {
        if (!request.getContentType().equals("application/json")) {
            logger.log(Level.SEVERE, "JSON MIME type expected");
            throw new IOException("Unexpected MIME type:" + request.getContentType());
        }
        JSONObjectReader parsedJson = JSONParser.parse(ServletUtil.getData(request));
  //      if (FWPService.logging) {
            logger.info("Received: " + parsedJson.toString());
  //      }
        return parsedJson;
    }

    static void returnJSON(HttpServletResponse response, JSONObjectWriter json) throws IOException {
//        if (FWPService.logging) {
            logger.info("To be returned: " + json.toString());
//        }
        byte[] rawData = json.serializeToBytes(JSONOutputFormats.NORMALIZED);
        response.setContentType(JSON_CONTENT_TYPE);
        response.setHeader(HTTP_PRAGMA, "No-Cache");
        response.setDateHeader(HTTP_EXPIRES, 0);
        // Chunked data seems unnecessary here
        response.setContentLength(rawData.length);
        ServletOutputStream serverOutputStream = response.getOutputStream();
        serverOutputStream.write(rawData);
        serverOutputStream.flush();
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the input data
            JSONObjectReader parsedJson = getJSON(request);
            JSONObjectWriter result = new JSONObjectWriter();
            if (parsedJson.getString("yes").contains("again")) {
                HttpSession session = request.getSession(false);
                if (session != null && session.getAttribute("login") != null) {
        String temp = parsedJson.getString("name");
        if (temp.equals("bad")) throw new IOException(temp);

                    logger.info("Yes Set-Cookie");
                    Cookie walletCookie = new Cookie(EnrollServlet.WALLET_COOKIE,"data");
                    walletCookie.setMaxAge(10000000);
                    walletCookie.setSecure(true);
                    response.addCookie(walletCookie);
                    result.setBoolean("success", true);
                } else {
                    logger.info("NO SESSION");
                    result.setBoolean("success", false);
                }
            } else {
                Thread.sleep(2000);
                HttpSession session = request.getSession(true);
                session.setAttribute("login", "yes");
                result.setBoolean("success", true);
            }
            returnJSON(response, result);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

}
