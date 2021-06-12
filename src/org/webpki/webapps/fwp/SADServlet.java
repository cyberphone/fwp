/*
 *  Copyright 2018-2021 WebPKI.org (http://webpki.org).
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

import java.util.Base64;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.fwp.FWPCrypto;
import org.webpki.json.JSONOutputFormats;

/**
 * This is a temporary payment application.
 *
 */
public class SADServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(SADServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String signedAuthorizationB64U = request.getParameter(FWPCommon.FWP_SAD);
        if (signedAuthorizationB64U == null) {
            FWPCommon.failed("Missing signed authorization data");
            return;
        }
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='esad'>" +
            "<input type='hidden' name='" + FWPCommon.FWP_SAD +
            "' value='")
        .append(signedAuthorizationB64U)
        .append(
            "'/>" +
            "<input type='hidden' name='" + FWPCommon.FWP_ACCOUNT_DATA + 
            "' value='")
            .append(request.getParameter(FWPCommon.FWP_ACCOUNT_DATA))
            .append(
            "'/>" +
            "</form>" +

            "<div class='header'>Signed Authorization Data (SAD)</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
                  "Encrypt now" +
              "</div>" +
            "</div>" +
            
            "<div style='display:flex;justify-content:center'>" +
              "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                "Pay using FWP" +
              "</div>" +
            "</div>" +
            "<div style='display:flex;align-items:center;flex-direction:column;margin-top:15pt'>" +
                "<div class='ctbl'>")
        .append(HTML.encode(CBORObject.decode(
                    Base64.getUrlDecoder().decode(signedAuthorizationB64U)).toString(), true))
        .append("</div>" +
            "</div>");
        HTML.standardPage(response, FWPCommon.GO_HOME_JAVASCRIPT, html);
    }

}
