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

import org.webpki.cbor.CBORObject;

/**
 * Receives and shows the Signed Authorization Data (SAD).
 *
 */
public class SADServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(SADServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String signedAuthorizationB64U = request.getParameter(FWPWalletCore.FWP_SAD);
        if (signedAuthorizationB64U == null) {
            FWPWalletCore.failed("Missing signed authorization data");
            return;
        }
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='esad'>" +
            "<input type='hidden' name='" + FWPWalletCore.FWP_SAD +
            "' value='")
        .append(signedAuthorizationB64U)
        .append(
            "'/>" +
            "<input type='hidden' name='" + FWPWalletCore.FWP_ACCOUNT_DATA + 
            "' value='")
        .append(request.getParameter(FWPWalletCore.FWP_ACCOUNT_DATA))
        .append(
            "'/>" +
            "</form>" +

            "<div class='header'>Signed Authorization Data (SAD)</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>")
        .append(ADServlet.sectionReference("seq-4.3"))
        .append(
              "The FIDO signature has now been added. " +
              "<div style='margin-top:0.4em'>Since FWP is a <i>privacy-centric scheme</i>, " +
              "the data is not yet ready for release.</div>" +
              "</div>" +
            "</div>" +
            
            "<div style='display:flex;justify-content:center'>" +
              "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
              "Next Step - Encrypt Authorization" +
              "</div>" +
            "</div>" +

            "<div class='staticbox'>")
        .append(HTML.encode(CBORObject.decode(
                    Base64.getUrlDecoder().decode(signedAuthorizationB64U)).toString(), true)
                .replace("9:&nbsp;", 
                        "<span style='color:grey;word-break:normal'>// The platform data is " +
                          "currently not authentic</span><br>&nbsp;&nbsp;9:&nbsp;"))
        .append(
            "</div>");
        HTML.standardPage(response, FWPWalletCore.GO_HOME_JAVASCRIPT, html);
    }

}
