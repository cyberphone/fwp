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

import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORMap;

/**
 * This is a temporary payment application.
 *
 */
public class FinalizeServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(FinalizeServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            String fwpAssertionB64U = request.getParameter(FWPCommon.FWP_ASSERTION);
            if (fwpAssertionB64U == null) {
                FWPCommon.failed("FWP assertion missing");
            }
            
            CBORMap encrypted = 
                    new CBORAsymKeyEncrypter(FWPService.issuerEncryptionKey.getPublic(),
                                             FWPService.issuerKeyEncryptionAlgorithm,
                                             FWPService.issuerContentEncryptionAlgorithm)
                .setKeyId(FWPService.issuerKeyId).encrypt(
                        Base64.getUrlDecoder().decode(fwpAssertionB64U));

            StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='assertion'>" +
                "<input type='hidden' name='" + FWPCommon.FWP_ASSERTION + 
                "' value='")
            .append(Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted.encode()))
            .append(
                "'/>" +
                "</form>" +

                "<div class='header'>The Completed FWP Assertion</div>" +
        
                "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
                  "<div class='comment'>" +
                     "The following is what the browser (FWP implementation) generated internally. " +
                     "However, we are not done yet!" +
                  "</div>" +
                "</div>" +
                "<div style='display:flex;justify-content:center'>" +
                  "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                    "Next step - Finalize Assertion" +
                  "</div>" +
                "</div>" +
                "<div style='display:flex;align-items:center;flex-direction:column;margin-top:15pt'>" +
                    "<div class='ctbl'>")
            .append(HTML.encode(encrypted.toString(), true))
            .append("</div>" +
                "</div>");
        
            HTML.standardPage(response, FWPCommon.GO_HOME_JAVASCRIPT, html);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}
