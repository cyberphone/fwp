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

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * TBD
 *
 */
public class MerchantServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(MerchantServlet.class.getName());

    private static final long serialVersionUID = 1L;
    
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String fwpAssertion = request.getParameter(FWPWalletCore.FWP_ASSERTION);
        if (fwpAssertion == null) {
            FWPWalletCore.failed("Missing FWP assertion");
            return;
        }
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='esad'>" +
            "<input type='hidden' name='" + FWPWalletCore.FWP_ASSERTION +
            "' value='")
        .append(fwpAssertion)
        .append(
            "'/>" +
            "</form>" +

            "<div class='header'>Back to Merchant</div>" +

            "<div style='display:flex;justify-content:center;margin-top:15pt'>" +
              "<div class='comment'>" +
              "This part is still to be written..." +
              "<div style='margin-top:0.4em'>Thanx for testing anyway!</div>" +
              "</div>" +
            "</div>");
/*
            
            "<div style='display:flex;justify-content:center'>" +
              "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
              "Next Step - Encrypt Authorization" +
              "</div>" +
            "</div>" +

            "<div class='staticbox'>")
        .append(HTML.encode(CBORObject.decode(
                    Base64.getUrlDecoder().decode(fwpAssertion)).toString(), true)
                .replace("9:", 
                        "<span style='color:grey'>// The platform data is " +
                          "currently not authentic</span><br>&nbsp;&nbsp;9:"))
        .append(
            "</div>");
*/
        HTML.standardPage(response, FWPWalletCore.GO_HOME_JAVASCRIPT, html);
    }

}
