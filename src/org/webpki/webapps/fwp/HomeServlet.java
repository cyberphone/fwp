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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final String BUTTONS_ID = "buttons";
    private static final String FAILED_ID  = "failed";

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response,
                          Actors.SITE,
                          "window.addEventListener('load', function(event) {\n" +
                          "  if (!window.PublicKeyCredential) {\n" +
                          "    document.getElementById('" + BUTTONS_ID +
                                                       "').style.display = 'none';\n" +
                          "    document.getElementById('" + FAILED_ID + 
                                                       "').style.display = 'block';\n" +
                          "  }\n" +
                          "});\n",
                          new StringBuilder(
            "<div class='header'>FIDO&#xae; Web Pay (FWP) Demo</div>" +

            "<div style='padding-top:15pt'>This site permits testing and debugging " +
                "a scheme for a <i>universal payment authorization system</i> based on FIDO2. " + 
                "Due to the lack of built-in browser support, the &quot;Wallet&quot; UI is " +
                "currently implemented as a Web emulator." +
                "<p>Note that you can always return to the main menu by clicking " +
                "<span style='position:relative;top:0.3em'>" +
                "<img src='images/thelab.svg' style='width:4em' alt='the lab'/></span></p>" +
            "</div>" +

            "<div id='" + BUTTONS_ID + "' style='display:flex;justify-content:center'>" +
              "<table>" +

                "<tr><td><div class='multibtn' onclick=\"document.location.href='buy'\" >" +
                    "Buy Something!" +
                "</div></td></tr>" +
    
                "<tr><td><div class='multibtn' onclick=\"document.location.href='enroll'\" >" +
                    "Enroll Payment Cards..." +
                "</div></td></tr>" +

                WalletAdminServlet.WALLET_ADMIN_BUTTON +
              
                "<tr><td><div class='multibtn' onclick=\"document.location.href='login'\" >" +
                    "&quot;WebAuthn&quot; Login..." +
                "</div></td></tr>" +

              "</table>" +
            "</div>" +

            "<div id='" + FAILED_ID + "' class='errorText'>" +
                "Your browser does not support FIDO2/WebAuthn" +
            "</div>" +

            "<div class='sitefooter'>Trademarks: FIDO is a trademark of the FIDO Alliance.<br>" +
                "Privacy/security notice: this test site depends on a local " +
                "persistent cookie." +
            "</div>"));
    }
}
