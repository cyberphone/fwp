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
import java.io.PrintWriter;

import java.util.logging.Logger;
import java.util.logging.Level;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.fwp.FWPCrypto;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

/**
 * This Servlet creates Signed Authorization Data (SAD).
 *
 */
public class FIDOPayServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
   
    static Logger logger = Logger.getLogger(FIDOPayServlet.class.getName());

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            // Get the input (request) data.
            JSONObjectReader requestJson = WalletCore.getJSON(request);
                
            // Get the Authorization Data (AD).
            byte[]unsignedAssertion = requestJson.getBinary(WalletCore.FWP_AD);

            // Get the associated FIDO/WebAuthn assertion elements.
            byte[] clientDataJSON = requestJson.getBinary(FWPCrypto.CLIENT_DATA_JSON);
            byte[] authenticatorData = requestJson.getBinary(FWPCrypto.AUTHENTICATOR_DATA);
            byte[] signature = requestJson.getBinary(FWPCrypto.SIGNATURE);
            
            // Add the assertion elements creating a complete SAD object and return it.
            WalletCore.returnJSON(response, new JSONObjectWriter()
                                        .setBinary(WalletCore.FWP_SAD,
                                                   FWPCrypto.addSignature(unsignedAssertion,
                                                                          clientDataJSON,
                                                                          authenticatorData,
                                                                          signature)));

        } catch (Exception e) {
            String message = e.getMessage();
            logger.log(Level.SEVERE, WalletCore.getStackTrace(e, message));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            PrintWriter writer = response.getWriter();
            writer.print(message);
            writer.flush();
        }
    }
}
