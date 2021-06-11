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
import java.io.InputStream;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;

import javax.sql.DataSource;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.fwp.FWPElements;

import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;

import org.webpki.webutil.InitPropertyReader;

public class FWPService extends InitPropertyReader implements ServletContextListener {

    static Logger logger = Logger.getLogger(FWPService.class.getName());

    static String sampleSignature;
    
    static String sampleJsonForHashing;
    
    static String samplePublicKey;
    
    static String sampleKeyConversionKey;

    static String keyDeclarations;
    
    static DataSource jdbcDataSource;
    
    static JSONObjectWriter samplePaymentRequest;
    
    static String samplePayeeHostname = "spaceshop.com";

    static boolean logging;

    byte[] getEmbeddedResource(String name) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(name);
        if (is == null) {
            throw new IOException("Resource fail for: " + name);
        }
        return ArrayUtil.getByteArrayFromInputStream(is);
    }
    
    String getEmbeddedResourceString(String name) throws IOException {
        return new String(getEmbeddedResource(name), "utf-8").trim();
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        initProperties(event);
        CustomCryptoProvider.forcedLoad(false);
        try {

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Logging?
            /////////////////////////////////////////////////////////////////////////////////////////////
            logging = getPropertyBoolean("logging");
            
            samplePaymentRequest = new JSONObjectWriter()
                    .setString(FWPElements.JSON_PR_PAYEE, "Space Shop")
                    .setString(FWPElements.JSON_PR_ID, "7040566321")
                    .setString(FWPElements.JSON_PR_AMOUNT, "435.00")
                    .setString(FWPElements.JSON_PR_CURRENCY, "EUR");
 
            ////////////////////////////////////////////////////////////////////////////////////////////
            // Database
            ////////////////////////////////////////////////////////////////////////////////////////////
            Context initContext = new InitialContext();
            Context envContext  = (Context)initContext.lookup("java:/comp/env");
            jdbcDataSource = (DataSource)envContext.lookup("jdbc/FWP");
            DataBaseOperations.testConnection();
            
            logger.info("FWP Demo Successfully Initiated");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
        }
    }
}
