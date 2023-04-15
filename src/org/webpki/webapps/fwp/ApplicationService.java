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

import java.security.KeyPair;

import java.util.Base64;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;

import javax.sql.DataSource;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.cbor.CBORString;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.jose.JOSEKeyWords;

import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.UTF8;
import org.webpki.webutil.InitPropertyReader;

/**
 * A single service for the whole application?!  Yes, this is an emulator, not a product :)
 */
public class ApplicationService extends InitPropertyReader implements ServletContextListener {

    static Logger logger = Logger.getLogger(ApplicationService.class.getName());

    public static DataSource jdbcDataSource;
    
    static KeyPair issuerEncryptionKey;
    
    static CBORString issuerEncryptionKeyId = new CBORString("x25519:2021:01");
    
    static String issuerId = "https://mybank.fr/payment";
    
    static KeyEncryptionAlgorithms issuerKeyEncryptionAlgorithm = 
            KeyEncryptionAlgorithms.ECDH_ES_A256KW;

    static ContentEncryptionAlgorithms issuerContentEncryptionAlgorithm =
            ContentEncryptionAlgorithms.A256GCM;

    static String samplePayeeHostname = "spaceshop.com";

    static boolean logging;

    
    static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    static byte[] base64UrlDecode(String b64u) {
        return Base64.getUrlDecoder().decode(b64u);
    }

    byte[] getEmbeddedResource(String name) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(name);
        if (is == null) {
            throw new IOException("Resource fail for: " + name);
        }
        return ArrayUtil.getByteArrayFromInputStream(is);
    }
    
    String getEmbeddedResourceString(String name) throws IOException {
        return UTF8.decode(getEmbeddedResource(name)).trim();
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
            
            /////////////////////////////////////////////////////////////////////////////////////////////
            // Hard coded issuer data
            /////////////////////////////////////////////////////////////////////////////////////////////
            issuerEncryptionKey = JSONParser.parse(getEmbeddedResource("x25519privatekey.jwk"))
                   .removeProperty(JOSEKeyWords.KID_JSON).getKeyPair();

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Database
            /////////////////////////////////////////////////////////////////////////////////////////////
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
