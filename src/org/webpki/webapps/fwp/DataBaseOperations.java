/*
 *  Copyright 2015-2020 WebPKI.org (http://webpki.org).
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

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;

import java.util.logging.Logger;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;

import org.webpki.crypto.HashAlgorithms;

public class DataBaseOperations {

    static Logger logger = Logger.getLogger(DataBaseOperations.class.getCanonicalName());
    
    static void testConnection() throws SQLException {
        try (Connection connection = FWPService.jdbcDataSource.getConnection();) { }
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Create (or recreate) user and give it some payment credentials as well                     //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void initiateUserAccount(String userId,
                                    String cardHolder,
                                    String keyHandle,
                                    byte[] rawPublicKey,
                                    Connection connection)
            throws SQLException, IOException, GeneralSecurityException {
/*
        CREATE PROCEDURE InitiateUserAccountSP (IN p_UserId CHAR(36),
                                                IN p_CardHolder VARCHAR(50),
                                                IN p_CredentialId VARCHAR(100),
                                                IN p_PublicKey VARBINARY(300),
                                                IN p_S256KeyHash BINARY(32))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call InitiateUserAccountSP(?,?,?,?,?)}");) {
            stmt.setString(1, userId);
            stmt.setString(2, cardHolder);
            stmt.setString(3, keyHandle);
            stmt.setBytes(4, rawPublicKey);
            stmt.setBytes(5, HashAlgorithms.SHA256.digest(rawPublicKey));
            stmt.execute();
        }
    }

    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Delete user                                                                                //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void deletePaymentCards(String userId,
                                   Connection connection) throws SQLException {
/*
        CREATE PROCEDURE DeletePaymentCardsSP (IN p_UserId CHAR(36))
*/
        try (CallableStatement stmt = connection.prepareCall("{call DeletePaymentCardsSP(?)}");) {
            stmt.setString(1, userId);
            stmt.execute();
        }
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Check if the user (which may not exist) has payment cards                                  //
    ////////////////////////////////////////////////////////////////////////////////////////////////
   static boolean hasPaymentCards(String userId, Connection connection) throws SQLException {
/*
       CREATE PROCEDURE HasPaymentCardsSP (OUT p_Found BOOLEAN, IN p_UserId CHAR(36))

*/
        try (CallableStatement stmt = connection.prepareCall("{call HasPaymentCardsSP(?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.BOOLEAN);
            stmt.setString(2, userId);
            stmt.execute();
            return stmt.getBoolean(1);
        }
    }
   
   static class CoreClientData {
       String credentialId;
       PublicKey publicKey;
       String cardHolder;
   }


    ////////////////////////////////////////////////////////////////////////////////////////////////
    // WebAuthn on Android as well as FWP presume that the key handle (CredentialId) is known.    //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static CoreClientData getCoreClientData(String userId, Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
/*
    CREATE PROCEDURE GetCoreClientDataSP (OUT p_CredentialId VARCHAR(100),
                                          OUT p_PublicKey VARBINARY(300),
                                          OUT p_CardHolder VARCHAR(50),
                                          IN p_UserId CHAR(36))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call GetCoreClientDataSP(?,?,?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.VARCHAR);
            stmt.registerOutParameter(2, java.sql.Types.VARBINARY);
            stmt.registerOutParameter(3, java.sql.Types.VARCHAR);
            stmt.setString(4, userId);
            stmt.execute();
            String credentialId = stmt.getString(1);
            if (credentialId == null) {
                throw new IOException("Missing credentialId for user: " + userId);
            }
            CoreClientData coreClientData = new CoreClientData();
            coreClientData.credentialId = credentialId;
            coreClientData.publicKey = CBORPublicKey.decode(CBORObject.decode(stmt.getBytes(2)));
            coreClientData.cardHolder = stmt.getString(3);
            return coreClientData;
        }
    }
}
