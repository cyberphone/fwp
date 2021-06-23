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

import java.security.GeneralSecurityException;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.ArrayList;

import java.util.logging.Logger;

import org.webpki.crypto.HashAlgorithms;

public class DataBaseOperations {

    static Logger logger = Logger.getLogger(DataBaseOperations.class.getCanonicalName());
    
    static void testConnection() throws SQLException {
        try (Connection connection = WalletService.jdbcDataSource.getConnection();) { }
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Create (or recreate) user and give it some payment credentials as well                     //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void initiateUserAccount(String userId,
                                    String cardHolder,
                                    String credentialId,
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
            stmt.setString(3, credentialId);
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

    static class CoreClientData {
        String credentialId;
        byte[] cosePublicKey;
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
                return null;
            }
            CoreClientData coreClientData = new CoreClientData();
            coreClientData.credentialId = credentialId;
            coreClientData.cosePublicKey = stmt.getBytes(2);
            coreClientData.cardHolder = stmt.getString(3);
            return coreClientData;
        }
    }
    
    static class VirtualCard {
        String credentialId;
        byte[] publicKey;
        String serialNumber;
        String accountId;
        String paymentMethod;
        
        VirtualCard(String credentialId, 
                    byte[] cosePublicKey, 
                    String serialNumber, 
                    String accountId,
                    String paymentMethod) {
            this.credentialId = credentialId;
            this.publicKey = cosePublicKey;
            this.serialNumber = serialNumber;
            this.accountId = accountId;
            this.paymentMethod = paymentMethod;
        }
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // FIDO Web Pay: Get our enrolled virtual cards if there are any                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static ArrayList<VirtualCard> getVirtualCards(String userId, Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
        ArrayList<VirtualCard> virtualCards = new  ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(
                "SELECT USERS.CredentialId, USERS.PublicKey, PAYMENT_CARDS.SerialNumber, " +
                "PAYMENT_CARDS.AccountId, PAYMENT_CARDS.PaymentMethod FROM " +
                "USERS INNER JOIN PAYMENT_CARDS ON " +
                "USERS.UserId = PAYMENT_CARDS.UserId WHERE USERS.UserId = ?;");) {
            stmt.setString(1, userId);
            try (ResultSet rs = stmt.executeQuery();) {
                if (rs.next()) {
                    virtualCards.add(new VirtualCard(rs.getString(1),
                                                     rs.getBytes(2), 
                                                     String.valueOf(rs.getInt(3)),
                                                     rs.getString(4),
                                                     rs.getString(5)));
                }
            }
        }
        return virtualCards;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // FIDO login: Verify that the key hash of the public key matches the user Id                 //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static void authenticate(String userId, byte[] rawPublicKey, Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
/*
        CREATE PROCEDURE AuthenticateSP (OUT p_Status INT,
                                         IN p_UserId CHAR(36),
                                         IN p_S256KeyHash BINARY(32))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call AuthenticateSP(?,?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.INTEGER);
            stmt.setString(2, userId);
            stmt.setBytes(3, HashAlgorithms.SHA256.digest(rawPublicKey));
            stmt.execute();
            switch (stmt.getInt(1)) {
                case 0:
                    return;
                case 1:
                    throw new GeneralSecurityException("No such user: " + userId);
                default:
                    throw new GeneralSecurityException("Non-matching key hash");
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // FIDO Web Pay: Verify that the account related data matches                                 //
    ////////////////////////////////////////////////////////////////////////////////////////////////
    static String authorize(String accountId,
                            String serialNumber,
                            byte[] rawPublicKey,
                            Connection connection)
            throws IOException, SQLException, GeneralSecurityException {
/*
        CREATE PROCEDURE AuthorizeSP (OUT p_Status INT,
                                      OUT p_UserId CHAR(36),
                                      IN p_AccountId VARCHAR(30),
                                      IN p_SerialNumber INT,
                                      IN p_S256KeyHash BINARY(32))
*/
        try (CallableStatement stmt = 
                connection.prepareCall("{call AuthorizeSP(?,?,?,?,?)}");) {
            stmt.registerOutParameter(1, java.sql.Types.INTEGER);
            stmt.registerOutParameter(2, java.sql.Types.CHAR);
            stmt.setString(3, accountId);
            stmt.setInt(4, Integer.valueOf(serialNumber));
            stmt.setBytes(5, HashAlgorithms.SHA256.digest(rawPublicKey));
            stmt.execute();
            switch (stmt.getInt(1)) {
                case 0:
                    return stmt.getString(2);
                case 1:
                    throw new GeneralSecurityException("No such card: " + serialNumber);
                case 2:
                    throw new GeneralSecurityException("No such account: " + accountId);
                default:
                    throw new GeneralSecurityException("Non-matching key hash");
            }
        }
    }
}
