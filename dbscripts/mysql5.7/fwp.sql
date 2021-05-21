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
 
 -- SQL Script for MySQL 5.7
--
-- root privileges are required!!!
--
-- Clear and create DB to begin with
--
DROP DATABASE IF EXISTS FWP;
CREATE DATABASE FWP CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE FWP;
--
-- Create our single user
--
DROP USER IF EXISTS fwp@localhost;
CREATE USER fwp@localhost IDENTIFIED BY 'foo123';
--
-- Give this user access
--
GRANT ALL ON FWP.* TO fwp@localhost;
GRANT SELECT ON mysql.proc TO fwp@localhost;
--
-- Create tables and stored procedures
--
-- #################################################
-- # This is a database for the FIDO Web Pay PoC   #
-- #                                               #
-- # It is only useful for the Web based PoC :-)   #
-- #################################################

/*=============================================*/
/*                   USERS                     *
/*=============================================*/

CREATE TABLE USERS (
                      
    -- Unique User ID.
    -- This ID is kept in the persistent cookie used by FWP Wallet emulator.
    -- Here using a UUID.
    
    UserId          CHAR(36)     NOT NULL UNIQUE, 


    -- Name on payment cards

    CardHolder      VARCHAR(50)  NOT NULL,
    
    
    -- FIDO CredentialId expressed as a Base64url-encoded string.
    --
    -- In a real-world FWP implementation this would be a part of the local
    -- FWP wallet database since a verifier does not need this information.
    -- However, in a server-oriented setting using the WebAuthn API the
    -- FIDO CredentialId must be known by the verifier.  

    CredentialId    VARCHAR(100) NOT NULL,


    -- The FWP wallet is obliged including the associated public key in
    -- assertions.  Here it is stored in the CBOR/COSE format.
    
    PublicKey       VARBINARY(300) NOT NULL,


    -- Authentication of FWP assertions is performed by verifying that 
    -- both the SHA256 of the public key and claimed UserId match.
    -- This is typically performed after having verified that the
    -- signature is valid.

    S256KeyHash     BINARY(32)   NOT NULL,

    Created         TIMESTAMP    NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Admin data
                                                                        
    PRIMARY KEY (UserId)
);


/*=============================================*/
/*                PAYMENT_CARDS                */
/*=============================================*/

CREATE TABLE PAYMENT_CARDS (

-- Note: a payment card holds an external representation of an Account ID
-- like an IBAN or Card Number

    SerialNumber   INT           NOT NULL  AUTO_INCREMENT,               -- Unique ID/Serial number

    UserId          CHAR(36)     NOT NULL,                               -- Owner

    AccountId       VARCHAR(30)  NOT NULL,                               -- Account Reference
    
    PaymentMethodUrl VARCHAR(50) NOT NULL,                               -- Payment method URL

    Created         TIMESTAMP    NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Admin data

    PRIMARY KEY (SerialNumber),
    FOREIGN KEY (UserId) REFERENCES USERS(UserId) ON DELETE CASCADE
);


DELIMITER //

-- Test code only called by this script
CREATE PROCEDURE ASSERT_TRUE (IN p_DidIt BOOLEAN,
                              IN p_Message VARCHAR(100))
  BEGIN
    IF p_DidIt = FALSE THEN
      SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = p_Message, MYSQL_ERRNO = 1001;
    END IF;
  END
//


CREATE PROCEDURE InitiateUserAccountSP (IN p_UserId CHAR(36),
                                        IN p_CardHolder VARCHAR(50),
                                        IN p_CredentialId VARCHAR(100),
                                        IN p_PublicKey VARBINARY(300),
                                        IN p_S256KeyHash BINARY(32))
  BEGIN
    -- To make it simple, clear previous entry...
    DELETE FROM USERS WHERE UserId = p_UserId;
    
    -- Create an entry with the same UserId
    INSERT INTO USERS(UserId, 
                      CardHolder,
                      CredentialId,
                      PublicKey,
                      S256KeyHash) 
        VALUES(p_UserId,
               p_CardHolder,
               p_CredentialId,
               p_PublicKey,
               p_S256KeyHash);
               
    -- Add payment cards...
    INSERT INTO PAYMENT_CARDS(UserId,
                              AccountId,
                              PaymentMethodUrl) 
        VALUES(p_UserId,
               "FR7630002111110020050014382",
               "https://bankdirect.com");
  END
//


CREATE PROCEDURE DeletePaymentCardsSP (IN p_UserId CHAR(36))
  BEGIN
    DELETE Target FROM PAYMENT_CARDS As Target
        INNER JOIN USERS ON USERS.UserId = Target.UserId
        WHERE USERS.UserId = p_UserId;
  END
//

CREATE PROCEDURE HasPaymentCardsSP (OUT p_Found BOOLEAN,
                                    IN p_UserId CHAR(36))
  BEGIN
    SET p_Found = EXISTS (SELECT * FROM USERS
        INNER JOIN PAYMENT_CARDS ON USERS.UserId = PAYMENT_CARDS.UserId
        WHERE USERS.UserId = p_UserId);
  END
//

CREATE PROCEDURE GetCoreClientDataSP (OUT p_CredentialId VARCHAR(100),
                                      OUT p_PublicKey VARBINARY(300),
                                      IN p_UserId CHAR(36))
  BEGIN
    SELECT CredentialId, PublicKey INTO p_CredentialId, p_PublicKey FROM USERS
        WHERE USERS.UserId = p_UserId;
  END
//

CREATE PROCEDURE AuthenticateSP (OUT p_Status INT,
                                 IN p_UserId CHAR(36),
                                 IN p_S256KeyHash BINARY(32))
  BEGIN
    DECLARE v_S256KeyHash BINARY(32);
    
    SELECT S256KeyHash INTO v_S256KeyHash FROM USERS
        WHERE USERS.UserId = p_UserId;
    IF v_S256KeyHash IS NULL THEN
      SET p_Status = 1;    -- No such users
    ELSEIF v_S256KeyHash <> p_S256KeyHash THEN
      SET p_Status = 2;    -- Non-matching key
    ELSE                       
      SET p_Status = 0;    -- Success
    END IF;
  END
//

DELIMITER ;

-- Run a few tests

SET @UserId = "2fb3f4f1-0d7d-43b9-b9f7-39d5dc5544fd";
SET @CardHolder = "Luke Skywalker";
SET @CredentialId = "gfdgddrer4535srwrsrwr";
SET @S256KeyHash = x'b3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104a';
SET @DummyPublicKey = x'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

SET @WrongS256KeyHash = x'c3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104a';
SET @WrongUserId = "3fb3f4f1-0d7d-43b9-b9f7-39d5dc5544fd";

CALL InitiateUserAccountSP(@UserId, @CardHolder, @CredentialId, @DummyPublicKey, @S256KeyHash);

CALL HasPaymentCardsSP(@found, @UserId);

CALL ASSERT_TRUE(@found = TRUE, "Must have");

CALL DeletePaymentCardsSP(@UserId);

CALL HasPaymentCardsSP(@found, @UserId);

CALL ASSERT_TRUE(@found = FALSE, "Must NOT have");

CALL AuthenticateSP(@Status, @UserId, @S256KeyHash);
CALL ASSERT_TRUE(@Status = 0, "Auth failed");

CALL AuthenticateSP(@Status, @WrongUserId, @S256KeyHash);
CALL ASSERT_TRUE(@Status = 1, "Wrong user failed");

CALL AuthenticateSP(@Status, @UserId, @WrongS256KeyHash);
CALL ASSERT_TRUE(@Status = 2, "Wrong key failed");

CALL GetCoreClientDataSP(@OutCredentialId, @OutPublicKey, @UserId); 
CALL ASSERT_TRUE(@OutCredentialId = @CredentialId, "CredentialId failed");
CALL ASSERT_TRUE(@OutPublicKey = @DummyPublicKey, "PublicKey failed");

CALL GetCoreClientDataSP(@OutCredentialId, @OutPublicKey, @WrongUserId); 
CALL ASSERT_TRUE(@OutCredentialId IS NULL, "CredentialId failed");

CALL GetCoreClientDataSP(@OutCredentialId, @OutPublicKey, NULL); 
CALL ASSERT_TRUE(@OutCredentialId IS NULL, "CredentialId failed");

-- Remove all test data

DELETE FROM USERS;

SET @Result = 'SUCCESSFUL';
SELECT @Result;
