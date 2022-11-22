/*
 *  Copyright 2015-2021 WebPKI.org (http://webpki.org).
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
 
 -- SQL Script for MySQL 8.x
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
CREATE DEFINER = root@localhost SQL SECURITY DEFINER
  VIEW v_routines AS SELECT * FROM information_schema.routines;
GRANT SELECT ON v_routines TO fwp@localhost;
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
    
    
    -- FIDO CredentialId.
    --
    -- In a real-world FWP implementation this would be a part of the local
    -- FWP wallet database since a verifier does not need this information.
    -- However, in a server-oriented setting using the WebAuthn API the
    -- FIDO CredentialId must be known by the verifier.  

    CredentialId    VARBINARY(1024) NOT NULL,

    -- FIDO RpId. Provides issuer isolation

    RpId            VARCHAR(255) NOT NULL,

    -- The FWP wallet is obliged including the associated public key in
    -- assertions.  Here it is stored in the CBOR/COSE format.
    -- It is used for FIDO/WebAuthn but is also used by the FWP wallet
    -- for inclusion in assertions.
    
    PublicKey       VARBINARY(300) NOT NULL,


    -- Authorization of FWP assertions is performed by verifying that 
    -- the SHA256 of the public key match the claimed public key.
    
    S256KeyHash     BINARY(32)   NOT NULL,
    
    -- User statistics
    
    FWPSteps        INT          NOT NULL DEFAULT 0,                     -- The "technical" payment route
    
    BasicBuy        INT          NOT NULL DEFAULT 0,                     -- The basic payment route

    WebAuthn        INT          NOT NULL DEFAULT 0,                     -- WebAuthn operations

    ClientIpAddress VARCHAR(50)  NOT NULL,                               -- From where?

    ClientHost      VARCHAR(100) NULL,                                   -- Host of client (may not be available)

    Created         TIMESTAMP    NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Account creation time
                                                                        
    PRIMARY KEY (UserId)
);


/*=============================================*/
/*                PAYMENT_CARDS                */
/*=============================================*/

CREATE TABLE PAYMENT_CARDS (

-- Note: a payment card holds an external representation of an Account ID
-- like an IBAN or Card Number

    SerialNumber    INT          NOT NULL  AUTO_INCREMENT,               -- Unique ID/Serial number

    UserId          CHAR(36)     NOT NULL,                               -- Owner

    AccountId       VARCHAR(30)  NOT NULL,                               -- Account Reference
    
    PaymentNetworkId   VARCHAR(50)  NOT NULL,                            -- Payment Network ID/URL

    Created         TIMESTAMP    NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Admin data

    PRIMARY KEY (SerialNumber),
    FOREIGN KEY (UserId) REFERENCES USERS(UserId) ON DELETE CASCADE
) AUTO_INCREMENT=20500123;                                              -- Impress :)


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
                                        IN p_CredentialId VARBINARY(1024),
                                        IN p_RpId VARCHAR(255),
                                        IN p_PublicKey VARBINARY(300),
                                        IN p_S256KeyHash BINARY(32),
                                        IN p_ClientIpAddress VARCHAR(50))
  BEGIN
    -- To make it simple, clear previous entry...
    DELETE FROM USERS WHERE UserId = p_UserId;
    
    -- Create an entry with the same UserId
    INSERT INTO USERS(UserId, 
                      CardHolder,
                      CredentialId,
                      RpId,
                      PublicKey,
                      S256KeyHash,
                      ClientIpAddress) 
        VALUES(p_UserId,
               p_CardHolder,
               p_CredentialId,
               p_RpId,
               p_PublicKey,
               p_S256KeyHash,
               p_ClientIpAddress);
               
    -- Add payment cards...
    INSERT INTO PAYMENT_CARDS(UserId,
                              AccountId,
                              PaymentNetworkId) 
        VALUES(p_UserId,
               "FR7630002111110020050014382",
               "https://banknet2.org");

    INSERT INTO PAYMENT_CARDS(UserId,
                              AccountId,
                              PaymentNetworkId) 
        VALUES(p_UserId,
               "4532 5620 0500 3239",
               "https://supercard.com");
  END
//


CREATE PROCEDURE DeletePaymentCardsSP (IN p_UserId CHAR(36))
  BEGIN
    DELETE Target FROM PAYMENT_CARDS As Target
        INNER JOIN USERS ON USERS.UserId = Target.UserId
        WHERE USERS.UserId = p_UserId;
  END
//

CREATE PROCEDURE GetCoreClientDataSP (OUT p_CredentialId VARBINARY(1024),
                                      OUT p_RpId VARCHAR(255),
                                      OUT p_PublicKey VARBINARY(300),
                                      OUT p_CardHolder VARCHAR(50),
                                      IN p_UserId CHAR(36))
  BEGIN
    SELECT CredentialId,
           RpId,
           PublicKey, 
           CardHolder INTO p_CredentialId,
                           p_RpId,
                           p_PublicKey, 
                           p_CardHolder FROM USERS
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
      SET p_Status = 1;    -- No such user
    ELSEIF v_S256KeyHash <> p_S256KeyHash THEN
      SET p_Status = 2;    -- Non-matching key
    ELSE                       
      SET p_Status = 0;    -- Success
    END IF;
  END
//

CREATE PROCEDURE AuthorizeSP (OUT p_Status INT,
                              OUT p_UserId CHAR(36),
                              OUT p_CardHolder VARCHAR(50),
                              IN p_SerialNumber INT,
                              IN p_AccountId VARCHAR(30),
                              IN p_S256KeyHash BINARY(32))
  BEGIN
    DECLARE v_S256KeyHash BINARY(32);
    DECLARE v_AccountId VARCHAR(30);

    SELECT USERS.UserID,
           USERS.CardHolder,
           USERS.S256KeyHash,
           PAYMENT_CARDS.AccountId
        INTO 
           p_UserId,
           p_CardHolder,
           v_S256KeyHash,
           v_AccountId
        FROM USERS INNER JOIN PAYMENT_CARDS ON USERS.UserId = PAYMENT_CARDS.UserId
        WHERE PAYMENT_CARDS.SerialNumber = p_SerialNumber;
            
    IF p_UserId IS NULL THEN
      SET p_Status = 1;    -- No such card
    ELSEIF v_AccountId <> p_AccountId THEN
      SET p_Status = 2;    -- Non-matching account
    ELSEIF v_S256KeyHash <> p_S256KeyHash THEN
      SET p_Status = 3;    -- Non-matching key
    ELSE                       
      SET p_Status = 0;    -- Success
      UPDATE USERS SET FWPSteps = FWPSteps + 1 WHERE UserId = p_UserId;
    END IF;
  END
//

DELIMITER ;

-- Run a few tests
SET collation_connection = 'utf8mb4_unicode_ci';

SET @UserId = "2fb3f4f1-0d7d-43b9-b9f7-39d5dc5544fd";
SET @CardHolder = "Luke Skywalker";
SET @CredentialId = x'aaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccc00000000000000000';
SET @RpId = "mybank.com";
SET @ClientIpAddress = "202.56.22.89";
SET @S256KeyHash = x'b3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104a';
SET @DummyPublicKey = x'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

SET @WrongS256KeyHash = x'c3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104a';
SET @WrongUserId = "3fb3f4f1-0d7d-43b9-b9f7-39d5dc5544fd";

CALL InitiateUserAccountSP(@UserId, @CardHolder, @CredentialId, @RpId, @DummyPublicKey, @S256KeyHash, @ClientIpAddress);

SELECT USERS.CredentialId,
       USERS.S256KeyHash, 
       PAYMENT_CARDS.SerialNumber,
       PAYMENT_CARDS.AccountId, 
       PAYMENT_CARDS.PaymentNetworkId
   INTO
       @OutCredentialId,
       @OutS256KeyHash,
       @OutSerialNumber,
       @OutAccountId,
       @OutPaymentNetworkId
   FROM USERS INNER JOIN PAYMENT_CARDS 
   ON USERS.UserId = PAYMENT_CARDS.UserId
   WHERE USERS.UserId = @UserId
   LIMIT 1;

CALL AuthorizeSP(@Status, @OutUserId, @OutCardHolder, @OutSerialNumber, @OutAccountId, @OutS256KeyHash);
CALL ASSERT_TRUE(@Status = 0, "Authz failed");
CALL ASSERT_TRUE(@OutUserId = @UserId, "Authz failed");
CALL AuthorizeSP(@Status, @OutUserId, @OutCardHolder, 23, @OutAccountId, @OutS256KeyHash);
CALL ASSERT_TRUE(@Status = 1, "Authz failed");
CALL AuthorizeSP(@Status, @OutUserId, @OutCardHolder, @OutSerialNumber, "hi", @OutS256KeyHash);
CALL ASSERT_TRUE(@Status = 2, "Authz failed");
CALL AuthorizeSP(@Status, @OutUserId, @OutCardHolder, @OutSerialNumber, @OutAccountId, @WrongS256KeyHash);
CALL ASSERT_TRUE(@Status = 3, "Authz failed");
   
CALL DeletePaymentCardsSP(@UserId);

CALL AuthenticateSP(@Status, @UserId, @S256KeyHash);
CALL ASSERT_TRUE(@Status = 0, "Auth failed");

CALL AuthenticateSP(@Status, @WrongUserId, @S256KeyHash);
CALL ASSERT_TRUE(@Status = 1, "Wrong user failed");

CALL AuthenticateSP(@Status, @UserId, @WrongS256KeyHash);
CALL ASSERT_TRUE(@Status = 2, "Wrong key failed");

CALL GetCoreClientDataSP(@OutCredentialId, @OutRpId, @OutPublicKey, @OutCardHolder, @UserId); 
CALL ASSERT_TRUE(@OutCredentialId = @CredentialId, "CredentialId failed");
CALL ASSERT_TRUE(@OutPublicKey = @DummyPublicKey, "PublicKey failed");
CALL ASSERT_TRUE(@OutCardHolder = @CardHolder, "CardHolder failed");

CALL GetCoreClientDataSP(@OutCredentialId, @OutRpId, @OutPublicKey, @OutCardHolder, @WrongUserId); 
CALL ASSERT_TRUE(@OutCredentialId IS NULL, "CredentialId failed");

CALL GetCoreClientDataSP(@OutCredentialId, @OutRpId, @OutPublicKey, @OutCardHolder, NULL); 
CALL ASSERT_TRUE(@OutCredentialId IS NULL, "CredentialId failed");

-- Remove all test data
SET SQL_SAFE_UPDATES = 0;
DELETE FROM USERS;

SET @Result = 'SUCCESSFUL';
SELECT @Result;
