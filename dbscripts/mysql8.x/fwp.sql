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
-- ###############################################################
-- # This is the Payer side of a PoC database for "Direct Mode"  #
-- # Open Banking APIs.  The database holds information about    #
-- # Credentials and OAuth2 tokens                               #
-- ###############################################################


/*=============================================*/
/*                OAUTH2TOKENS                 */
/*=============================================*/

CREATE TABLE OAUTH2TOKENS (
    IdentityToken   VARCHAR(50) NOT NULL UNIQUE,                        -- Unique User ID

    AccessToken     CHAR(36)    NOT NULL UNIQUE,                        -- The token we normally use
    
    RefreshToken    CHAR(36)    NOT NULL UNIQUE,                        -- For refreshing AccessToken
    
    Expires         INT         NOT NULL,                               -- In UNIX "epoch" style
                                                                        
    PRIMARY KEY (IdentityToken)
);


/*=============================================*/
/*                CREDENTIALS                  */
/*=============================================*/

CREATE TABLE CREDENTIALS (

-- Note: a Credential holds an external representation of an Account ID
-- like an IBAN or Card Number + and an Authorization key

    CredentialId    INT         NOT NULL  AUTO_INCREMENT,               -- Unique ID/Serial number

    AccountId       VARCHAR(30) NOT NULL,                               -- Account Reference
    
    PaymentMethodUrl VARCHAR(50) NOT NULL,                              -- Payment method URL

    HumanName       VARCHAR(50) NOT NULL,                               -- "Card Holder"
    
    AccessCount     INT         NOT NULL  DEFAULT 0,                    -- "Statistics"
    
    IpAddress       VARCHAR(50) NOT NULL,                               -- "Statistics"

    LastAccess      TIMESTAMP   NULL,                                   -- "Statistics"
    
    IdentityToken   VARCHAR(50) NOT NULL,                               -- For OAuth2 tokens

    Created         TIMESTAMP   NOT NULL  DEFAULT CURRENT_TIMESTAMP,    -- Administrator data

-- Authentication of user authorization signatures is performed
-- by verifying that both SHA256 of the public key (in X.509 DER
-- format) and claimed CredentialId match.

    S256AuthKey     BINARY(32)  NOT NULL,                               -- Payment request key hash 

    S256BalKey      BINARY(32)  NOT NULL,                               -- Balance key hash 

    PRIMARY KEY (CredentialId),
    FOREIGN KEY (IdentityToken) REFERENCES OAUTH2TOKENS(IdentityToken) ON DELETE CASCADE
) AUTO_INCREMENT=200500123;                                             -- Brag about "users" :-)


DELIMITER //


CREATE PROCEDURE CreateCredentialSP (OUT p_CredentialId INT,
                                     IN p_IdentityToken VARCHAR(50),
                                     IN p_AccountId VARCHAR(30),
                                     IN p_HumanName VARCHAR(50),
                                     IN p_IpAddress VARCHAR(50),
                                     IN p_PaymentMethodUrl VARCHAR(50),
                                     IN p_S256AuthKey BINARY(32),
                                     IN p_S256BalKey BINARY(32))
  BEGIN
    INSERT INTO CREDENTIALS(AccountId, 
                            HumanName,
                            IpAddress,
                            PaymentMethodUrl, 
                            IdentityToken, 
                            S256AuthKey, 
                            S256BalKey) 
        VALUES(p_AccountId,
               p_HumanName,
               p_IpAddress,
               p_PaymentMethodUrl,
               p_IdentityToken, 
               p_S256AuthKey, 
               p_S256BalKey);
    SET p_CredentialId = LAST_INSERT_ID();
  END
//

CREATE PROCEDURE StoreAccessTokenSP (IN p_AccessToken CHAR(36),
                                     IN p_RefreshToken CHAR(36),
                                     IN p_Expires INT,
                                     IN p_IdentityToken VARCHAR(50))
  BEGIN
    IF EXISTS (SELECT * FROM OAUTH2TOKENS WHERE OAUTH2TOKENS.IdentityToken = p_IdentityToken) THEN
      UPDATE OAUTH2TOKENS SET AccessToken = p_AccessToken, 
                              RefreshToken = p_RefreshToken,
                              Expires = p_Expires
          WHERE OAUTH2TOKENS.IdentityToken = p_IdentityToken;
    ELSE
      INSERT INTO OAUTH2TOKENS(IdentityToken, AccessToken, RefreshToken, Expires) 
          VALUES(p_IdentityToken, p_AccessToken, p_RefreshToken, p_Expires);
    END IF;
  END
//

CREATE PROCEDURE AuthenticatePayReqSP (OUT p_Error INT,
                                       OUT p_HumanName VARCHAR(50),
                                       OUT p_IdentityToken VARCHAR(50),

-- Note: the assumption is that the following variables are non-NULL otherwise
-- you may get wrong answer due to the (weird) way SQL deals with comparing NULL!

                                       IN p_CredentialId INT,
                                       IN p_AccountId VARCHAR(30),
                                       IN p_PaymentMethodUrl VARCHAR(50),
                                       IN p_S256AuthKey BINARY(32))
  BEGIN
    DECLARE v_AccountId VARCHAR(30);
    DECLARE v_PaymentMethodUrl VARCHAR(50);
    DECLARE v_S256AuthKey BINARY(32);

    SELECT HumanName, 
           IdentityToken,
           AccountId,
           PaymentMethodUrl,
           S256AuthKey
        INTO 
           p_HumanName,
           p_IdentityToken,
           v_AccountId,
           v_PaymentMethodUrl,
           v_S256AuthKey
        FROM CREDENTIALS WHERE CREDENTIALS.CredentialId = p_CredentialId;
    IF v_AccountId IS NULL THEN
      SET p_Error = 1;    -- No such credential
    ELSEIF v_AccountId <> p_AccountId THEN
      SET p_Error = 2;    -- Non-matching account
    ELSEIF v_S256AuthKey <> p_S256AuthKey THEN
      SET p_Error = 3;    -- Non-matching key
    ELSEIF v_PaymentMethodUrl <> p_PaymentMethodUrl THEN
      SET p_Error = 4;    -- Non-matching payment method
    ELSE                       
      SET p_Error = 0;    -- Success
      UPDATE CREDENTIALS SET LastAccess = CURRENT_TIMESTAMP, AccessCount = AccessCount + 1
          WHERE CREDENTIALS.CredentialId = p_CredentialId;
    END IF;
  END
//

CREATE PROCEDURE AuthenticateBalReqSP (OUT p_Error INT,
                                       OUT p_IdentityToken VARCHAR(50),

-- Note: the assumption is that the following variables are non-NULL otherwise
-- you may get wrong answer due to the (weird) way SQL deals with comparing NULL!

                                       IN p_CredentialId INT,
                                       IN p_AccountId VARCHAR(30),
                                       IN p_S256BalKey BINARY(32))
  BEGIN
    DECLARE v_AccountId VARCHAR(30);
    DECLARE v_S256BalKey BINARY(32);

    SELECT IdentityToken,
           AccountId,
           S256BalKey
        INTO 
           p_IdentityToken,
           v_AccountId,
           v_S256BalKey
        FROM CREDENTIALS WHERE CREDENTIALS.CredentialId = p_CredentialId;
    IF v_AccountId IS NULL THEN
      SET p_Error = 1;    -- No such credential
    ELSEIF v_AccountId <> p_AccountId THEN
      SET p_Error = 2;    -- Non-matching account
    ELSEIF v_S256BalKey <> p_S256BalKey THEN
      SET p_Error = 3;    -- Non-matching key
    ELSE                       
      SET p_Error = 0;    -- Success
    END IF;
  END
//

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

DELIMITER ;

-- Run a few tests

SET @IdentityToken = "20010101-1234";
SET @PaymentKey = x'b3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104a';
SET @BalanceKey = x'b3b76a196ced26e7e5578346b25018c0e86d04e52e5786fdc2810a2a10bd104b';
SET @AccountId = "SE6767676767676767676";
SET @HumanName = "Luke Skywalker";
SET @IpAddress = "127.0.0.1";
SET @PaymentMethodUrl = "https://supercard.com";

CALL StoreAccessTokenSP ("56b0762c-5834-4a53-a6b8-2d9eebff4514",
                         "6c6b27e5-c71b-4d93-9b08-1f17cac179da",
                         1572875316,
                         @IdentityToken);

CALL CreateCredentialSP (@CredentialId, 
                         @IdentityToken,
                         @AccountId,
                         @HumanName,
                         @IpAddress,
                         @PaymentMethodUrl,
                         @PaymentKey,
                         @BalanceKey);

CALL AuthenticatePayReqSP (@Error,
                           @ReadHumanName,
                           @ReadIdentityToken,
                           @CredentialId,
                           @AccountId,
                           @PaymentMethodUrl,
                           @PaymentKey);
CALL ASSERT_TRUE(@Error = 0, "Error code");
CALL ASSERT_TRUE(@ReadHumanName = @HumanName, "Human name");
CALL ASSERT_TRUE(@ReadIdentityToken = @IdentityToken, "Identity token");

CALL AuthenticatePayReqSP (@Error,
                           @ReadHumanName,
                           @ReadIdentityToken,
                           @CredentialId + 1,
                           @AccountId,
                           @PaymentMethodUrl,
                           @PaymentKey);
CALL ASSERT_TRUE(@Error = 1, "Error code");

CALL AuthenticatePayReqSP (@Error,
                           @ReadHumanName,
                           @ReadIdentityToken,
                           @CredentialId,
                           "no such account",
                           @PaymentMethodUrl,
                           @PaymentKey);
CALL ASSERT_TRUE(@Error = 2, "Error code");

CALL AuthenticatePayReqSP (@Error,
                           @HumanName,
                           @ReadIdentityToken,
                           @CredentialId,
                           @AccountId,
                           @PaymentMethodUrl,
                           @BalanceKey);
CALL ASSERT_TRUE(@Error = 3, "Error code");

CALL AuthenticatePayReqSP (@Error,
                           @HumanName,
                           @ReadIdentityToken,
                           @CredentialId,
                           @AccountId,
                           "payme twice!",
                           @PaymentKey);
CALL ASSERT_TRUE(@Error = 4, "Error code");

CALL AuthenticateBalReqSP (@Error,
                           @ReadIdentityToken,
                           @CredentialId,
                           @AccountId,
                           @BalanceKey);
CALL ASSERT_TRUE(@Error = 0, "Error code");
CALL ASSERT_TRUE(@ReadIdentityToken = @IdentityToken, "Identity token");

CALL AuthenticateBalReqSP (@Error,
                           @ReadIdentityToken,
                           @CredentialId + 1,
                           @AccountId,
                           @BalanceKey);
CALL ASSERT_TRUE(@Error = 1, "Error code");

CALL AuthenticateBalReqSP (@Error,
                           @ReadIdentityToken,
                           @CredentialId,
                           "no such account",
                           @BalanceKey);
CALL ASSERT_TRUE(@Error = 2, "Error code");

CALL AuthenticateBalReqSP (@Error,
                           @ReadIdentityToken,
                           @CredentialId,
                           @AccountId,
                           @PaymentKey);
CALL ASSERT_TRUE(@Error = 3, "Error code");

-- Remove all test data

DELETE FROM OAUTH2TOKENS;

SET @Result = 'SUCCESSFUL';
SELECT @Result;
