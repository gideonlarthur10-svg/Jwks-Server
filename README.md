#JWKS Server

Overview
This project adopts a JSON Web Key Set (JWKS) Server which has RESTful APIs.  
It offers an endpoint called /jwks that is used to publish active public keys and an endpoint called /auth which is used to issue JWTs signed using RSA key pairs.  
Key IDs (kid) are connected to keys, and they contain expiry time to increase security.  

The server also accepts expired query parameter in /auth in order to generate JWTs with expired keys (helpful to test key rollover and validation code).

The project is an educational one.

Features
Generation of key pair with kid and expiry time.  
JWKS endpoint at /jwks which will only serve unexpired public keys.  
Auth endpoint at /auth which issues JWTs which contain appropriate kid.  
The query parameter expired=true to use is handled to produce a JWT signed with an expired key.  
Unit tests that had coverage greater than 80%.  
Engages in work with given test client.  

Endpoints

GET /jwks
Gets the progressing (non-expired) public keys in the form of the JSON Web Key Set (JWKS).

