# JWKS Server with SQLite Backend

## Overview
This project extends the JWKS Server to include a SQLite-backed storage layer for RSA private keys.  
By using keys to a database file, the server ensures availability and secure key management even across restarts.  

In addition to key persistence, this project highlights **secure database interactions — specifically parameterized SQL queries to defend against SQL injection.

---

## Features
- Uses SQLite database: `totally_not_my_privateKeys.db`
- Table schema:
  ```sql
  CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key BLOB NOT NULL,
      exp INTEGER NOT NULL
  );
