/*
These are the default table definitions expected by DBLink.

If your database supports views you can redefine them as views on existing tables.
*/

/*
Stores private keys. Read only.
*/
CREATE TABLE httpsec_key (
    local_id        text    PRIMARY KEY,
    private_key     text    NOT NULL
);

/*
Stores session data. Read / write.
*/
CREATE TABLE httpsec_session (
    key             text    PRIMARY KEY,
    timestamp       bigint  NOT NULL
    data            text    NOT NULL
);

/*
Stores certificate urls. Read only.
*/
CREATE TABLE httpsec_certificate (
    local_id            text    PRIMARY KEY,
    certificate_url     text
);
