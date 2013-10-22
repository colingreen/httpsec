httpsec
=======

An authentication scheme for HTTP. A specification of the protocol and a reference implementation in Java.

Here's a link to [the original specification](http://secarta.com/archived/httpsec/) at secarta.com.

The original summary:

HTTPsec ("HTTP security") is an authentication scheme for the web protocol HTTP. HTTPsec provides cryptographically strong security at the application layer.

HTTPsec operates within the framework of the HTTP authentication headers. It uses RSA public keys for mutual authentication, and ephemeral Diffie-Hellman key exchange to ensure forward secrecy. The protocol provides mutual authentication and message origin authentication, via protection applied to (1) the integrity of URL, Method, and core HTTP headers, (2) the integrity of the message body, (3) message sequence, and (4) message replays. It optionally provides message body encryption. It does not provide header confidentiality (as messages would no longer be HTTP if their header fields were encrypted) or integrity protection applied to secondary headers (which may be legitimately altered by proxies).

Public key authentication

Public key is the only authentication method that scales in a multi-domain environment like the web. HTTPsec introduces public key authentication directly into the web protocol HTTP. This allows great flexibility for using public key authentication in diverse scenarios. For example, any use-case characterised by large numbers of user hosted across multiple isolated systems can employ HTTPsec to enforce authentication criteria based on per-user public keys.

How does it compare to SSL/TLS?

Public key authentication is already available at the transport layer with TLS. HTTPsec does not replace either of these; indeed it many be used in conjunction with them.

HTTPsec enforces public key authentication at the high message/application level, in a way that cannot be provided by lower Transport Level Security. SSL/TLS provides Transport rather than message security; it authenticates traffic between two machines. The entities you can authenticate with HTTPsec are "higher level", i.e they do not need to correspond 1-to-1 to machines or domains. For example, hospitals X, Y, Z may each have a system hosting numerous doctor identities. TLS would associate the three servers with a public key each. HTTPsec on the other hand could associate each doctor with a public key each, allowing a user-centric (rather than a server-centric) authentication model.

Browser-to-server security

Browser or desktop based applications can be built using HTTPsec (complimented of course by servers that also do so). See for example SecuMark.

Server-to-server security

The aim of HTTPsec is to be able to add authentication any kind of HTTP message. Any protocol that itself travels within the HTTP message body such as Web Service transactions expressed using SOAP or ReST can be protected by HTTPsec. HTTPsec-Java, for example, is a client/server implementation for such applications.

Algorithms employed

The algorithms employed in HTTPsec are RSA, OAEP, PSS, HMAC, SHA-256, and AES-256. The protocol does not allow algorithm negotiation.


