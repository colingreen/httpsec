<html>
    <head>
        <title>HTTPsec sample webapp</title>
    </head>
    <body>
        <h1>HTTPsec-Java Sample Webapp</h1>
        <p>For more information see <a href="http://secarta.com/products/httpsec-java.html">http://secarta.com/products/httpsec-java.html</a></p>
        <p>This webapp contains a single servlet <b><a href="echo">echo</a></b> that returns the request it receives in a <code>message/http</code> response. The echo servlet is protected by a filter that implements HTTPsec/1.0 authentication.

        <h4>X.509 Certificate</h4>
        <a href="http://secarta.com/products/httpsec-java/httpsec_sample_webapp.cert">http://secarta.com/products/httpsec-java/httpsec_sample_webapp.cert</a>
        <code><pre><%@ include file="httpsec_sample_webapp.cert" %></pre></code>

        <h4>Private Key</h4> ( PEM encoded PKCS#8 format )
        <code><pre><%@ include file="WEB-INF/httpsec_sample_webapp.key" %></pre></code>
    </body>
</html>
