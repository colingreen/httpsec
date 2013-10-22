<%@ page import="org.httpsec.net.*" %>
<%@ page import="org.httpsec.*" %>
<%@ page import="java.security.*" %>
<%@ page import="java.net.*" %>
<%@ page import="java.io.*" %>
<html>
    <head>
        <title>HTTPsec examples - client</title>
    </head>
    <body>
        <h2>request</h2>
        <form method="POST" action="">
            <label for="url">url</label><br>
            <input type="text" size="64" name="url" id="url" value="<%= request.getParameter( "url" ) == null ? "" : request.getParameter( "url" ) %>">
           
            <br>
            <label for="id">id</label><br>
            <input name="id" id="id" value="<%= request.getParameter( "id" ) == null ? "" : request.getParameter( "id" ) %>">

            <br>
            <label for="certificate">certificate</label><br>
            <input size="64" name="certificate" id="certificate" value="<%= request.getParameter( "certificate" ) == null ? "" : request.getParameter( "certificate" ) %>">

            <br>
            <label for="private-key">private key</label><br>
            <textarea rows="16" cols="64" name="private-key" id="private-key"><%= request.getParameter( "private-key" ) == null ? "" : request.getParameter( "private-key" ) %></textarea>
            <br><br>
            <input type="submit">
        </form>

        <h2>response</h2>
        <textarea rows="24" cols="80" style="width: 100%"><%
            if ( ! request.getMethod().equals( "POST" ) ) return;
            try {
                String id = request.getParameter( "id" );
                if ( id == null ) throw new Exception( "expected \"id\" parameter" );
                URI certificate = null;
                if ( request.getParameter( "certificate" ) != null && request.getParameter( "certificate" ).length() > 0 )
                    certificate = new URI( request.getParameter( "certificate" ) );
                if ( request.getParameter( "private-key" ) == null || request.getParameter( "private-key" ).length() == 0 )
                    throw new Exception( "expected \"private-key\" parameter" );
                PrivateKey privateKey = Utils.pem_decode( request.getParameter( "private-key" ) );
                HttpsecURLConnectionFactory cf = new HttpsecURLConnectionFactory( id, certificate, privateKey );
                HttpsecURLConnection c = cf.wrap(
                    ( HttpURLConnection )new URL( request.getParameter( "url" ) ).openConnection()
                );
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                try {
                    c.dump( b );
                } finally {
                    c.close();
                }
                out.println( b.toString() );
            } catch ( Exception e ) {
                e.printStackTrace();
                out.println( "error: " + e );
            }
        %></textarea>
    </body>
</html>
