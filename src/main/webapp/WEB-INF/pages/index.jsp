<%@ page isELIgnored="false" %>
<%@ page import="java.util.Enumeration" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<h1>GovUK OneLogin Demo</h1>
<p><a href="https://oidc.integration.account.gov.uk/logout?post_logout_redirect_uri=http://localhost:8080/logout">Logout (GovUK)</a></p>
<p><a href="/logout">Logout (Service)</a></p>

<h2>User Principal</h2>
<p>${userPrincipal}</p>

<h2>User Info</h2>
<p>${userInfo}</p>

<h2>Authorization Token</h2
<p>${authorizationToken}</p>

<h2>Session Attributes</h2>
<p>
<table>
<%
    Enumeration attributeNames = session.getAttributeNames();
    while (attributeNames.hasMoreElements())
    {
        String attributeName = (String)attributeNames.nextElement();
%>
    <tr><td><%= attributeName %></td><td><%= session.getAttribute(attributeName) %></td></tr>
<%
    }
%>
</table>
</p>
</body>
</html>