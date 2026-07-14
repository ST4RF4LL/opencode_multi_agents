<%-- Positive: raw EL reflection of request parameter --%>
<html>
<body>
  <p>Welcome ${param.user}</p>
  <p>Raw: <%= request.getParameter("user") %></p>
</body>
</html>
