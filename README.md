# WebApiLimitRequests
ASP.NET Core 8 Web API demo with request limiting feature.

To test the app follow these steps:

Use Web API call to create authenticated user (security/createToken endpoint).

Copy the following JSON to request body:

{
  "userName": "dusan",
  "password": "password"
}

From response copy JWT token, and use it when making call to the endpoint security/getMessage.

In API testing app (Postman, Hoppscotch, etc.) repeat the calls several times. Eventually you will get a message that quota has been exceeded.
