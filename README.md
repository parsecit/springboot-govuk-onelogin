# Spring Boot Integration with GovUK OneLogin OIDC Provider
Simple integration of GovUK OneLogin Open ID Connect using Spring Boot.

This is intended to be a minimal implementation, showing the changes that need to be made to
a standard Spring Boot setup to get OneLogin working as an authentication mechanism.

To use this, you will need to be registered with [the OneLogin service](https://www.sign-in.service.gov.uk/)
[(technical documentation](https://docs.sign-in.service.gov.uk/).  Note that this is *only* available to
users with an email account from a recognised central UK government domain.

# Set Up

## OneLogin

Go through the [OneLogin registration process](https://www.sign-in.service.gov.uk/getting-started) to set up a
test service.  This will include establishing:
- Your client ID.
- A public / private key pair.
- A user name and password for the integration environment.

## Environment Variables
Set these:

| Variable                                        | Description                                                                             |
|-------------------------------------------------|-----------------------------------------------------------------------------------------|
| ONELOGIN_CLIENT_ID *(mandatory)*                | The OIDC client ID allocated to your service during OneLogin registration.              |
| ONELOGIN_PRIVATE_KEY_RESOURCE *(optional)*      | A Spring resource for the private key file (defaults to `file:secret/private_key.pem`). |
| SERVER_PORT *(optional - standard Spring Boot)* | The port to run the application on.  See note 1.                                        |
| APPLICATION_NAME *(optional)*                   | The name of the application displayed in the title in the UI.                           |
| HTTPS_CERTIFICATE_RESOURCE                      | A Spring resource for the server HTTPS certificate See note 2.                          |
| HTTPS_PRIVATE_KEY_RESOURCE                      | A Spring resource for the server HTTPS private key See note 2.                          |

By setting different combinations of the above environment variables, multiple instances of the application can
be run to represent multiple OneLogin services (each with its own client ID).  This is to allow for the testing of
session and logout behaviour across multiple services.

Notes:

1. Spring has some special behaviour for the standard HTTP and HTTPS ports (80, 443, 8080, 8443), apparently to deal 
   with issues in some older browsers.  This tends to result in unexpected redirects.  A single instance using just a
   standard pair of ports (80/443 or 8080/8443) will probably work OK.  Since I want to run multiple instances on
   different ports to investigate session timeouts, etc., across multiple services, I avoid using the standard ports.
2. This project uses HTTPS because it's required to test the back-channel logout mechanism.  Basic login and user info
   retrieval works fine with HTTP as long as it is run on `localhost` (the OneLogin configuration insists on either
   `https://<anything>` or `http://localhost`).  It may be useful to remove the HTTPS Spring configuration to get
   something working initially.  The configuration requires a PEM format certificate and private key (because this is
   what `letsencrypt.org` gives by default), and the private key must be *unencrypted*.  Obviously production code
   will have an entirely different approach to the securing of secrets.

## Private Key
You must provide the private key corresponding to the public key you created and uploaded for your OneLogin service.
By default, this is expected to be in the file `secret/private_key.pem`, but this can be overridden using the
`ONELOGIN_PRIVATE_KEY_RESOURCE` environment variable, as above.

# Run
- Run the Spring Boot application (`uk.parsec.onelogin.AppApplication`) in your development environment of choice.
- Access the web UI - default is [http://localhost:8080/]().
- When redirected to OneLogin to log in / create an account, the first thing you will be required to enter is a user
  name and password *which are not your account credentials*.  This only happens in the OneLogin integration
  environment, and is there to ensure that nobody can accidentally mistake the integration environment for production.
  You can find the credentials to use in the
  [OneLogin configuration page for your service](https://admin.sign-in.service.gov.uk/services).  These credentials
  are supplied using HTTP BASIC authentication, so are mostly cached by your browser once entered the first time,
  but may need to be re-entered periodically.
