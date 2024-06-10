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

| Variable           | Description                                                                |
|--------------------|----------------------------------------------------------------------------|
| ONELOGIN_CLIENT_ID | The OIDC client ID allocated to your service during OneLogin registration. |

## Secrets
The directory `secret` must contain:

| File            | Description                                                                                         |
|-----------------|-----------------------------------------------------------------------------------------------------|
| private_key.pem | The private key corresponding to the public key you created and uploaded for your OneLogin service. |

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
