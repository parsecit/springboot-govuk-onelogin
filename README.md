# springboot-govuk-onelogin
Simple integration of GovUK OneLogin Open ID Connect using Spring Boot.

# Environment Variables
Set these:

| Variable           | Description                                                                |
|--------------------|----------------------------------------------------------------------------|
| ONELOGIN_CLIENT_ID | The OIDC client ID allocated to your service during OneLogin registration. |

# Secrets
The directory `secret` must contain:

| File            | Description                                                                                         |
|-----------------|-----------------------------------------------------------------------------------------------------|
| private_key.pem | The private key corresponding to the public key you created and uploaded for your OneLogin service. |

