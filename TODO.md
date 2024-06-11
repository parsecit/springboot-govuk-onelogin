- [X] Add logout.  https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/managing-your-users-sessions/#log-your-user-out-of-gov-uk-one-login
- [X] Retrieve userinfo from OneLogin API.  https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/authenticate-your-user/#retrieve-user-information
- [X] Add another (dummy) OIDC provider - see what Spring does when there is more than one to choose from.
      Result: Spring lets the user choose.  Note that the dummy service URLs must work for Spring to start up.
- [X] Add extra scopes to get more information from the OneLogin /userinfo endpoint.
- [ ] Investigate logout options.  Logout locally and from OneLogin are to some degree independent.
- [ ] Request logout notifications.  https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/managing-your-users-sessions/#request-logout-notifications-from-gov-uk-one-login.
- [ ] Investigate how to set the level of protection https://docs.sign-in.service.gov.uk/before-integrating/choose-the-level-of-authentication/#choose-the-level-of-authentication-for-your-service.
- 