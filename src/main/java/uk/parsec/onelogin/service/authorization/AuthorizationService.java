package uk.parsec.onelogin.service.authorization;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

/*
 * Encapsulates the code for retrieving the user's authorization token from the Spring security
 * context.  Also generates the content of the standard bearer token HTTP header, and acts
 * as a factory for a Spring interceptor which adds the header to requests.
 */
@Service
public class AuthorizationService
{
	private final OAuth2AuthorizedClientService authorizedClientService;

	public AuthorizationService(OAuth2AuthorizedClientService authorizedClientService)
	{
		this.authorizedClientService = authorizedClientService;
	}

	public String getAuthorizationToken()
	{
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof OAuth2AuthenticationToken authenticationToken)
		{
			OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
					authenticationToken.getAuthorizedClientRegistrationId(), authenticationToken.getName());
			OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
			return accessToken.getTokenValue();
		}
		else
		{
			return null;
		}
	}

	public String getBearerAuthorizationHeader()
	{
		return "Bearer " + getAuthorizationToken();
	}

	public ClientHttpRequestInterceptor buildInterceptor()
	{
		return
				(request, body, execution) ->
				{
					request.getHeaders().set("Authorization", getBearerAuthorizationHeader());
					return execution.execute(request, body);
				};
	}
}
