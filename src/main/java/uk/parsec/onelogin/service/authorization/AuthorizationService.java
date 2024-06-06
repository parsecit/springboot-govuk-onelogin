package uk.parsec.onelogin.service.authorization;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

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
		OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
		OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
				authentication.getAuthorizedClientRegistrationId(), authentication.getName());
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		return accessToken.getTokenValue();
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
