package uk.parsec.onelogin.service.userinfo.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import uk.parsec.onelogin.service.authorization.AuthorizationService;

import java.util.Map;

/*
 * Simple RestTemplate wrapper for the OneLogin /userinfo endpoint.
 */
@Service
public class UserInfoApi
{
	private final String url;
	private final RestTemplate template;

	public UserInfoApi(@Value("${spring.security.oauth2.client.provider.onelogin.user-info-uri}") String url, AuthorizationService authorizationService)
	{
		this.url = url;
		this.template = new RestTemplate();
		this.template.getInterceptors().add(authorizationService.buildInterceptor());
	}

	public Map<String, String> userinfo()
	{
		String response = template.getForObject(url, String.class);
		assert response != null;
		return Map.of("userinfo", response);
	}
}
