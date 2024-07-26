package uk.parsec.onelogin.service.userinfo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import uk.parsec.onelogin.service.userinfo.api.UserInfoApi;

import java.util.Map;

/*
 * Provides information about the user, both from the local security context and by invoking
 * the OneLogin /userinfo API.
 */
@Service
public class UserInfoService
{
	private final UserInfoApi userInfoApi;

	public UserInfoService(UserInfoApi userInfoApi)
	{
		this.userInfoApi = userInfoApi;
	}

	public OidcUser getOidcPrincipal()
	{
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return (OidcUser)authentication.getPrincipal();
	}

	public Map<String, String> getUserInfo()
	{
		return userInfoApi.userinfo();
	}
}
