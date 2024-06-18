package uk.parsec.onelogin.service.userinfo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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

	public String getUserPrincipalInfo()
	{
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Object principal = authentication.getPrincipal();
		return principal.toString();
	}

	public Map<String, String> getUserInfo()
	{
		return userInfoApi.userinfo();
	}
}
