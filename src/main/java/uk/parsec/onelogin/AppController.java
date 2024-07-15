package uk.parsec.onelogin;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import uk.parsec.onelogin.service.authorization.AuthorizationService;
import uk.parsec.onelogin.service.userinfo.UserInfoService;

import java.net.MalformedURLException;
import java.net.URL;

@Controller
public class AppController
{
	public static String INDEX_PAGE = "index";

	private final UserInfoService userInfoService;
	private final AuthorizationService authorizationService;
	private final String applicationName;

	@Autowired
	public AppController(UserInfoService userInfoService, AuthorizationService authorizationService, @Value("${spring.application.name}")String applicationName)
	{
		this.userInfoService = userInfoService;
		this.authorizationService = authorizationService;
		this.applicationName = applicationName;
	}

	@GetMapping("/")
	public String sayHello(Model model, HttpServletRequest request) throws MalformedURLException
	{
		model.addAttribute("userPrincipal", userInfoService.getUserPrincipalInfo());
		model.addAttribute("userInfo", userInfoService.getUserInfo());
		model.addAttribute("authorizationToken", authorizationService.getAuthorizationToken());
		model.addAttribute("applicationName", applicationName);
		model.addAttribute("logoutUri", getLogoutUri(request));
		return INDEX_PAGE;
	}

	/*
	 * This is probably not the right way to get paths out of the request, but it works
	 * for now.
	 */
	public String getLogoutUri(HttpServletRequest request) throws MalformedURLException
	{
		return new URL(new URL(request.getRequestURL().toString()), "/").toString();
	}
}
