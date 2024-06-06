package uk.parsec.onelogin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import uk.parsec.onelogin.service.authorization.AuthorizationService;
import uk.parsec.onelogin.service.userinfo.UserInfoService;

@Controller
public class AppController
{
	public static String INDEX_PAGE = "index";

	private final UserInfoService userInfoService;
	private final AuthorizationService authorizationService;

	@Autowired
	public AppController(UserInfoService userInfoService, AuthorizationService authorizationService)
	{
		this.userInfoService = userInfoService;
		this.authorizationService = authorizationService;
	}

	@GetMapping("/")
	public String sayHello(Model model)
	{
		model.addAttribute("userPrincipal", userInfoService.getUserPrincipalInfo());
		model.addAttribute("userInfo", userInfoService.getUserInfo());
		model.addAttribute("authorizationToken", authorizationService.getAuthorizationToken());
		return INDEX_PAGE;
	}
}
