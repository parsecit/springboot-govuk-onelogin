package uk.parsec.onelogin;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.lang.NonNull;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.MultiValueMap;
import org.springframework.web.filter.AbstractRequestLoggingFilter;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Set;

@Configuration
public class AppConfiguration
{
	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Value("${govuk.onelogin.private-key-resource}")
	Resource privateKeyFile;

	/*
	 * Configures the client for the back-end authorization code access token request to add
	 * the request parameters needed to authenticate the request to OneLogin.
	 *
	 * Useful starting point: https://dev.to/gregsimons/spring-security-privatekeyjwt-with-aws-kms-3cm4
	 */
	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
	{
		DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
		client.setRequestEntityConverter(new Converter(privateKeyFile));
		return client;
	}

	/*
	 * OneLogin (at the time of writing) uses ES256 to sign ID tokens.  This does not work out-of-the-box
	 * with Spring Boot OIDC, and needs the JWT decoder to be specifically configured.
	 *
	 * See https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-idtoken-verify
	 */
	@Bean
	public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
		OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
		idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> clientRegistration.getRegistrationId().equals("onelogin") ? SignatureAlgorithm.ES256 : SignatureAlgorithm.RS256);
		return idTokenDecoderFactory;
	}

	/*
	 * The request entity converter creates a set of parameters to send as part of the back-end
	 * authorization code request to the OIDC provider.  OneLogin requires a signed JWT token with
	 * specific contents to be included in these parameters - signed by the private key for the
	 * OneLogin service being accessed.
	 *
	 * This class extends the standard converter with the additional parameters.
	 */
	public static class Converter extends OAuth2AuthorizationCodeGrantRequestEntityConverter
	{
		private final Key privateKey;

		public Converter(Resource privateKeyFile) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
		{
			this.privateKey = buildPrivateKey(privateKeyFile);
		}

		protected MultiValueMap<String, String> createParameters(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest)
		{
			MultiValueMap<String, String> parameters = super.createParameters(authorizationCodeGrantRequest);

			String clientId = authorizationCodeGrantRequest.getClientRegistration().getClientId();

			String signedJwt = Jwts.builder()
					.claim("aud", "https://oidc.integration.account.gov.uk/token")
					.claim("iss", clientId)
					.claim("sub", clientId)
					.claim("exp", "" + ((int)(System.currentTimeMillis() / 1000) + 5 * 60))
					.claim("jti", "" + System.currentTimeMillis())
					.claim("iat", "" + ((int)(System.currentTimeMillis() / 1000)))
					.signWith(privateKey)
					.compact();

			parameters.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
			parameters.set("client_assertion", signedJwt);

			return parameters;
		}

		/*
		 * Quick and dirty way of loading a private key while avoiding unnecessary library
		 * dependencies.  Production code will have something better.
		 */
		private Key buildPrivateKey(Resource privateKeyFile) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
		{
			String key = privateKeyFile.getContentAsString(StandardCharsets.UTF_8);
			key = key
					.replaceAll("-*BEGIN PRIVATE KEY-*", "")
					.replaceAll("-*END PRIVATE KEY-*", "")
					.replaceAll("\\s", "");
			byte[] decoded = Base64.getDecoder().decode(key);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
			return keyFactory.generatePrivate(spec);
		}
	}

	/*
	 * Enable OIDC backchannel logout.
	 *
	 * See https://docs.spring.io/spring-security/reference/servlet/oauth2/login/logout.html
	 */
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception
	{
		return
			httpSecurity
					.authorizeHttpRequests(authorize -> authorize.requestMatchers("/favicon.ico").permitAll())
					.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout(logout -> logout.backChannel(Customizer.withDefaults()))
					.logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler()))
					.build();
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler()
	{
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
		return oidcLogoutSuccessHandler;
	}

	/*
	 * Turn on publishing so that backchannel logout works.
	 */
	@Bean
	public HttpSessionEventPublisher sessionEventPublisher()
	{
		return new HttpSessionEventPublisher();
	}

	/*
	 * Logging so that we can confirm the backchannel logout requests are being received.
	 */
	@Bean
	public FilterRegistrationBean<RequestLoggingFilter> logFilter()
	{
		FilterRegistrationBean<RequestLoggingFilter> filterRegistrationBean = new FilterRegistrationBean<>();
		filterRegistrationBean.setName("Request logging filter");
		// Run before the security filter starts redirecting things ...
		filterRegistrationBean.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 1);
		filterRegistrationBean.setFilter(new RequestLoggingFilter());
		return filterRegistrationBean;
	}

	public static class RequestLoggingFilter extends AbstractRequestLoggingFilter
	{
		private static final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);

		@Override
		protected void beforeRequest(@NonNull HttpServletRequest request, @NonNull String message)
		{
			logger.debug(message);
			String query = request.getQueryString();
			logger.debug("{} {}{}", request.getMethod(), request.getRequestURI(), query == null ? "" : "?" + query);
		}

		@Override
		protected void afterRequest(@NonNull HttpServletRequest request, @NonNull String message)
		{
		}
	}
}
