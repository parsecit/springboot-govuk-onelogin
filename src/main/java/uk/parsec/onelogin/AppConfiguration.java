package uk.parsec.onelogin;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Configuration
public class AppConfiguration
{
	@Value("${govuk.onelogin.private-key-resource}")
	Resource privateKeyFile;

	// Useful starting point: https://dev.to/gregsimons/spring-security-privatekeyjwt-with-aws-kms-3cm4
	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
	{
		DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
		client.setRequestEntityConverter(new Converter(privateKeyFile));
		return client;
	}

	// See https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-idtoken-verify
	@Bean
	public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
		OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
		idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> clientRegistration.getRegistrationId().equals("onelogin") ? SignatureAlgorithm.ES256 : SignatureAlgorithm.RS256);
		return idTokenDecoderFactory;
	}

//	@Bean
//	public RestTemplate restTemplate(RestTemplateBuilder builder)
//	{
//		builder.additionalInterceptors((request, body, execution) -> {
//			request.getHeaders().add("Authorization", "Bearer " + accessToken);
//			return execution.execute(request, body);
//		});
//		return builder.build();
//	}
//
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
			System.out.println(parameters);

			String signedJwt = Jwts.builder()
					.claim("aud", "https://oidc.integration.account.gov.uk/token")
					.claim("iss", "r4Wh7JKHakQDU5K2fRGAe3GowQk")
					.claim("sub", "r4Wh7JKHakQDU5K2fRGAe3GowQk")
					.claim("exp", "" + ((int)(System.currentTimeMillis() / 1000) + 5 * 60))
					.claim("jti", "" + System.currentTimeMillis())
					.claim("iat", "" + ((int)(System.currentTimeMillis() / 1000)))
					.signWith(privateKey)
					.compact();

			parameters.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
			parameters.set("client_assertion", signedJwt);

			System.out.println(parameters);
			return parameters;
		}

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
}
