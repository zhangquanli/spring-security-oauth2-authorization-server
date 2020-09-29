package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Authorization Request.
 *
 * @author Joe Grandja
 * @author Paurav Munshi
 * @see RegisteredClient
 * @see OAuth2AuthorizationService
 * @see OAuth2Authorization
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 * @since 0.0.1
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
    /**
     * The default endpoint {@code URI} for authorization requests.
     */
    public static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final RequestMatcher authorizationEndpointMatcher;
    private final StringKeyGenerator codeGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
     *
     * @param registeredClientRepository the repository of registered client
     * @param authorizationService       the authorization service
     */
    public OAuth2AuthorizationEndpointFilter(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService) {
        this(registeredClientRepository, authorizationService, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
    }

    /**
     * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
     *
     * @param registeredClientRepository the repository of registered client
     * @param authorizationService       the authorization service
     * @param authorizationEndpointUri   the endpoint {@code URI} for authorization requests
     */
    public OAuth2AuthorizationEndpointFilter(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService, String authorizationEndpointUri) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.authorizationEndpointMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.GET.name());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!authorizationEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Validate the request to ensure that all required parameters are present and valid

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
        String stateParameter = parameters.getFirst(OAuth2ParameterNames.STATE);

        // client_id (REQUIRED)
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) ||
                parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            OAuth2Error error = createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
            // when redirectUri is null then don't redirect
            sendErrorResponse(request, response, error, stateParameter, null);
            return;
        }
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            OAuth2Error error = createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
            // when redirectUri is null then don't redirect
            sendErrorResponse(request, response, error, stateParameter, null);
            return;
        } else if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            OAuth2Error error = createError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID);
            // when redirectUri is null then don't redirect
            sendErrorResponse(request, response, error, stateParameter, null);
            return;
        }
    }

    private OAuth2Error createError(String errorCode, String parameterName) {
        return new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName,
                "https://tools.ietf.org/html/rfc6749#section-4.1.2.1");
    }

    private void sendErrorResponse(
            HttpServletRequest request, HttpServletResponse response,
            OAuth2Error error, String state, String redirectUri) throws IOException {

        if (redirectUri == null) {
            // TODO Send default html error response
            response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
            return;
        }

        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
        if (StringUtils.hasText(error.getDescription())) {
            uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
        }
        if (StringUtils.hasText(error.getUri())) {
            uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
        }
        if (StringUtils.hasText(state)) {
            uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
        }
        redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
    }
}
