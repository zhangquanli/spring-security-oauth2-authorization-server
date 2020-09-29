package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion2;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @see AbstractAuthenticationToken
 * @since 0.0.1
 */
public class OAuth2AuthorizationCodeAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
    private String code;
    private Authentication clientPrincipal;
    private String clientId;
    private String redirectUri;

    /**
     * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
     *
     * @param code            the authorization code
     * @param clientPrincipal the authenticated client principal
     * @param redirectUri     the redirect uri
     */
    public OAuth2AuthorizationCodeAuthenticationToken(
            String code, Authentication clientPrincipal, @Nullable String redirectUri) {
        super(Collections.emptyList());
        Assert.hasText(code, "code cannot be empty");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.code = code;
        this.clientPrincipal = clientPrincipal;
        this.redirectUri = redirectUri;
    }

    /**
     * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
     *
     * @param code        the authorization code
     * @param clientId    the client identifier
     * @param redirectUri the redirect uri
     */
    public OAuth2AuthorizationCodeAuthenticationToken(
            String code, String clientId, @Nullable String redirectUri) {
        super(Collections.emptyList());
        Assert.hasText(code, "code cannot be empty");
        Assert.hasText(clientId, "clientId cannot be empty");
        this.code = code;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
    }

    @Override
    public Object getCredentials() {
        return clientPrincipal != null ? clientPrincipal : clientId;
    }

    @Override
    public Object getPrincipal() {
        return "";
    }

    /**
     * Returns the authorization code.
     *
     * @return the authorization code
     */
    public String getCode() {
        return code;
    }

    /**
     * Returns the redirect uri.
     *
     * @return the redirect uri
     */
    @Nullable
    public String getRedirectUri() {
        return redirectUri;
    }
}
