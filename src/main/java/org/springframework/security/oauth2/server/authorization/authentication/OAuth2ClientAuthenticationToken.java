package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion2;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * A {@link Authentication} implementation used for OAuth 2.0 Client Authentication.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @see AbstractAuthenticationToken
 * @see RegisteredClient
 * @since 0.0.1
 */
public class OAuth2ClientAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
    private String clientId;
    private String clientSecret;
    private RegisteredClient registeredClient;

    /**
     * Constructs an {@link OAuth2ClientAuthenticationToken} using the provided parameters.
     *
     * @param clientId     the client identifier
     * @param clientSecret the client secret
     */
    public OAuth2ClientAuthenticationToken(String clientId, String clientSecret) {
        super(Collections.emptyList());
        Assert.hasText(clientId, "clientId cannot be empty");
        Assert.hasText(clientSecret, "clientSecret cannot be empty");
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Constructs an {@link OAuth2ClientAuthenticationToken} using the provided parameters.
     *
     * @param registeredClient the registered client
     */
    public OAuth2ClientAuthenticationToken(RegisteredClient registeredClient) {
        super(Collections.emptyList());
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        this.registeredClient = registeredClient;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return registeredClient != null ? registeredClient.getClientId() : clientId;
    }

    @Override
    public Object getPrincipal() {
        return clientSecret;
    }

    /**
     * Returns the {@link RegisteredClient registered client}
     *
     * @return the {@link RegisteredClient}
     */
    @Nullable
    public RegisteredClient getRegisteredClient() {
        return registeredClient;
    }
}
