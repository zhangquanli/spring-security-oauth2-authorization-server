package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.core.SpringSecurityCoreVersion2;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * A representation of a client registration with an OAuth 2.0 Authorization Server.
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2 Client Registration</a>
 * @since 0.0.1
 */
public class RegisteredClient implements Serializable {
    private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
    private String id;
    private String clientId;
    private String clientSecret;
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;

    protected RegisteredClient() {
    }

    /**
     * Returns the identifier for the registration.
     *
     * @return the identifier for the registration
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the client identifier.
     *
     * @return the client identifier
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Returns the client secret.
     *
     * @return the client secret
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Returns the {@link ClientAuthenticationMethod authentication method(s)} used
     * when authenticating the client with the authorization server.
     *
     * @return the {@code Set} of {@link ClientAuthenticationMethod authentication method(s)}
     */
    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }

    /**
     * Returns the {@link AuthorizationGrantType authorization grant type(s)} that the client may use.
     *
     * @return the {@code Set} of {@link AuthorizationGrantType authorization grant type(s)}
     */
    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return authorizationGrantTypes;
    }

    /**
     * Returns the redirect URI(s) that the client may use in redirect-base flows.
     *
     * @return the {@code Set} of redirect URI(s)
     */
    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    /**
     * Returns the scope(s) used by the client.
     *
     * @return the {@code Set} of scope(s)
     */
    public Set<String> getScopes() {
        return scopes;
    }

    @Override
    public String toString() {
        return "RegisteredClient{" +
                "id='" + id + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                ", clientAuthenticationMethods=" + clientAuthenticationMethods +
                ", authorizationGrantTypes=" + authorizationGrantTypes +
                ", redirectUris=" + redirectUris +
                ", scopes=" + scopes +
                '}';
    }

    /**
     * Returns a new {@link Builder}, initialized with the provided registration identifier.
     *
     * @param id the identifier for the registration
     * @return the {@link Builder}
     */
    public static Builder withId(String id) {
        Assert.hasText(id, "id cannot be empty");
        return new Builder(id);
    }

    /**
     * Returns a new {@link Builder}, initialized with the provided {@link RegisteredClient}.
     *
     * @param registeredClient the {@link RegisteredClient} to copy from
     * @return the {@link Builder}
     */
    public static Builder withRegisteredClient(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient);
    }

    /**
     * A builder for {@link RegisteredClient}.
     */
    public static class Builder implements Serializable {
        private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
        private String id;
        private String clientId;
        private String clientSecret;
        private Set<ClientAuthenticationMethod> clientAuthenticationMethods = new LinkedHashSet<>();
        private Set<AuthorizationGrantType> authorizationGrantTypes = new LinkedHashSet<>();
        private Set<String> redirectUris = new LinkedHashSet<>();
        private Set<String> scopes = new LinkedHashSet<>();

        protected Builder(String id) {
            this.id = id;
        }

        protected Builder(RegisteredClient registeredClient) {
            id = registeredClient.id;
            clientId = registeredClient.id;
            clientSecret = registeredClient.clientSecret;
            if (!CollectionUtils.isEmpty(registeredClient.clientAuthenticationMethods)) {
                clientAuthenticationMethods.addAll(registeredClient.clientAuthenticationMethods);
            }
            if (!CollectionUtils.isEmpty(registeredClient.authorizationGrantTypes)) {
                authorizationGrantTypes.addAll(registeredClient.authorizationGrantTypes);
            }
            if (!CollectionUtils.isEmpty(registeredClient.redirectUris)) {
                redirectUris.addAll(registeredClient.redirectUris);
            }
            if (!CollectionUtils.isEmpty(registeredClient.scopes)) {
                scopes.addAll(registeredClient.scopes);
            }
        }

        /**
         * Sets the identifier for the registration.
         *
         * @param id the identifier for the registration
         * @return the {@link Builder}
         */
        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /**
         * Sets the client identifier.
         *
         * @param clientId the client identifier
         * @return the {@link Builder}
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the client secret.
         *
         * @param clientSecret the client secret
         * @return the {@link Builder}
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Adds an {@link ClientAuthenticationMethod authentication method}
         * the client may use when authenticating with the authorization server.
         *
         * @param clientAuthenticationMethod the authentication method
         * @return the {@link Builder}
         */
        public Builder clientAuthorizationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
            clientAuthenticationMethods.add(clientAuthenticationMethod);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link ClientAuthenticationMethod authentication method(s)}
         * allowing the ability to add, replace, or remove.
         *
         * @param clientAuthorizationMethodsConsumer a {@code Consumer} of the authentication method(s)
         * @return the {@link Builder}
         */
        public Builder clientAuthorizationMethods(
                Consumer<Set<ClientAuthenticationMethod>> clientAuthorizationMethodsConsumer) {
            clientAuthorizationMethodsConsumer.accept(clientAuthenticationMethods);
            return this;
        }

        /**
         * Adds an {@link AuthorizationGrantType authorization gran type} the client may use.
         *
         * @param authorizationGrantType the authorization grant type
         * @return the {@link Builder}
         */
        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            authorizationGrantTypes.add(authorizationGrantType);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link AuthorizationGrantType authorization grant type(s)}
         * allowing the ability to add, replace, or remove.
         *
         * @param clientAuthorizationMethodsConsumer a {@code Consumer} of authorization grant type(s)
         * @return the {@link Builder}
         */
        public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> clientAuthorizationMethodsConsumer) {
            clientAuthorizationMethodsConsumer.accept(authorizationGrantTypes);
            return this;
        }

        /**
         * Adds a redirect URI the client may use in a redirect-based flow.
         *
         * @param redirectUri the redirect URI
         * @return the {@link Builder}
         */
        public Builder redirectUri(String redirectUri) {
            redirectUris.add(redirectUri);
            return this;
        }

        /**
         * A {@code Consumer} of the redirect URI(s).
         * allowing the ability to add, replace, or remove.
         *
         * @param redirectUrisConsumer a {@code Consumer} of the redirect URI(s)
         * @return the {@link Builder}
         */
        public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer) {
            redirectUrisConsumer.accept(redirectUris);
            return this;
        }

        /**
         * Adds a scope the client may use.
         *
         * @param scope the scope
         * @return the {@link Builder}
         */
        public Builder scope(String scope) {
            scopes.add(scope);
            return this;
        }

        /**
         * A {@code Consumer} of the scope(s)
         * allowing the ability to add, replace, or remove.
         *
         * @param scopesConsumer a {@code Consumer} of the scope(s)
         * @return the {@link Builder}
         */
        public Builder scopes(Consumer<Set<String>> scopesConsumer) {
            scopesConsumer.accept(scopes);
            return this;
        }

        /**
         * Builds a new {@link RegisteredClient}.
         *
         * @return a {@link RegisteredClient}
         */
        public RegisteredClient build() {
            Assert.hasText(clientId, "clientId cannot be empty");
            Assert.notEmpty(authorizationGrantTypes, "authorizationGrantTypes cannot be empty");
            if (authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                Assert.hasText(clientSecret, "clientSecret cannot be empty");
                Assert.notEmpty(redirectUris, "redirectUris cannot be empty");
            }
            if (CollectionUtils.isEmpty(clientAuthenticationMethods)) {
                clientAuthenticationMethods.add(ClientAuthenticationMethod.BASIC);
            }
            validateScopes();
            validateRedirectUris();
            return create();
        }

        private void validateScopes() {
            if (CollectionUtils.isEmpty(scopes)) {
                return;
            }

            for (String scope : scopes) {
                Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
            }
        }

        private boolean validateScope(String scope) {
            return scope == null ||
                    scope.chars().allMatch(c -> withinTheRangeOf(c, 0x21, 0x21) ||
                            withinTheRangeOf(c, 0x23, 0x5B) ||
                            withinTheRangeOf(c, 0x5D, 0x7E));
        }

        private boolean withinTheRangeOf(int c, int min, int max) {
            return c >= min && c <= max;
        }

        private void validateRedirectUris() {
            if (CollectionUtils.isEmpty(redirectUris)) {
                return;
            }

            for (String redirectUri : redirectUris) {
                Assert.isTrue(validateRedirectUri(redirectUri),
                        "redirect_uri \"" + redirectUri + "\" is not a valid redirect URI or contains fragment");
            }
        }

        private boolean validateRedirectUri(String redirectUri) {
            try {
                URI validRedirectUri = new URI(redirectUri);
                return validRedirectUri.getFragment() == null;
            } catch (URISyntaxException e) {
                return false;
            }
        }

        private RegisteredClient create() {
            RegisteredClient registeredClient = new RegisteredClient();

            registeredClient.id = id;
            registeredClient.clientId = clientId;
            registeredClient.clientSecret = clientSecret;
            registeredClient.clientAuthenticationMethods =
                    Collections.unmodifiableSet(clientAuthenticationMethods);
            registeredClient.authorizationGrantTypes = Collections.unmodifiableSet(authorizationGrantTypes);
            registeredClient.redirectUris = Collections.unmodifiableSet(redirectUris);
            registeredClient.scopes = Collections.unmodifiableSet(scopes);

            return registeredClient;
        }
    }
}
