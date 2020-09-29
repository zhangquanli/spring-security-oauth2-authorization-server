package org.springframework.security.oauth2.server.authorization;

import org.springframework.lang.Nullable;

/**
 * Implementation of this interface are responsible for the management
 * of {@link OAuth2Authorization OAuth 2.0 Authorization(s)}
 *
 * @author Joe Grandja
 * @see OAuth2Authorization
 * @since 0.0.1
 */
public interface OAuth2AuthorizationService {

    /**
     * Saves the {@link OAuth2Authorization}.
     *
     * @param authorization the {@link OAuth2Authorization}
     */
    void save(OAuth2Authorization authorization);

    /**
     * Returns the {@link OAuth2Authorization} containing the provided {@code token},
     * or {@code null} if not found.
     *
     * @param token     the token credential
     * @param tokenType the {@link TokenType token type}
     * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
     */
    OAuth2Authorization findByToken(String token, @Nullable TokenType tokenType);

}
