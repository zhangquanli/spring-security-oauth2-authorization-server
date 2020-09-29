package org.springframework.security.oauth2.server.authorization.client;

/**
 * A repository for OAuth 2.0 {@link RegisteredClient}(s)
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @see RegisteredClient
 * @since 0.0.1
 */
public interface RegisteredClientRepository {

    /**
     * Return the registered client identified by the provided {@code id}, or {@code null} if not found.
     *
     * @param id the registration identifier
     * @return the {@link RegisteredClient} if found, otherwise {@code null}
     */
    RegisteredClient findById(String id);

    /**
     * Returns the registered client identified by the provided {@code clientId}, or {@code null} if not found.
     *
     * @param clientId the client identifier
     * @return the {@link RegisteredClient} if found, otherwise {@code null}
     */
    RegisteredClient findByClientId(String clientId);

}
