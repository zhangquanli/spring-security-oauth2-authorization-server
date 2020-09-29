package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link RegisteredClientRepository} that stores {@link RegisteredClient}(s) in-memory.
 *
 * @author Anoop Garlapati
 * @see RegisteredClientRepository
 * @see RegisteredClient
 * @since 0.0.1
 */
public final class InMemoryRegisteredClientRepository implements RegisteredClientRepository {
    private final Map<String, RegisteredClient> idRegistrationMap;
    private final Map<String, RegisteredClient> clientIdRegistrationMap;

    /**
     * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
     *
     * @param registrations the client registration(s)
     */
    public InMemoryRegisteredClientRepository(RegisteredClient... registrations) {
        this(Arrays.asList(registrations));
    }

    /**
     * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
     *
     * @param registrations the client registration(s)
     */
    public InMemoryRegisteredClientRepository(List<RegisteredClient> registrations) {
        Assert.notEmpty(registrations, "registrations cannot be empty");
        Map<String, RegisteredClient> idRegistrationMapResult = new ConcurrentHashMap<>();
        Map<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
        for (RegisteredClient registration : registrations) {
            Assert.notNull(registration, "registration cannot be null");
            String id = registration.getId();
            if (idRegistrationMapResult.containsKey(id)) {
                throw new IllegalArgumentException("Registered client must be unique. " +
                        "Found duplicate identifier: " + id);
            }
            String clientId = registration.getClientId();
            if (clientIdRegistrationMapResult.containsKey(clientId)) {
                throw new IllegalArgumentException("Registered client must be unique. " +
                        "Found duplicate client identifier: " + clientId);
            }
            idRegistrationMapResult.put(id, registration);
            clientIdRegistrationMapResult.put(clientId, registration);
        }
        idRegistrationMap = idRegistrationMapResult;
        clientIdRegistrationMap = clientIdRegistrationMapResult;
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return idRegistrationMap.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return clientIdRegistrationMap.get(clientId);
    }
}
