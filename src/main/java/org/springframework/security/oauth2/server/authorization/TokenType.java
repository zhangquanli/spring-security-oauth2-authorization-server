package org.springframework.security.oauth2.server.authorization;

import org.springframework.security.core.SpringSecurityCoreVersion2;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Objects;

/**
 * @author Joe Grandja
 */
public final class TokenType implements Serializable {
    private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
    public static final TokenType ACCESS_TOKEN = new TokenType("access_token");
    public static final TokenType AUTHORIZATION_CODE = new TokenType("authorization_code");
    private final String value;

    public TokenType(String value) {
        Assert.hasText(value, "value cannot be empty");
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        TokenType tokenType = (TokenType) o;
        return Objects.equals(value, tokenType.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
