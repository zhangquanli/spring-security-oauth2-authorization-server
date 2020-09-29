package org.springframework.security.core;

/**
 * Internal class used for serialization across Spring Security Authorization Server classes.
 *
 * @since 0.0.1
 */
public class SpringSecurityCoreVersion2 {
    private static final int MAJOR = 0;
    private static final int MINOR = 0;
    private static final int PATCH = 1;

    /**
     * Global Serialization value for Spring Security Authorization Server classes.
     */
    public static final long SERIAL_VERSION_UID = getVersion().hashCode();

    public static String getVersion() {
        return MAJOR + "." + MINOR + "." + PATCH;
    }
}
