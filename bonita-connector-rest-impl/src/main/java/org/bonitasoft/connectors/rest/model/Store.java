package org.bonitasoft.connectors.rest.model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * A basic key store to be used in a HTTP request.
 */
public class Store {
    
    /**
     * The type of the key store.
     */
    private static String keyStoreType = "JKS";
    
    /**
     * The file.
     */
    private File file = null;
    
    /**
     * The password.
     */
    private String password = null;

    /**
     * Generate the key store based on the options.
     * @return The generated key store.
     * @throws Exception In case of any exception
     */
    public KeyStore generateKeyStore() throws Exception {
        KeyStore store  = KeyStore.getInstance(keyStoreType);
        if (file != null) {
            try (FileInputStream instream = new FileInputStream(file)) {
                store.load(instream, password.toCharArray());
            }
        }
        return store;
    }

    /**
     * File value getter.
     * @return The file value.
     */
    public File getFile() {
        return file;
    }
    
    /**
     * File value setter.
     * @param file The new file value.
     */
    public void setFile(final File file) {
        this.file = file;
    }

    /**
     * Password value getter.
     * @return The password value.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Password value setter.
     * @param password The password file value.
     */
    public void setPassword(final String password) {
        this.password = password;
    }
    
}
