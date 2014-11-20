package org.bonitasoft.connectors.rest.model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class RESTKeyStore {
    
    static private String KeyStoreType = "JKS";
    
    private File file;
    
    private String password;

    public KeyStore generateKeyStore() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore store  = KeyStore.getInstance(KeyStoreType);
        if(file != null) {
            try(FileInputStream instream = new FileInputStream(file)) {
                store.load(instream, password.toCharArray());
            }
        }
        return store;
    }

    public File getFile() {
        return file;
    }
    
    public void setFile(File file) {
        this.file = file;
    }

    
    public String getPassword() {
        return password;
    }

    
    public void setPassword(String password) {
        this.password = password;
    }
    
}
