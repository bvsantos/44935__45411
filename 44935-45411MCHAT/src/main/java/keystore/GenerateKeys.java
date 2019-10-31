package keystore;


import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class GenerateKeys {
    private static final String KEYSTORE_LOCATION = "src/main/java/keystore/keystoreAES256.jks";
    private static final String KEYSTORE_PASS = "feialua";
    public static void main(String[] args) throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        //loadKey("");
        generateKey();
    }

    public static void generateKey()throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream stream = new FileInputStream(KEYSTORE_LOCATION);
        ks.load(stream, KEYSTORE_PASS.toCharArray());
        
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(KEYSTORE_PASS.toCharArray());

        ks.getEntry("JCEKS", protParam);

        // save my secret key

        KeyGenerator generator = KeyGenerator.getInstance("DES");

        generator.init(64);

        Key encryptionKey = generator.generateKey();
        KeyStore.SecretKeyEntry skEntry =
          new KeyStore.SecretKeyEntry((SecretKey) encryptionKey);
        //ks.setEntry("Csessionkey", skEntry, protParam);
        //KeyStore.SecretKeyEntry skEntry =
                new KeyStore.SecretKeyEntry((SecretKey) encryptionKey);
        ks.setEntry("Cmackm", skEntry, protParam);
//      KeyStore.SecretKeyEntry skEntry =
//                new KeyStore.SecretKeyEntry((SecretKey) encryptionKey);
        ks.setEntry("Cmacka", skEntry, protParam);

        // store away the keystore

        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream(KEYSTORE_LOCATION);
            ks.store(fos, KEYSTORE_PASS.toCharArray());
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
    }

    public static Key loadKey(String alias) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream stream = new FileInputStream(KEYSTORE_LOCATION);
        ks.load(stream, KEYSTORE_PASS.toCharArray());
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(KEYSTORE_PASS.toCharArray());

        ks.getEntry("JCEKS", protParam);
        return ks.getKey(alias, KEYSTORE_PASS.toCharArray());
/*
        Key sessionkey = ks.getKey("Asessionkey", KEYSTORE_PASS.toCharArray());
        Key mackm = ks.getKey("Amackm", KEYSTORE_PASS.toCharArray());
        Key macka = ks.getKey("Amacka", KEYSTORE_PASS.toCharArray());

        System.out.println(sessionkey.getAlgorithm());
        System.out.println(mackm.getAlgorithm());
        System.out.println(macka.getAlgorithm());
 */
    }
}