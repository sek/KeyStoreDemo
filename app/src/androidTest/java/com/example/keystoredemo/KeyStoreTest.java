package com.example.keystoredemo;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.test.InstrumentationTestCase;
import android.util.Base64;

import org.joda.time.DateTime;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.greaterThan;

public class KeyStoreTest extends InstrumentationTestCase {

    private KeyPair keyPair;
    private KeyStore keyStore;
    private final String alias = "test-key";
    private SharedPreferences sharedPrefs;
    private Context ctx;

    public void setUp() throws Exception {
        ctx = getInstrumentation().getTargetContext();
        sharedPrefs = ctx.getSharedPreferences("db", Context.MODE_PRIVATE);

        keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        kpg.initialize(new KeyPairGeneratorSpec.Builder(ctx)
                .setAlias(alias)
                .setStartDate(Calendar.getInstance().getTime())
                .setEndDate(new DateTime(2045, 1, 1, 0, 0).toDate())
                .setSerialNumber(BigInteger.valueOf(1))
                .setSubject(new X500Principal("CN=test1"))
                .build());

        keyPair = kpg.generateKeyPair();

        final PublicKey publicKey = keyPair.getPublic();
        assertNotNull(publicKey);
        assertTrue(publicKey.getEncoded().length > 10);

        final PrivateKey privateKey = keyPair.getPrivate();
        assertNotNull(privateKey);
    }

    public void tearDown() throws Exception {
        keyStore.deleteEntry(alias);
        assertThat(enumerationToList(keyStore.aliases()), not(contains(alias)));
        sharedPrefs.edit().clear().apply();
    }

    public void testListingEntries() throws Exception {
        assertThat(enumerationToList(keyStore.aliases()), contains(alias));
    }

    public void testStoringAndRetrievingPreferences() {
        assertEquals("default", sharedPrefs.getString("prefs-value", "default"));
        sharedPrefs.edit().putString("prefs-value", "value1").apply();
        assertEquals("value1", sharedPrefs.getString("prefs-value", ""));
    }

    public void testStoringDBPasswordUsingPrivateKey() throws Exception {
        final String dbPassword = "fakeDbPassword";
        String encryptedPassword = encrypt(dbPassword);
        assertThat(encryptedPassword.length(), greaterThan(20));

        // use Preferences API to store the public key encrypted password
        sharedPrefs.edit().putString("encryption.password", encryptedPassword).apply();

        // retrieve from Preferences and decrpyt using the private key
        encryptedPassword = null;
        encryptedPassword = sharedPrefs.getString("encryption.password", null);
        assertEquals(dbPassword, decrypt(encryptedPassword));
    }

    private String decrypt(String encryptedText) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

        Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
        output.init(Cipher.DECRYPT_MODE, privateKey);

        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(Base64.decode(encryptedText, Base64.DEFAULT)), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i);
        }

        return new String(bytes, 0, bytes.length, "UTF-8");
    }

    private String encrypt(String plainText) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

        Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
        input.init(Cipher.ENCRYPT_MODE, publicKey);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, input);
        cipherOutputStream.write(plainText.getBytes("UTF-8"));
        cipherOutputStream.close();

        byte[] encrypted = outputStream.toByteArray();
        // could also use RMONTools.bytesToHexString
        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    private ArrayList<String> enumerationToList(Enumeration<String> strings) {
        ArrayList<String> result = new ArrayList<>();
        while (strings.hasMoreElements()) {
            result.add(strings.nextElement());
        }
        return result;
    }

    // before running this test lock the screen
    public void testInteractionWithScreenLock() {
        final KeyguardManager keyguardManager = (KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
        assertTrue(keyguardManager.isKeyguardSecure());
        assertTrue(keyguardManager.isKeyguardLocked());
        // API Level 21 - ignores SIM locked status
//        assertTrue(keyguardManager.isDeviceSecure());
    }
}