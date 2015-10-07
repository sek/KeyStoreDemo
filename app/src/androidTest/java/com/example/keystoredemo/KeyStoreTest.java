package com.example.keystoredemo;

import android.security.KeyPairGeneratorSpec;
import android.test.InstrumentationTestCase;

import org.joda.time.DateTime;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

public class KeyStoreTest extends InstrumentationTestCase {
    public void testCreateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        String alias = "test-key";

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        kpg.initialize(new KeyPairGeneratorSpec.Builder(getInstrumentation().getTargetContext())
                .setAlias(alias)
                .setStartDate(Calendar.getInstance().getTime())
                .setEndDate(new DateTime(2045,1,1,0,0).toDate())
                .setSerialNumber(BigInteger.valueOf(1))
                .setSubject(new X500Principal("CN=test1"))
                .build());

        KeyPair kp = kpg.generateKeyPair();


        assertEquals("", kp.getPublic());
        assertEquals("", kp.getPrivate());
    }
}