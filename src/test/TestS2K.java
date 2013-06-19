/*
 * Oxford Brookes University Secure Email Proxy 
 * Copyright (C) 2002/3 Oxford Brookes University Secure Email Project
 * http://secemail.brookes.ac.uk
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 * The Secure Email Project is:
 * 
 * Marcus Povey <mpovey@brookes.ac.uk> or <icewing@dushka.co.uk>
 * Damian Branigan <dbranigan@brookes.ac.uk>
 * George Davson <gdavson@brookes.ac.uk>
 * David Duce <daduce@brookes.ac.uk>
 * Simon Hogg <simon.hogg@brookes.ac.uk>
 * Faye Mitchell <frmitchell@brookes.ac.uk>
 * 
 * For further information visit the secure email project website.
 */

package test;
import java.security.*;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;

/**
 * <p>This class tests the S2K key generator.</p>
 * <p>It will attempt to encrypt and decrypt arbitrary data using a key generated from
 * a given passphrase for each possible S2K convention - simple, Salted and Itterated Salted.</p>
 */
public class TestS2K extends Test {
    
    public final String passPhrase = "This is the passphrase";
    public final String rawdata = "This is some raw data that will be encrypted, but maybe its a bit bugged and needs some more stuff here......1234567890";
    public final int skalgorithm = 1;
    public final int hashalgorithm = 1;

    
    /** Creates a new instance of TestS2K */
    public TestS2K() {
        setTestName("Test S2K Key generator"); // name of the test to be printed on the console.
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestS2K t = new TestS2K();
        
        t.printWelcome();
        
        t.doTest();
    }
    
    protected byte[] generateSalt() throws Exception {
      
        System.out.println("  Generating salt...");

        byte salt[] = new byte[8];

        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.nextBytes(salt);

        return salt;
       
    }
    
    protected byte[] encrypt(Key key, byte[] data) throws Exception {

        System.out.println("  Encrypting using key...");

        int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(skalgorithm)/8;

        // create IV
        byte[] ivdata = new byte[blockSize+2];
        SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
        rnd.nextBytes(ivdata);
        ivdata[8] = ivdata[blockSize-2];
        ivdata[9] = ivdata[blockSize-1];
        IvParameterSpec iv = new IvParameterSpec(ivdata);

        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getFullCipherText(skalgorithm),"BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(data);  
    }
    
    protected byte[] decrypt(Key key, byte[] data) throws Exception {

        System.out.println("  Decrypting using key...");

        int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(skalgorithm)/8;

        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getFullCipherText(skalgorithm),"BC");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(data);
    }
    
    protected void compare(byte dec[]) throws Exception {
        
        System.out.println("  Comparing decrypted data with original...");
        
        if (dec.length!=rawdata.getBytes().length) 
            throw new Exception("Decrypted data is the wrong length!");
        for (int n = 0; n<dec.length; n++) 
            if (dec[n]!=rawdata.getBytes()[n]) 
                throw new Exception("Decrypted data is not the same as original!\n ("
                    + new String(dec) + ")");
    }
    
    protected boolean simple() throws Exception {
        System.out.println("Testing Simple S2K...");
        
        S2K s2k1 = new S2K(hashalgorithm);
        Key k1 = s2k1.generateKey(passPhrase.getBytes(), skalgorithm);
        byte enc[] = encrypt(k1, rawdata.getBytes());
        
        S2K s2k2 = new S2K(hashalgorithm);
        Key k2 = s2k2.generateKey(passPhrase.getBytes(), skalgorithm);
        byte dec[] = decrypt(k2, enc);
        
        compare(dec);
        
        return true;
    }
    
    protected boolean salted() throws Exception {
        System.out.println("Testing Salted S2K...");
        
        byte salt[] = generateSalt();
        
        S2K s2k1 = new S2K(hashalgorithm, salt);
        Key k1 = s2k1.generateKey(passPhrase.getBytes(), skalgorithm);
        byte enc[] = encrypt(k1, rawdata.getBytes());
        
        S2K s2k2 = new S2K(hashalgorithm, salt);
        Key k2 = s2k2.generateKey(passPhrase.getBytes(), skalgorithm);
        byte dec[] = decrypt(k2, enc);
        
        compare(dec);
        
        return true;
    }
    
    protected boolean itterated() throws Exception {
        System.out.println("Testing Itterated S2K...");
        
        byte salt[] = generateSalt();
        
        S2K s2k1 = new S2K(hashalgorithm, salt, 2);
        Key k1 = s2k1.generateKey(passPhrase.getBytes(), skalgorithm);
        byte enc[] = encrypt(k1, rawdata.getBytes());
        
        S2K s2k2 = new S2K(hashalgorithm, salt, 2);
        Key k2 = s2k2.generateKey(passPhrase.getBytes(), skalgorithm);
        byte dec[] = decrypt(k2, enc);
        
        compare(dec);
        
        return true;
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean test() throws Exception {
        boolean result = false;

        System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());
        
        try {
            result = simple();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            result = false;
        }
        
        try {
            result = salted();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            result = false;
        }
        
        try {
            result = itterated();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            result = false;
        }
        
        // if we got this far then the test should have gone ok
        return result;
    }
    
}
