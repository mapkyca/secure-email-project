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
import java.security.spec.RSAPublicKeySpec;


/**
 * <p>This test generates a random RSA keypair, writes them as an MPI and reads them back in.</p>
 * <p>This is done a number of times. If the bug is present, the RSA cipher will throw an exception
 * with the value "attempt to process message to long for cipher"
 */
public class TestMPIBug extends Test {
    
    /** Algorithm settings */
    public final int SymmetricAlgorithm = 1; // idea
    public final int PKAlgorithm = 1; // rsa enc & sign
    
    private int itterations;
    
    /** Creates a new instance of TestMPIBug */
    public TestMPIBug(int its) {
        setTestName("Test MPI bug"); // name of the test to be printed on the console.
        
        itterations = its;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("TestMPIBug");
            System.out.println();
            System.out.println("Usage: java test.TestMPIBug itterations");
            System.out.println();
            System.out.println("Itterations = number of times the test is run & the max number of bytes\nto test with the cipher.");
        } else {
            TestMPIBug t = new TestMPIBug(Integer.parseInt(args[0]));

            t.printWelcome();

            t.doTest();
        }
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean test() throws Exception {
        boolean result = true;

        System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());

        for (int n=0; n<itterations; n++) {
            System.out.println("Running test "+n+"...");

            // generate key pair
                KeyPairGenerator k = KeyPairGenerator.getInstance(PublicKeyAlgorithmSettings.getCipherText(PKAlgorithm), "BC");
                k.initialize(PublicKeyAlgorithmSettings.getDefaultKeySize(PKAlgorithm), SecureRandom.getInstance("SHA1PRNG"));

                KeyPair kp = k.generateKeyPair();

            // generate session key
                KeyGenerator k2 = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm), "BC");
                k2.init(SecureRandom.getInstance("SHA1PRNG"));
                Key key = k2.generateKey();

                SessionKey sk = new SessionKey(SymmetricAlgorithm, key.getEncoded());

            // encrypt session key
                byte keyid[] = new byte[8];
                for (int na = 0; na<keyid.length; na++) keyid[na] = 0x00;

                PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(kp.getPublic(),keyid,PKAlgorithm,sk);


            // write session key
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                OpenPGPPacketOutputStream outstream = new OpenPGPPacketOutputStream(out);
                outstream.writePacket(pkeskp);
                outstream.close();

            // read session key
                ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
                OpenPGPPacketInputStream instream = new OpenPGPPacketInputStream(in);

                PublicKeyEncryptedSessionKeyPacket pkeskp2 = (PublicKeyEncryptedSessionKeyPacket)instream.readPacket();

            // compare
                SessionKey sk2 = pkeskp2.getSessionKey(kp.getPrivate());
                if (sk.getAlgorithm()!=sk2.getAlgorithm()) 
                    throw new Exception("Algorithm codes are different!");
                if (sk.getSessionKey().length != sk2.getSessionKey().length)
                    throw new Exception("Session key lengths are different!");

                byte []rawsk1 = sk.getSessionKey();
                byte []rawsk2 = sk2.getSessionKey();
                for (int na = 0; na<sk.getSessionKey().length; na++)
                    if (rawsk1[na]!=rawsk2[na]) throw new Exception("Session keys are different!");
        }
            
        return result;
    }
    
}
