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
 * <p>This test encrypts a session key using a public key, encrypts it and then tries to load it back using the private key.</p>
 * <p>If this works, one can be reasonably sure that the session key is being written in a compatible format.</p>
 */
public class TestRSAPKESKP extends Test {
    
    /** Algorithm settings */
    public final int SymmetricAlgorithm = 1; // idea
    public final int PKAlgorithm = 1; // rsa enc & sign
    
    /** Creates a new instance of TestRSAPKESKP */
    public TestRSAPKESKP() {
        setTestName("Test RSA Public Key Encrypted SK packet"); // name of the test to be printed on the console.
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestRSAPKESKP t = new TestRSAPKESKP();
        
        t.printWelcome();
        
        t.doTest();
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean test() throws Exception {
        
        boolean result = true;
        
        System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());

        // generate key pair
        System.out.println("Generating RSA keypair...");
            KeyPairGenerator k = KeyPairGenerator.getInstance(PublicKeyAlgorithmSettings.getCipherText(PKAlgorithm), "BC");
            k.initialize(PublicKeyAlgorithmSettings.getDefaultKeySize(PKAlgorithm), SecureRandom.getInstance("SHA1PRNG"));

            KeyPair kp = k.generateKeyPair();

        // generate session key
        System.out.println("Generating a session key...");
            KeyGenerator k2 = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm), "BC");
            k2.init(SecureRandom.getInstance("SHA1PRNG"));
            Key key = k2.generateKey();

            SessionKey sk = new SessionKey(SymmetricAlgorithm, key.getEncoded());

        // encrypt session key
        System.out.println("Creating new Public Key Encrypted Session Key Packet...");
            byte keyid[] = new byte[8];
            for (int n = 0; n<keyid.length; n++) keyid[n] = 0x00;

            PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(kp.getPublic(),keyid,PKAlgorithm,sk);


        // write session key
        System.out.println("Writing packet...");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            OpenPGPPacketOutputStream outstream = new OpenPGPPacketOutputStream(out);
            outstream.writePacket(pkeskp);
            outstream.close();

        // read session key
        System.out.println("Reading packet...");
            ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
            OpenPGPPacketInputStream instream = new OpenPGPPacketInputStream(in);

            PublicKeyEncryptedSessionKeyPacket pkeskp2 = (PublicKeyEncryptedSessionKeyPacket)instream.readPacket();

        // compare
        System.out.print("Comparing session keys...");
            SessionKey sk2 = pkeskp2.getSessionKey(kp.getPrivate());
            if (sk.getAlgorithm()!=sk2.getAlgorithm()) 
                throw new Exception("Algorithm codes are different!");
            if (sk.getSessionKey().length != sk2.getSessionKey().length)
                throw new Exception("Session key lengths are different!");

            byte []rawsk1 = sk.getSessionKey();
            byte []rawsk2 = sk2.getSessionKey();
            for (int n = 0; n<sk.getSessionKey().length; n++)
                if (rawsk1[n]!=rawsk2[n]) throw new Exception("Session keys are different!");

            System.out.println("Ok.");
                    
        
        // if we got this far then the test should have gone ok
        return result;
            
    }
    
}
