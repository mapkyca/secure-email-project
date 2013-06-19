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
 * <p>A test app to better diagnose exactly what is going wrong with the MPI class.</p>
 */
public class TestMPIBug2 extends Test {
    
    /** Creates a new instance of TestMPIBug2 */
    public TestMPIBug2() {
        setTestName("Test MPI Bug 2"); // name of the test to be printed on the console.
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestMPIBug2 t = new TestMPIBug2();

        t.printWelcome();

        t.doTest();
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean test() throws Exception {
       
        for (int n = 0; n < 50; n++) {
            System.out.println("Test "+n+": ");
            BigInteger x = new BigInteger(64, SecureRandom.getInstance("SHA1PRNG"));
            BigInteger y = MPI.valueOf(MPI.toByteArray(x));

            System.out.println("X: "+x.toString(16));
            System.out.println("Y: "+y.toString(16));

            if ((x.compareTo(y)!=0) || 
                (x.bitLength()!=y.bitLength()) || 
                (x.bitCount()!=y.bitCount()) ||
                (x.equals(y)!=true)
            )
                return false;
        }
            
        return true;
    }
    
}
