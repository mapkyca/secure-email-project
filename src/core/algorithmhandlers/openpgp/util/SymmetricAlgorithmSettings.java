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

package core.algorithmhandlers.openpgp.util;
import core.exceptions.AlgorithmException;
import java.lang.String;

/**
 * <p>A class that returns settings for the symmetric key algorithm, translating the algorithm code into a symmetric cipher.</p>
 */
public class SymmetricAlgorithmSettings {
    
    public static final int IDEA = 1;
    public static final int TRIPLEDES = 2;
    public static final int CAST5 = 3;
   
    
    /**
     * <p>A method that returns a correctly formatted cipher text string for creating a JCE cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported. 
     */
    public static String getCipherText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case IDEA : return "IDEA";
            case TRIPLEDES : return "DESede"; 
            case CAST5 : return "CAST5";
            default : throw new AlgorithmException("Requested symmetric algorithm (" + algorithm + ") not supported.");
        }
    }
    
    
    /**
     * <p>A method for returning the default mode for a given cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported. 
     */
    public static String getModeText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case IDEA : 
            case TRIPLEDES : 
            case CAST5 : return "PGPCFBwithIV";
            default : throw new AlgorithmException("Requested symmetric algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /**
     * <p>A method for returning the default padding for a given cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported. 
     */
    public static String getPaddingText(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case IDEA :
            case TRIPLEDES : 
            case CAST5 : return "NoPadding";
            default : throw new AlgorithmException("Requested symmetric algorithm (" + algorithm + ") not supported.");
        }
    }
   
    /**
     * <p>A method for returning the default key size for a given cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported. 
     */
    public static int getDefaultKeySize(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case IDEA : 
            case TRIPLEDES : 
            case CAST5 : return 128;
            default : throw new AlgorithmException("Requested symmetric algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /**
     * <p>A method for returning the default block size in bits for a given cipher.</p>
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static int getDefaultBlockSize(int algorithm) throws AlgorithmException {
        switch (algorithm) {
            case IDEA : 
            case TRIPLEDES : 
            case CAST5 : return 64;
            default : throw new AlgorithmException("Requested symmetric algorithm (" + algorithm + ") not supported.");
        }
    }
    
    /** A convenient method to return the full text needed to create a given cipher.
     * @throws AlgorithmException if the requested algorithm is not supported.
     */
    public static String getFullCipherText(int algorithm) throws AlgorithmException {
        return SymmetricAlgorithmSettings.getCipherText(algorithm) + "/" + SymmetricAlgorithmSettings.getModeText(algorithm) + "/" + SymmetricAlgorithmSettings.getPaddingText(algorithm);
    }
}
