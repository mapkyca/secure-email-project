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
import java.math.BigInteger;
import java.io.*;


/**
 * <p>A class representing an OpenPGP Multi-precision Integer (MPI).</p>
 */
public class MPI {
    
    /** Storage for the MPI */
    private BigInteger value;
    
    /** Creates a new instance of MPI out of a BigInteger*/
    public MPI(BigInteger mpi) {
        value = mpi;
    }
    
    /** Create a new instance of MPI from a byte array.
     * @throws AlgorithmException if there was a problem.
     */
    public MPI(byte mpi[]) throws AlgorithmException {
        value = valueOf(mpi);
    }
    
    /** Create a new instance of MPI from a byte stream.
     * @throws AlgorithmException if there was a problem.
     */
    public MPI(InputStream in) throws AlgorithmException {
        value = valueOf(in);
    }
    
    /** Return the value of the MPI */
    public BigInteger getValue() {
        return value;
    }
    
    /** Encode the MPI into a byte array according to the OpenPGP spec 
     * @throws AlgorithmException if there was a problem
     */
    public byte[] toByteArray() throws AlgorithmException {
        return toByteArray(value);
    }
    
    /** Encodes big integer mpi to an MPI byte array according to the OpenPGP spec 
     * @throws AlgorithmException if there was a problem
     */
    public static byte[] toByteArray(BigInteger mpi) throws AlgorithmException {
       try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // write size
            out.write((mpi.bitLength() >> 8) & 0xFF);
            out.write(mpi.bitLength() & 0xFF);

            // remove zeros and write data 
            byte data[] = mpi.toByteArray(); 

            if (data[0] == 0) {              
                out.write(data, 1, data.length-1); // remove unnecessary significant 0's
            } else {
               out.write(data);
            }
            byte[] tmp = out.toByteArray();
       
            return tmp;
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
       
    }
    
    /** Decode a MPI byte array data into a big integer 
     * @throws AlgorithmException if there was a problem
     */
    public static BigInteger valueOf(byte data[]) throws AlgorithmException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        return valueOf(in);   
    }
    
    /** Decode a MPI byte array data into a big integer from a byte stream 
     * @throws AlgorithmException if there was a problem
     */
    public static BigInteger valueOf(InputStream in) throws AlgorithmException {
        try {
            int size = (((in.read() & 0xFF ) << 8) | (in.read() & 0xFF));

            byte[] data = new byte[(size + 7) / 8];
            in.read(data);

            return new BigInteger(1,data); // return +ve BigInteger

        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    } 
    
    
    // These methods are a little HR, but they were necessary to overcome an intermittant bug to do with
    // loosing the sign value.
    // TODO: Clean this up a bit.
    
    /** Encodes mpi data in the form of a byte array to an MPI byte array compatible 
     * with the OpenPGP spec.
     * @param data Raw number data.
     * @throws AlgorithmException if there was a problem
     */
    public static byte[] toByteArray(byte data[]) throws AlgorithmException {
        
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            byte tmp[] = data;
            
            // adjust for length if necessary
            if (data[0] == 0) {
                tmp = new byte[data.length-1];
                System.arraycopy(data,1,tmp,0,data.length-1);
            }
            
            // write size
            out.write(((tmp.length * 8) >> 8) & 0xFF);
            out.write((tmp.length * 8) & 0xFF);
            
            // write mpi data
            out.write(tmp);
            
            // return byte array
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /** Decode a MPI byte array data into a raw data byte array from a byte stream. 
     * @throws AlgorithmException if there was a problem
     */
    public static byte[] getBytes(InputStream in) throws AlgorithmException {
        try {
            // read the size
            int size = (((in.read() & 0xFF ) << 8) | (in.read() & 0xFF));

            // read the data
            byte[] data = new byte[(size + 7) / 8];
            in.read(data);
            
            return data;
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /** Decode a MPI byte array data into a raw data byte array from a byte array. 
     * @throws AlgorithmException if there was a problem
     */
    public static byte[] getBytes(byte data[]) throws AlgorithmException {  
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        return getBytes(in); 
    }
}
