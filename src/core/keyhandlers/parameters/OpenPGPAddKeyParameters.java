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

package core.keyhandlers.parameters;
import core.keyhandlers.KeyHandlerParameters;
import java.util.Date;

/**
 * <p>A class holding the information necessary to add an OpenPGP key to a key store.</p>
 */
public class OpenPGPAddKeyParameters implements KeyHandlerParameters {
    
    /** Public key algorithm of the key being added.*/
    private int publicKeyAlgorithm;
    
    /** A list of symmetric algorithm preferences. */
    private byte[] symmetricAlgorithmPrefs;
    
    /** The date to stamp the packet as created. */
    private Date creationDate;
    
    /** Creates a new instance of OpenPGPAddKeyParameters.
     * @param creationDate the creation date that will be set in the key packet.
     * @param keyAlgorithm The public key algorithm of the key.
     * @param symmetricPrefs An ordered list denoting symmetric encryption algorithm preferences (only used on primary keys).
     */
    public OpenPGPAddKeyParameters(Date creationDate, int keyAlgorithm, byte [] symmetricPrefs) {
        setCreationDate(creationDate);
        setPublicKeyAlgorithm(keyAlgorithm);
        setSymmetricAlgorithmPrefs(symmetricPrefs);
    }
    
    /** 
     * <p>Return the PGP Public key algorithm being used.</p>
     * <p>Returns the PGP code for the public key algorithm being used.</p>
     */
    public int getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }
    
    /** Set the public key algorithm being used. */
    protected void setPublicKeyAlgorithm(int alg) {
        publicKeyAlgorithm = alg;
    }
    
    /** 
     * <p>Return an ordered list of symmetric algorithm preferences.</p>
     */
    public byte[] getSymmetricAlgorithmPrefs() {
        return symmetricAlgorithmPrefs;
    }
    
    /** Set the symmetric algorithm being used. */
    protected void setSymmetricAlgorithmPrefs(byte prefs[]) {
        symmetricAlgorithmPrefs = prefs;
    }
    
    /** Get the creation date timestamp. */
    public Date getCreationDate() {
        return creationDate;
    }
    
    /** Set the creation date timestamp. */
    protected void setCreationDate(Date date) {
        creationDate = date;
    }
    

}
