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

package core.keyhandlers;
import java.security.*;
import java.io.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import core.algorithmhandlers.openpgp.util.*;
import core.algorithmhandlers.keymaterial.*;
import core.keyhandlers.parameters.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.keydata.*;
import core.exceptions.*;

/**
 * Implementation of an OpenPGP secret keyring.
 */
public class OpenPGPSecretKeyring extends OpenPGPKeyring {
    

    /** Creates a new instance of OpenPGPSecretKeyring */
    public OpenPGPSecretKeyring() {
    }
    
    /** Creates a new instance of OpenPGPSecretKeyring */
    public OpenPGPSecretKeyring(String filename, KeyHandlerParameters parameters) {
        super(filename, parameters);
    }
    
    /**
     * <p>Add a number of keys to the key store.</p>
     * <p>Stores a key in the key store with details specified by idDetails and parameters as necessary.</p>
     * <p>If a key with the same details already exists it is NOT replaced, this is up to you to do.</p>
     * <p>The first key in the array is added as a primary key (which must be capable of signing), all other keys are added as sub keys.</p>
     * @param key[] The keys to store. If key[n] is an instance of OpenPGPKeyData then if possible the existing key packet is used. This enables you to import keys from other key sources.
     * @param idDetails[] Information identifying the keys. Should be of type OpenPGPStandardKeyIdentifier. Must contain at least one entry.
     * @param parameters[] Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @throws KeyHandlerException if something went wrong.
     */
    public void addKeys(KeyData[] key, KeyIdentifier[] idDetails, KeyHandlerParameters[] parameters) throws KeyHandlerException {
        try{
            
            KeyPacket primaryKeyPacket = null;
            KeyPacket currentKeyPacket = null;
            OpenPGPAddSecretKeyParameters currentParam = null;
            
            // create / append key file
            OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(new FileOutputStream(getFileName(), true));
            
            // itterate through all given keys, first element is primary
            for (int n = 0; n < key.length; n++) {
                
                // check initial parameters
                if ((key==null) || (key[n]==null))
                    throw new KeyHandlerException("Key material is null.");

                if ((idDetails==null) || (idDetails[0]==null)) // it is ok for non primary keys to have no ID details
                    throw new KeyHandlerException("Primary key has no user ID details!");

                if ((parameters==null) || (parameters[n]==null))
                    throw new KeyHandlerException("Key parameter is null.");
                
                if (!(parameters[n] instanceof OpenPGPAddKeyParameters))
                    throw new KeyHandlerException("Key parameter is the wrong type.");
                
                
                // create key packet
                currentParam = (OpenPGPAddSecretKeyParameters)parameters[n];
                
                if (n == 0) { // this is the primary key
                    
                    if (key[n] instanceof OpenPGPKeyData) { // if this is an OpenPGPKeyData key then try and import the key packet.
                        OpenPGPKeyData tmpKey = (OpenPGPKeyData)key[n];
                        
                        if ((tmpKey.getKeyPacket() instanceof SecretKeyPacket) && (!(tmpKey.getKeyPacket() instanceof SecretSubkeyPacket)))
                            currentKeyPacket = tmpKey.getKeyPacket(); // key[n] contains a SecretKeyPacket
                        else
                            throw new KeyHandlerException("Key "+n+" does not appear to be a Secret Key Packet.");
                        
                    } else {
                        currentKeyPacket = new SecretKeyPacket(currentParam.getCreationDate(), currentParam.getPublicKeyAlgorithm(), currentParam.getSymmetricAlgorithm(), createS2K(currentParam.getHashAlgorithm()), currentParam.getPassPhrase(), key[n].getKey());
                    }
                    primaryKeyPacket = currentKeyPacket;
                    
                } else { // this is a subkey
                    if (key[n] instanceof OpenPGPKeyData) { // if this is an OpenPGPKeyData key then try and import the key packet.
                        OpenPGPKeyData tmpKey = (OpenPGPKeyData)key[n];
                        
                        if (tmpKey.getKeyPacket() instanceof SecretSubkeyPacket) 
                             currentKeyPacket = tmpKey.getKeyPacket(); // key[n] contains a SecretSubkeyPacket
                        else
                            throw new KeyHandlerException("Key "+n+" does not appear to be a Secret Subkey Packet.");
                        
                    } else {
                        currentKeyPacket = new SecretSubkeyPacket(currentParam.getCreationDate(), currentParam.getPublicKeyAlgorithm(), currentParam.getSymmetricAlgorithm(), createS2K(currentParam.getHashAlgorithm()), currentParam.getPassPhrase(), key[n].getKey());
                    }
                }
                
                // write key packet
                out.writePacket(currentKeyPacket);
                
                // if this is a primary key then write user ID
                if ((n == 0) && (idDetails[n]!=null)) {
                    if (!(idDetails[n] instanceof OpenPGPStandardKeyIdentifier))
                        throw new KeyHandlerException("User ID is of the wrong type!");

                    out.writePacket(new UserIDPacket(idDetails[n].getDefaultID()));
                }
                
                // generate and write signature (only if this is a subkey)
                if (n>0) { // sub key (signed with primary key)
                    byte [] tmp = generateSubKeyHashData(primaryKeyPacket.encodePacketBody(), currentKeyPacket.encodePacketBody());
                   
                    out.writePacket(new SignaturePacket(generateSubkeySignature(key[n].getKey().getPrivateKey(), primaryKeyPacket.getKeyID(), currentParam, tmp)));
                }
            }
            
            // close stream
            out.close();
            
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
    }     

    /**
     * <p>Change a key handler setting.</p>
     * <p>This method allows you to change a setting of a key handler object, for example change the passphrase used for unlocking a key.</p>
     * <p>What settings can be changed depend on the type of key handler.</p>
     * @param parameters What to change and the parameters needed.
     * @throws KeyHandlerException if something went wrong.
     */
    public void changeSetting(KeyHandlerParameters parameters) throws KeyHandlerException {
        // TODO : Change passcode setting
    }
    
}
