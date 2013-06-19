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

package extras.websitemailer;
import core.interfaces.*;
import core.iptp.*;
import core.exceptions.*;
import core.email.*;

/**
 * <p>A dummy email handler class.</p>
 * <p>This class is sent an Email object and "fakes" the existance of a smtp mail server session, 
 * so that the applet can use a email pipe interface without too much modification.</p>
 */
public class DummyHandler implements SendPipeServerInterface {
    
    public static final int IDLE = 0;
    public static final int HELO = 1;
    public static final int MAIL = 2;
    public static final int RCPT = 3;
    public static final int DATA = 4;
    public static final int SENDDATA = 5;
    public static final int QUIT = 6;
    
    /** The email to work on. */
    private Email email;
    
    /** Current position in fake mail transfer */
    private int status;
    
    /** Creates a new instance of DummyHandler */
    public DummyHandler(Email email) {
        status = IDLE;
        this.email = email;
    }
    
    /**
     * <p>Awaits a command from the client.</p>
     * <p>The implementor of this method must take the internet protocol command and parameters and map it
     * into the appropriate proxy protocol command.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>If you are implementing version 2 or higher of the internal proxy protocol (at time of writing this hasn't been written) you MUST throw a NoMappingPossibleException if no mapping is possible.</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     *
     */
    public IPTPCommand awaitCommand() throws NoMappingPossibleException, PipeCommunicationException {
        
        // send bogus commands and change modes
        if (status==IDLE)
            status = HELO;
        
        switch (status) {
            case HELO : 
                status++;
                return new IPTPRelay("HELO localhost\r\n");
                
            case MAIL : 
                status++; 
                EmailHeader [] head = email.getHeader("To");
                return new IPTPMail(head[0].getTagValue()); 
                
            case RCPT : 
                status++;
                String [] rcpts = email.getRecipients();
                return new IPTPRcpt(rcpts[0]);
                
            case DATA : 
                status++;
                return new IPTPData();
                
            case SENDDATA : 
                status++;
                return new IPTPSendData(new String(email.getBytes()));
                
            default : 
                status = IDLE;
                disconnectFromClient(); 
                return new IPTPQuit();
        }   
        
    }
    
        
    /** <p>Send a command response back to the client.</p>
     * <p>Does nothing.</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public void sendCommandResponse(IPTPCommandResponse commandResponse) throws NoMappingPossibleException, PipeCommunicationException {
        if (!commandResponse.isOk()) status --;
    }
    
    /** <p>Await a client connection on a specified port.</p>
     * <p>Does nothing.</p>
     */
    public void awaitConnection() throws PipeCommunicationException {
    }
    
    /** <p>Disconnect socket and drop any connection.</p>
     * <p>Any socket exceptions caused by closing a socket in accept state are handled internally.</p>
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public void disconnectFromClient() throws PipeCommunicationException {
        status = IDLE;
    }
    
    /** <p>Configure what port the server will wait on when awaitConnection is called.</p>
     * <p>Does nothing.</p>
     */
    public void initServerConnection(int port) {
    }
    
    /** <p> Returns true if the socket is connected to the email client.</p>
     */
    public boolean isConnectedToClient() {
        if (status!= IDLE)
            return true;
        
        return false;
    }

    
}
