//******************************************************************************
//
// File:    UserPasswordMatcher.java
// Package: ---
// Unit:    Class UserPasswordMatcher
// 
// The snippet of code for hashing the password was taken from the example snippets on the course website
// 
// Author: Marko Galesic
//******************************************************************************

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Objects of this class match one user from a password
 * hash database against all the password hashes in a 
 * dictionary
 * 
 * @author Marko Galesic
 */
public class UserPasswordMatcher extends Thread
{
	// Hidden data members
	private SynchronizedPlaintextPassword plaintextPassword;
	private String username;
	/**
	 * Constructor for UserFromPasswordHash class takes a dictionary and a database for lookup
	 *
	 * @param dictionary the dictionary of passwords
	 * @param database   the database of password, username pairs
	 */
	public UserPasswordMatcher(String username, SynchronizedPlaintextPassword plaintextPassword)
	{
		this.plaintextPassword = plaintextPassword;
		this.username = username;
	}
	
	/**
	 * Block until plaintext pasword is available - then print it out with a username
	 */
	@Override
	public void run()
	{
		// Wait for plaintext password
		try
		{
			plaintextPassword.latch.await((long)10.0, TimeUnit.SECONDS);
		}
		catch(InterruptedException e)
		{
			System.err.println("Error while waiting for plaintext password.");
		}

		// Get plaintext password
		String password = plaintextPassword.getPlaintextPassword(username);

		// Print out username password combination
		synchronized(System.out)
		{
			if (password != "" ) System.out.println(username + " " + password); // Printout the user \ password combo
		}
	}
}
