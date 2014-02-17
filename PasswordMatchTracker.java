//******************************************************************************
//
// File:    PasswordMatchTracker.java
// Package: ---
// Unit:    Class PasswordMatchTracker
// 
// A class the manages the communications between the PasswordHashGenerator class
// and UserPasswordMatcher class
// 
// Author: Marko Galesic
//******************************************************************************


import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.*;
public class PasswordMatchTracker
{
	
	/**
	 * A private class for create password hash \ password pairs
	 */
	private class HashPasswordCombo
	{
		public byte[] hashedPassword;	
		public String plaintextPassword;

		/**
		 * Constructor for HashPasswordCombo
		 *
		 * @param hashedPassword byte array containing the hash of a password
		 * @param database   the password the hashedPassword represents
		 */
		public HashPasswordCombo(byte[] hashedPassword, String plaintextPassword)
		{
			this.hashedPassword = hashedPassword;
			this.plaintextPassword = plaintextPassword;
		}
	}
	
	// Hidden members

	// List for storing password hash \ password pair objects
	private ArrayList<HashPasswordCombo> crackedPasswords = new ArrayList<HashPasswordCombo>();		
		
	// A lock to control access priviledge for the password list 
	private Lock passpwordPairListReady = new ReentrantLock();

	// A way to persistently signal list is populated
	private Semaphore passwordPairListSemaphore = new Semaphore(1);
		
	// Integer to keep track of the amount of hashers still running
	private int numberOfPasswordHashers;

	/**
	 * Constructor for PasswordMatchTracker - creates the object which will keep track of all
	 * password hash \ plaintext pairs and number of hashers running
	 *
	 * @param numberOfPasswordHashers total number of hashers
	 */
	public PasswordMatchTracker(int numberOfPasswordHashers)
	{
		this.numberOfPasswordHashers = numberOfPasswordHashers;
	}

	/**
	 * A method for getting the plaintext representation of a hashed password
	 * 
	 * @param hashedPassword the hash we want to get the equivalent plaintext password for
	 */
	public synchronized String get(byte[] hashedPassword)
	{
		// Keep trying to get the password until all hashers are done
		while (numberOfPasswordHashers > 0)
		{
			try{wait();}
			catch(InterruptedException e)
			{
				System.err.println("Interrupted while waiting:\n" + e.getMessage());
			}
			
			// Get access priviledge
			//  passpwordPairListReady.lock();	

			String plaintextPassword = null;
			// Find password if there is one
			for(HashPasswordCombo hashPasswordCombo : crackedPasswords)
			{
				if (Arrays.equals(hashPasswordCombo.hashedPassword,hashedPassword))
				{
					// Read the password
					plaintextPassword = hashPasswordCombo.plaintextPassword;
					
					// Release access priviledge
					//passpwordPairListReady.unlock();

					return plaintextPassword;
				}
			}
			// Release access priviledge
			//passpwordPairListReady.unlock();
			
		}
		// Return null if there was no match found
		return null;
	}
	

	/**
	 * A method for putting the plaintext representation of a hashed password into the 
	 * password pair lists
	 * 
	 * @param password the plaintext representation of a password
	 * @param hashedPassword the hashed representation of a password
	 */ 	
	public synchronized void put(String password, byte[] hashedPassword)
	{
		// Aqcuire access priviledge
		//passpwordPairListReady.lock();

		// Create element to put into list
		HashPasswordCombo combo = new HashPasswordCombo(hashedPassword, password);

		// Add pair to the list
		crackedPasswords.add(combo);

		// Release access priviledge
		//passpwordPairListReady.unlock();
		
		// One hasher is done - decrement thread counter
		numberOfPasswordHashers--;

		notifyAll();
	}
}
