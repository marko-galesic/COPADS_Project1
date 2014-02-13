//******************************************************************************
//
// File:    PasswordCrack.java
// Package: ---
// Unit:    Class PasswordCrack
//
// Author: Marko Galesic
//******************************************************************************

import java.util.*;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/*
 * Cracks a database filled with usernames and     
 * passwords by using a password dictionary
 * 
 * @author Marko Galesic
 */
public class PasswordCrack
{
	// The character to split database entries on
	private static String DATABASE_ENTRY_SPLIT = "\\s+";
	
	/**
	 * Populates the dictionary with entries from a dictionary file.
	 * Takes as an argument a file object for the dictionary
	 * 
	 * Assumes that dictionary is N lines of alphanumeric characters
	 * @param filePath the file path of the dictionary
	 * @return dictionary of passwords as a HashSet
	 */
	public static HashSet<String> populateDictionary(File dictionaryFile) throws IOException
	{
		HashSet<String> passwordDictionary = new HashSet<String>();
		BufferedReader br = null;

		String line;

		br = new BufferedReader(new FileReader(dictionaryFile));

		// Read lines in file
		while ((line = br.readLine()) != null)
		{
			passwordDictionary.add(line);
		}

		return passwordDictionary;
	}

	/**
	 * Populates the database with entries from a database file.
	 * Takes as an argument a file object for the database
	 * 
	 * Assumes that database is N lines of username password combinations
	 *
	 * @param databaseFile the file path of the database
	 * @return database map
	 */
	public static HashMap<String, String> populateDatabase(File databaseFile) throws IOException, IllegalArgumentException
	{
		HashMap<String, String> database = new HashMap<String, String >();
		BufferedReader br = null;

		String line;

		br = new BufferedReader(new FileReader(databaseFile));

		// Read lines in file
		while ((line = br.readLine()) != null)
		{
			String[] entry = line.split(DATABASE_ENTRY_SPLIT);// Split around whitespace
			
			// First make sure we have a password with the correct format			
			if (entry[1].matches("[0-9a-fA-F]+"))
			{
				database.put(entry[0], entry[1]);
			}
			else
			{
				throw new IllegalArgumentException("Bad password format: " + entry[1]);
			}
		}

		return database;
	}

	/**
	 * Main program where threads to print username password combinations are spawned based on number
	 * of database entries and where threads for calculating hashes based on a dictionary are spawned.
	 *
	 * This piece of code is also responsible for creating the record keeper (a HashMap) of password
	 * hashes to their corresponding plaintext representations
	 */
	public static void main(String[] args) throws IllegalArgumentException
	{
		// Make sure that the user has provided valid number of arguments
		if(args.length != 2)
		{
			System.err.println("Usage: java PasswordCrack <dictionaryFile> <databaseFile>");
			return;
		}
		
		// Create Thread pool
		ExecutorService pool = Executors.newCachedThreadPool();
		
		// Helper objects for the dictionary and the database
		HashSet<String> dictionary; 
		HashMap<String, String> database; 

		// Create a map of hashes to their plaintext counter parts - use this later to communicate between threads
		HashMap<String, SynchronizedPlaintextPassword> passwordPlaintextMap = new HashMap<String, SynchronizedPlaintextPassword>();

		// Some temporary file objects for getting the data
		File dictionaryFile = new File(args[0]);
		File databaseFile = new File(args[1]);

		try
		{
			dictionary = populateDictionary(dictionaryFile);
			database = populateDatabase(databaseFile);
		}		
		catch(IOException e)
		{
			throw new IllegalArgumentException("Bad Input.");
		}
		
		// Go through all usernames in database and generate threads for each user to print
		// username password combination
		for(String username : database.keySet())
		{
			// Temp variable for clarity
			String passwordHash = database.get(username);
			SynchronizedPlaintextPassword synchronizedPlaintextPassword = null;
			
			if (!passwordPlaintextMap.containsKey(passwordHash))
			{
				synchronizedPlaintextPassword = new SynchronizedPlaintextPassword();			
	
				// Create entry for user \ password combo in HashMap
				passwordPlaintextMap.put(passwordHash, synchronizedPlaintextPassword);			
			
				// Spawn UserPasswordMatcher Thread
				pool.execute(new UserPasswordMatcher(username, synchronizedPlaintextPassword)); 
			}
			else
			{
				// Get plaintext password object to send to matcher thread
				synchronizedPlaintextPassword = passwordPlaintextMap.get(passwordHash);
				
				pool.execute(new UserPasswordMatcher(username, synchronizedPlaintextPassword)); 
			}		
		}

		pool.shutdown(); // Don't accept any more threads
			
		for(String plaintTextPassword : dictionary)
		{
			// Spawn PasswordHashGenerator
			Thread phgThread = new Thread(new PasswordHashGenerator(plaintTextPassword, passwordPlaintextMap));
			phgThread.start();
		}
	
		// Total wait time of 0.2 seconds per password until we terminate all UserPasswordMatcher threads
      		try
		{
			pool.awaitTermination ((long)(dictionary.size() * 0.2), TimeUnit.SECONDS);
		}
		catch(InterruptedException e)
		{
			System.err.println("Error while waiting for thread pool termination.");
		}
	}
}
