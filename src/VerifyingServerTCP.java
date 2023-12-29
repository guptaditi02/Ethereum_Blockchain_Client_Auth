//Aditi Gupta - argupta - Project2Task5
//Took code from EchoServerTCP.java from Coulouris textbook to make the changes
// Took help from https://www.geeksforgeeks.org/rsa-algorithm-cryptography/ to understand RSA algorithm
// Used ShortMessageSign.java and ShortMessageVerify.java to sign and check the signature on very small messages.
//Used code from Lab 5 for separation of concerns

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLOutput;
import java.util.HashMap;
import java.security.MessageDigest;
import java.util.TreeMap;

public class VerifyingServerTCP {
    private static int sum = 0, diff=0; // Variable to store the sum/difference of values
private static String id, e, n,operation, sign, operand;
private static int value;
    public static void main(String[] args) {
        // Create a ServerSocket for accepting incoming client connections
        ServerSocket serverSocket = null;

        // A hashmap to store and retrieve values associated with client IDs
        TreeMap<String, Integer> map = new TreeMap<>();

        try {
            // Announce that the server is running
            System.out.println("Server started");

            // Create a BufferedReader to read input from the user
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            // Prompt the user for the port number to listen on
            System.out.print("Enter the port number for the server to listen on (e.g., 6789): ");
            int serverPort = Integer.parseInt(reader.readLine());

            // Create a ServerSocket to listen for incoming TCP connections
            serverSocket = new ServerSocket(serverPort);

            while (true) {
                // Wait for a client to connect
                Socket clientSocket = serverSocket.accept();

                // Read and process client request
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                String request = in.readLine();

                if (request == null) {
                    continue;
                }

                // Split the client request to extract details
                String[] elements = request.split(",");
                 id = elements[0];
                e= elements[1];
                n= elements[2];
                System.out.println("Visitor's public key: " + e + " " + n);

                // Compute and verify the client ID
                String computedID = hashId();
                if (!computedID.equals(id)) {
                    out.println("Error in verifying ID");
                    clientSocket.close();
                    continue;
                }

                // Check if this ID has a previous value, otherwise initialize with zero
                if (!map.containsKey(id)) {
                    map.put(id, 0);
                }

                // Extract other elements from the client request
                operand = elements[3];
                 operation = elements[4];
                 sign=elements[5];
                System.out.println("Signature verified: " + verify((id+ ","+e+ ","+n+ ","+operand+ ","+operation), sign));
                System.out.println("Operation requested: " + operation);
                // Verify the client's signature
                if (!verify((id+ ","+e+ ","+n+ ","+operand+ ","+operation), sign)) {
                    out.println("Error in verifying signature");
                    clientSocket.close();
                    continue;
                }

                // Perform the requested operation (addition or subtraction or get)
                value=Integer.parseInt(operand);
                if (operation.equalsIgnoreCase("add")|| operation.equalsIgnoreCase("get")) {
                    sum = add(map.get(id), value);
                } else {
                    sum = diff(map.get(id), value);
                }

                // Update the value associated with the client ID in the map
                map.put(id, sum);

                // Print the updated value associated with the client ID
                System.out.println("Value associated with ID " + id + ": " + map.get(id));

                // Send the result back to the client
                out.println(sum);

                // Close the client socket when done
                clientSocket.close();
            }
        } catch (IOException e) {
            System.out.println("IO Exception: " + e.getMessage());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        } finally {
            try {
                if (serverSocket != null)
                    serverSocket.close();
            } catch (IOException e) {
                System.out.println("Error closing server socket: " + e.getMessage());
            }
        }
    }

    // Method to add two numbers
    public static int add(int i, int value) {
        sum = i+value;
        return sum;
    }

    // Method to subtract two numbers
    public static int diff(int i, int value) {
        diff = i-value;
        return diff;
    }

    // Method to compute a hash of the client's public key details
    // code taken from ShortMessageSign.java - Signing a short message
    public static String hashId() throws Exception {
        String s= e+n;
        // compute the digest with SHA-256
        // code taken from ShortMessageSign.java - Signing a short message
        byte[] bytesOfMessage = s.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md.digest(bytesOfMessage);

        //code taken from ShortMessageSign.java - Signing a short message
        //https://stackoverflow.com/questions/6780395/how-can-i-convert-a-byte-to-a-positive-biginteger-in-java
        BigInteger bigInteger = new BigInteger(1, bigDigest);

        //Converting big integer to string
        String hashValue = bigInteger.toString();

        //printing the last 20 characters of the hash value
        String id = hashValue.substring(hashValue.length() - 20);
        return id;
    }


    // Took code from ShortMessageVerify.java to check the signature on very small messages.
    // Method to verify the client's signed message using RSA
    public static boolean verify(String messageToCheck, String encryptedHashStr)throws Exception  {

        // Take the encrypted string and make it a big integer
        BigInteger encryptedHash = new BigInteger(encryptedHashStr);
        // Decrypt it
        BigInteger E=new BigInteger(e);
        BigInteger N=new BigInteger(n);
        BigInteger decryptedHash = encryptedHash.modPow(E,N);

        // Get the bytes from messageToCheck
        byte[] bytesOfMessageToCheck = messageToCheck.getBytes("UTF-8");

        // compute the digest of the message with SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] messageToCheckDigest = md.digest(bytesOfMessageToCheck);

        // we add a 0 byte as the most significant byte to keep
        // the value to be signed non-negative.
        byte[] messageDigest = new byte[messageToCheckDigest.length+1];

        //Took this line from https://stackoverflow.com/questions/6780395/how-can-i-convert-a-byte-to-a-positive-biginteger-in-java
        System.arraycopy(messageToCheckDigest, 0, messageDigest, 1, messageToCheckDigest.length);

        // Make it a big int
        BigInteger bigIntegerToCheck = new BigInteger(messageDigest);

        // inform the client on how the two compare
        if(bigIntegerToCheck.compareTo(decryptedHash) == 0) {

            return true;
        }
        else {
            return false;
        }
    }

}
