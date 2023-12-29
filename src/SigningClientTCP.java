//Aditi Gupta - argupta - Project2Task5
//Took help from EchoClientTCP.java from Coulouris textbook to make the changes
// Took help from https://www.geeksforgeeks.org/rsa-algorithm-cryptography/ to understand RSA algorithm
//Used code from Lab 5 for separation of concerns

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Random;

public class SigningClientTCP {
    private static int serverPort;
    // Each public and private key consists of an exponent and a modulus
    private static BigInteger n; // n is the modulus for both the private and public keys
    private static BigInteger e; // e is the exponent of the public key
    private static BigInteger d; // d is the exponent of the private key
    public static void main(String[] args) {
        try {
            // Announce that the client is running
            System.out.println("The client is running.");
            generateKeys();

            // Create a BufferedReader to read input from the user
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            // Prompt the user for the server side port number
            System.out.print("Enter the server side port number (e.g., 6789): ");
            serverPort = Integer.parseInt(reader.readLine());
            String total = " ";
            while (true) {
                // Create a socket and connect to the server
                try {
                    // Display the menu and get user input
                    String nextLine = menu(reader);

                    // https://gist.github.com/chatton/8955d2f96f58f6082bde14e7c33f69a6
                    if (nextLine.trim().equalsIgnoreCase("1")) {
                        // Option 1: Add a value to the sum
                        System.out.println("Enter a value to add to your sum:");
                        String value = reader.readLine();
                        String add = "add";
                        total = hashId() + "," + e+"," +n+"," +value + "," + add;
                        String signedMessage = sign(total);
                        total = total + "," + signedMessage;
                    } else if (nextLine.trim().equalsIgnoreCase("2")) {
                        // Option 2: Subtract a value from the sum
                        System.out.println("Enter a value to subtract from your sum:");
                        String value = reader.readLine();
                        String diff = "diff";
                        total = hashId() + "," + e+"," +n+"," + value + "," + diff;
                        String signedMessage = sign(total);
                        total = total + "," + signedMessage;
                    } else if (nextLine.trim().equalsIgnoreCase("3")) {
                        // Option 3: Get the current sum
                        int num = 0;
                        String get = "get";
                        total = hashId() + "," + e +","+ n +","+ num + "," + get;
                        String signedMessage = sign(total);
                        total = total + "," + signedMessage;
                    } else if (nextLine.trim().equalsIgnoreCase("4")) {
                        // Option 4: Exit the client
                        System.out.println("Client side quitting. The remote variable server is still running.");
                        break;
                    } else {
                        System.out.println("Invalid option. Please choose a valid option (1-4).");
                    }

                    // Read and display the server's reply
                    //https://gist.github.com/chatton/8955d2f96f58f6082bde14e7c33f69a6
                    String reply = communicateWithServer(total);
                    System.out.println("Reply from server: " + reply);
                } catch (IOException e) {
                    System.out.println("Error in client socket: " + e.getMessage());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        } catch (IOException e) {
            System.out.println("IO Exception: " + e.getMessage());
        }
    }

    // Method to encapsulate communication with the server
    //Taken from EchoClientTCP.java from Coulouris textbook
    private static String communicateWithServer(String request) {
        try (Socket socket = new Socket("localhost", serverPort);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            out.println(request); // Send the request to the server
            return in.readLine(); // Read and return the server's reply
        } catch (IOException e) {
            return "Error in client socket: " + e.getMessage();
        }
    }
    // Used code from ShortMessageSign.java for this function
    public static String sign(String message) throws Exception {

        // compute the digest with SHA-256
        byte[] bytesOfMessage = message.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md.digest(bytesOfMessage);

        // we add a 0 byte as the most significant byte to keep
        // the value to be signed non-negative.
        byte[] messageDigest = new byte[bigDigest.length+1];

        //code taken from ShortMessageSign.java - Signing a short message
        //https://stackoverflow.com/questions/6780395/how-can-i-convert-a-byte-to-a-positive-biginteger-in-java
        System.arraycopy(bigDigest, 0, messageDigest, 1, bigDigest.length);

        // From the digest, create a BigInteger
        BigInteger m = new BigInteger(messageDigest);

        // encrypt the digest with the private key
        BigInteger c = m.modPow(d, n);

        // return this as a big integer string
        return c.toString();
    }

    // Method to display the client menu and get user input
    public static String menu(BufferedReader reader) throws IOException {
        System.out.println("1. Add a value to your sum.");
        System.out.println("2. Subtract a value from your sum.");
        System.out.println("3. Get your sum.");
        System.out.println("4. Exit client.");
        String nextLine = reader.readLine();
        return nextLine;
    }

    //generate private and public keys  and display this to user
    // Took code for generating public and private keys from RSAExample.java
    public static void generateKeys() {

        Random rnd = new Random();

        // Step 1: Generate two large random primes.
        // We use 400 bits here, but best practice for security is 2048 bits.
        // Change 400 to 2048, recompile, and run the program again and you will
        // notice it takes much longer to do the math with that many bits.
        BigInteger p = new BigInteger(400, 100, rnd);
        BigInteger q = new BigInteger(400, 100, rnd);

        // Step 2: Compute n by the equation n = p * q.
        n = p.multiply(q);

        // Step 3: Compute phi(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Step 4: Select a small odd integer e that is relatively prime to phi(n).
        // By convention the prime 65537 is used as the public exponent.
        e = new BigInteger("65537");

        // Step 5: Compute d as the multiplicative inverse of e modulo phi(n).
        d = e.modInverse(phi);

        System.out.println(" e = " + e);  // Step 6: (e,n) is the RSA public key
        System.out.println(" d = " + d);  // Step 7: (d,n) is the RSA private key
        System.out.println(" n = " + n);  // Modulus for both keys
        System.out.println("Public key is (e,n): (" + e + "," + n + ")");
        System.out.println("Private key is (d,n): (" + d + "," + n + ")");
    }
    public static String hashId() throws Exception {
    String s= e.toString()+n.toString();
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
}
