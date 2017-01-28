package laix.client_server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Created by La1x on 14.09.2016.
 */
public class AuthenticationUtil {
    //hashmap of data base
    private static Map<String, UserData> Database;
    private static final String DB_FILENAME = "authDB.txt";

    private static final BigInteger N = new BigInteger("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0BEA2314C" +
            "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
            "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
            "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
            "FD5138FE8376435B9FC61D2FC0EB06E3", 16);
    //private static final BigInteger N = new BigInteger("524BAF", 16); //5393327
    private static final BigInteger g = BigInteger.valueOf(2);
    private static final BigInteger k = BigInteger.valueOf(3);

    public static final int bit_length = 1024;

    public static void loadDataBase() throws IOException {
        if(Files.notExists(Paths.get(DB_FILENAME))) {
            Files.createFile(Paths.get(DB_FILENAME));
            Database = new HashMap<String, UserData>();
        } else {
            List<String> content = Files.readAllLines(Paths.get(DB_FILENAME));
            Database = new HashMap<String, UserData>();
            for (String line : content) {
                String[] s = line.split(",");
                Database.put(s[0], new UserData(s[1], s[2]));
            }
        }
    }

    public static boolean addNewUser(String login, String salt, String v) throws NoSuchAlgorithmException {
        if (Database.containsKey(login) == true) {
            return false;
        } else {
            //String salt = getRandomSalt();
            Database.put(login, new UserData(salt, v));
            String newUser = login + "," + salt + "," + v + "\n";
            try {
                Files.write(Paths.get(DB_FILENAME), newUser.getBytes(), StandardOpenOption.APPEND);
            } catch (IOException e) {
                e.printStackTrace();
            }
            return true;
        }
    }

    public void setUserStatus() {

    }

    public static boolean checkLogin(String login) {
        if (Database.get(login) == null || Database.isEmpty()) {
            return false;
        } else {
            return true;
        }

    }

    public static UserData getUserData(String login) {
        if (Database.get(login) == null || Database.isEmpty())
            return null;
        else
            return new UserData(Database.get(login).getSalt(), Database.get(login).getV());
    }

    public static BigInteger sha256(String input) throws NoSuchAlgorithmException {

        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            try {
                md.update(input.getBytes("UTF-8")); // Change this to "UTF-16" if needed
            } catch (UnsupportedEncodingException uee) {
                uee.printStackTrace();
            }
            byte[] digest = md.digest();

            String result = String.format("%064x", new java.math.BigInteger(1, digest));
            return new BigInteger(result, 16);

        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        }
        return null;
    }

    public static String getRandomSalt() {
        final Random r = new SecureRandom();
        byte[] salt = new byte[32];
        r.nextBytes(salt);
        return String.format("%064x", new java.math.BigInteger(1, salt));
    }

    public static BigInteger get_v(BigInteger x) {
        BigInteger v = g.modPow(x, N);
        return v;
    }

    public static BigInteger get_a() {
        BigInteger a = (new BigInteger(bit_length, new Random())).mod(N);
        return a;
    }

    public static BigInteger get_A(BigInteger a) {
        return g.modPow(a, N);
    }

    public static BigInteger get_b() {
        BigInteger b = (new BigInteger(bit_length, new Random())).mod(N);
        return b;
    }

    public static BigInteger get_B(BigInteger b, BigInteger v) {
        BigInteger kv = k.multiply(v).mod(N);
        return g.modPow(b, N).add(kv).mod(N);
    }

    public static BigInteger get_serverS(BigInteger A, BigInteger b, BigInteger v, BigInteger u) {
        return v.modPow(u, N).multiply(A).mod(N).modPow(b, N);
    }

    public static BigInteger get_clientS(BigInteger B, BigInteger x, BigInteger a, BigInteger u) {
        BigInteger t1 = u.multiply(x).mod(N).add(a).mod(N);
        BigInteger t2 = g.modPow(x, N).multiply(k).mod(N);
        BigInteger t3 = B.subtract(t2).mod(N);
        return t3.modPow(t1, N);
    }

    
    public static BigInteger get_M(String login, String salt, BigInteger A, BigInteger B, BigInteger K) throws NoSuchAlgorithmException {

        String t1 = (sha256(N.toString(16)).xor(sha256(g.toString(16)))).toString(16);
        return sha256(t1 +
                sha256(login).toString(16) +
                salt +
                A.toString(16) +
                B.toString(16) +
                K.toString(16));
    }

    public static BigInteger get_M2(BigInteger A, BigInteger M1, BigInteger K) throws NoSuchAlgorithmException {
        return sha256(A.toString(16) +
                M1.toString(16) +
                K.toString(16));
    }

    public static String encryptText(String srcTxt, int shift) {
        String outString = "";
        char c;
        int srcTxtLenght = srcTxt.length();
        for (int i = 0; i < srcTxtLenght; i++)
        {
            c = srcTxt.charAt((i));
            if (Character.toString(c).matches("[ё]"))
            {
                c = 'е';
            } else if (Character.toString(c).matches("[Ё]"))
            {
                c = 'Е';
            }
            if (Character.toString(c).matches("[A-Z]"))
            {
                if (shift > 0)
                    outString += (char)((int)'A' + (( ((int)c + shift % 26) - (int)'A') % 26));
                else
                    outString += (char)((int)'Z' - (( (int)'Z' - ((int)c + shift % 26)) % 26));
            } else if (Character.toString(c).matches("[a-z]"))
            {
                if (shift > 0)
                    outString += (char)((int)'a' + (( ((int)c + shift % 26) - (int)'a') % 26));
                else
                    outString += (char)((int)'z' - (( (int)'z' - ((int)c + shift % 26)) % 26));
            } else if (Character.toString(c).matches("[А-Я]"))
            {
                if (shift > 0)
                    outString += (char)((int)'А' + (( ((int)c + shift % 32) - (int)'А') % 32));
                else
                    outString += (char)((int)'Я' - (( (int)'Я' - ((int)c + shift % 32)) % 32));
            }  else if (Character.toString(c).matches("[а-я]"))
            {
                if (shift > 0)
                    outString += (char)((int)'а' + (( ((int)c + shift % 32) - (int)'а') % 32));
                else
                    outString += (char)((int)'я' - (( (int)'я' - ((int)c + shift % 32)) % 32));
            } else if (Character.toString(c).matches("[0-9]"))
            {
                if (shift > 0)
                    outString += (char)((int)'0' + (( ((int)c + shift % 10) - (int)'0') % 10));
                else
                    outString += (char)((int)'9' - (( (int)'9' - ((int)c + shift % 10)) % 10));
            } else
            {
                outString += c;
            }
        }
        return outString;
    }

    public static String decryptText(String srcTxt, int shift) {
        return encryptText(srcTxt, -shift);
    }
}
