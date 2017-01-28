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

    private static final BigInteger N = new BigInteger("524BAF", 16); //5393327
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

    public static BigInteger get_R(BigInteger A, BigInteger M1, BigInteger K) throws NoSuchAlgorithmException {
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
    
    public String analyse(String input) {
        Map<Character, Integer> freqMap = new HashMap<Character, Integer>;
        String alphabet = "абвгдежзийклмнопрстуфцхчшщъыьэюя";
        for( char s : alphabet.toCharArray() ) {
            freqMap.put(new Character(s), new Integer(0));
        }
        
        for( char s : input.toCharArray() ) {
            Integer frequency = freqMap.get(s);
            freqMap.put(s, frequency++);
        }
        Map<Character, Integer> constFreq = new HashMap<Character, Integer>();
        constFreq.put('а', 45172*10000/538566);
        constFreq.put('б', 9302*10000/538566);
        constFreq.put('в', 24790*10000/538566);
        constFreq.put('г', 11168*10000/538566);
        constFreq.put('д', 16380*10000/538566);
        constFreq.put('е', 42469*10000/538566);
        constFreq.put('ё', 431*10000/538566);
        constFreq.put('ж', 5456*10000/538566);
        constFreq.put('з', 9592*10000/538566);
        constFreq.put('и', 35785*10000/538566);
        constFreq.put('к', 19314*10000/538566);
        constFreq.put('л', 27258*10000/538566);
        constFreq.put('м', 15918*10000/538566);
        constFreq.put('н', 35095*10000/538566);
        constFreq.put('о', 61225*10000/538566);
        constFreq.put('п', 13837*10000/538566);
        constFreq.put('р', 24543*10000/538566);
        constFreq.put('с', 28100*10000/538566);
        constFreq.put('т', 30585*10000/538566);
        constFreq.put('у', 15443*10000/538566);
        constFreq.put('ф', 1206*10000/538566);
        constFreq.put('х', 4595*10000/538566);
        constFreq.put('ч', 7338*10000/538566);
        constFreq.put('ш', 5087*10000/538566);
        constFreq.put('щ', 1511*10000/538566);
        constFreq.put('ц', 2179*10000/538566);
        constFreq.put('э', 1628*10000/538566);
        constFreq.put('ъ', 283*10000/538566);
        constFreq.put('ь', 10490*10000/538566);
        constFreq.put('ы', 10223*10000/538566);
        constFreq.put('ю', 3494*10000/538566);
        constFreq.put('я', 12468*10000/538566);
        constFreq.put('й', 6201*10000/538566);
        
        
        Map<Character, Character> resMap = new HashMap<Character,Character>();
        for(Map.Entry<Character, Integer> curFreq : freqMap.entrySet()) {
            for(Map.Entry<Character, Integer> curConstFreq : constFreq.entrySet()) {
                t = curFreq.getValue();
                if(t - 0.14 < curFreq.getValue() && curFreq.getValue() < t + 0.14)
                    resMap.put(curFreq.getKey(), curConstFreq.getKey());
            }
        }
        
        String result = "";
        for(char s : input.toCharArray()) {
            b = resMap.get(s);
            result = result + b;
        }
        return result;
    }
}
