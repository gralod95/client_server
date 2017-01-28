package laix.client_server;


import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

public class Client {
    private static String hostIp = "127.0.0.1";
    private static int port = 9898;
    private static String clientName;
    private static ObjectInputStream inputStream;
    private static ObjectOutputStream outputStream;

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        Socket clientSock = new Socket(hostIp, port);
        System.out.println("Client started with socket " + hostIp + ":" + port + " at " + java.util.Calendar.getInstance().getTime().toString());

        clientName = "temp_client_" + java.util.Calendar.getInstance().getTime().getMinutes();
        System.out.println("Client name: " + clientName);

        inputStream = new ObjectInputStream(clientSock.getInputStream());
        outputStream = new ObjectOutputStream((clientSock.getOutputStream()));
        System.out.println("Streams created.");

        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        String line = null;
        System.out.println("Type in message and press enter.");
        System.out.println();

        while(true) {
            //System.out.println("Waiting for answer...");
            Message answer = (Message) inputStream.readObject();
            answer.print();
            
            if(answer.isRequestAnswer()) {
                System.out.print("["+ clientName + "]: ");
                line = userInput.readLine();

                if(line.equals("/reg")){
                    registration();
                }
                if(line.equals("/enter")){
                    authentication();
                }

                line = AuthenticationUtil.encryptText(line, 3);
                Message message = new Message(clientName, line);
                outputStream.writeObject(message);
            }
        }
    }

    private static void registration() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        Message outMsg, inMsg;
        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        String line = null;
        System.out.print("<Registration>: enter login:\n<Registration>: ");
        String login = userInput.readLine();
        System.out.print("<Registration>: enter password:\n<Registration>: ");
        String password = userInput.readLine();

        //salt
        String salt = AuthenticationUtil.getRandomSalt();
        //x
        BigInteger x = AuthenticationUtil.sha256(salt + password);
        //v
        BigInteger v = AuthenticationUtil.get_v(x);

        //start registration on server with empty message and TAG_REG
        outMsg = new Message(login, "");
        outMsg.setTag(Message.TAG_REG);
        outputStream.writeObject(outMsg);

        //send login, salt and v
        outMsg = new Message(login, salt);
        outMsg.setTag(Message.TAG_REG);
        outputStream.writeObject(outMsg);

        outMsg = new Message(login, v.toString(16));
        outMsg.setTag(Message.TAG_REG);
        outputStream.writeObject(outMsg);

        inMsg = (Message) inputStream.readObject();
        if (inMsg.getText().equals("REG_OK"))
            System.out.println("<Registration>: success.");
        if (inMsg.getText().equals("REG_ERR"))
            System.out.println("<Registration>: error. try another login.");
    }

    private static void authentication() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        Message outMsg, inMsg;
        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));

        System.out.print("<Authentication>: enter login:\n<Authentication>: ");
        String login = userInput.readLine();
        System.out.print("<Authentication>: enter password:\n<Authentication>: ");
        String password = userInput.readLine();

        //a
        BigInteger a = AuthenticationUtil.get_a();
        //A
        BigInteger A = AuthenticationUtil.get_A(a);

        //start authentication on server with empty message and TAG_AUTH
        outMsg = new Message(login, "");
        outMsg.setTag(Message.TAG_AUTH);
        outputStream.writeObject(outMsg);

        //send login and A
        outMsg = new Message(login, A.toString(16));
        outMsg.setTag(Message.TAG_AUTH);
        outputStream.writeObject(outMsg);

        //get salt and B
        inMsg = (Message) inputStream.readObject();
        //login not found
        if (inMsg.getTag() == Message.TAG_STOP){
            System.out.println("Error." + inMsg.getText());
            return;
        }
        String salt = inMsg.getText();
        inMsg = (Message) inputStream.readObject();
        BigInteger B = new BigInteger(inMsg.getText(), 16);

        //u
        BigInteger u = AuthenticationUtil.sha256(A.toString(16) + B.toString(16));

        //x
        BigInteger x = AuthenticationUtil.sha256(salt + password);
        //S
        BigInteger S = AuthenticationUtil.get_clientS(B, x, a, u);
        //K - session key
        BigInteger K = AuthenticationUtil.sha256(S.toString(16));
        //M
        BigInteger M1 = AuthenticationUtil.get_M(login, salt, A, B, K);
        //R
        BigInteger R = AuthenticationUtil.get_R(A, M1, K);

        //send M to server
        outMsg = new Message(login, M1.toString(16));
        outMsg.setTag(Message.TAG_AUTH);
        outputStream.writeObject(outMsg);

        //get R from server
        inMsg = (Message) inputStream.readObject();
        BigInteger serverR = new BigInteger(inMsg.getText(), 16);

        if(R.compareTo(serverR) == 0) {
            System.out.println("<Authentication>: Success.");
        } else {
            System.out.println("<Authentication>: Failure. Wrong log:pass.");
        }
    }
}
