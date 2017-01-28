package laix.client_server;

import javax.swing.undo.AbstractUndoableEdit;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;


public class ServerThread extends Thread {
    private String serverName = "serverOnPC";
    private Socket clientSock;
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;

    public ServerThread(Socket clientSock) {
        this.clientSock = clientSock;
        this.start();
    }

    public void run() {
        System.out.println("<New connection>: " +
                            clientSock.getInetAddress().toString() +
                            ":" +
                            clientSock.getPort());
        try {
            outputStream = new ObjectOutputStream(clientSock.getOutputStream());
            inputStream = new ObjectInputStream(clientSock.getInputStream());
            System.out.println("<Streams created>");

            boolean clientStatus = false;
            while(!clientStatus) {
                clientStatus = this.processClient();
            }

            Message helloMsg = new Message(serverName, "Access granted. Hello.");
            helloMsg.setRequestAnswer(true);
            outputStream.writeObject(helloMsg);

            while(true) {
                Message inMsg = (Message) inputStream.readObject();
                System.out.println(AuthenticationUtil.decryptText(inMsg.getText(), 3));
                //inMsg.print();

                Message outMsg = new Message(serverName, "<received>");
                outMsg.setRequestAnswer(true);
                outputStream.writeObject(outMsg);
            }
        } catch (IOException e) {
            if(e.getMessage().equals("Connection reset")) {
                try {
                    clientSock.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
                System.out.println("<Client disconnected>: " +
                        clientSock.getInetAddress().toString() +
                        ":" +
                        clientSock.getPort());
            } else {
                e.printStackTrace();
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private boolean processClient() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        Message message = new Message(serverName,
                "send /reg for registration or /enter for enter login and password.");
        message.setRequestAnswer(true);
        outputStream.writeObject(message);//

        Message answerMessage = (Message) inputStream.readObject();
        switch (answerMessage.getTag()) {
            case Message.TAG_REG:
                registration();
                return false; //user not authenticate yet
            case Message.TAG_AUTH:
                return authentication();
            default:
                return false;
        }
    }

    private boolean registration() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        Message inMsg, outMsg;
        System.out.println("<User registration>");

        inMsg = (Message) inputStream.readObject();
        String salt = inMsg.getText();

        inMsg = (Message) inputStream.readObject();
        String v = inMsg.getText();

        if(AuthenticationUtil.addNewUser(inMsg.getName(), salt, v)) {
            outMsg = new Message(serverName,"REG_OK");
            outMsg.setTag(Message.TAG_REG);
            outputStream.writeObject(outMsg);
            System.out.println("<User registration success>");
            return true;
        } else {
            outMsg = new Message(serverName,"REG_ERR");
            outMsg.setTag(Message.TAG_REG);
            outputStream.writeObject(outMsg);
            System.out.println("<User registration error>");
            return false;
        }
    }


    private boolean authentication() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        Message inMsg, outMsg;
        System.out.println("<User authentication>");

        //get login and A
        inMsg = (Message) inputStream.readObject();
        String login = inMsg.getName();
        BigInteger A = new BigInteger(inMsg.getText(), 16);

        if (!AuthenticationUtil.checkLogin(login)) {
            System.out.println("Error. Login not found in DB.");
            outMsg = new Message(serverName, "User not found.");
            outMsg.setTag(Message.TAG_STOP);
            outputStream.writeObject(outMsg);
            return false;
        }

        //v
        BigInteger v = new BigInteger( AuthenticationUtil.getUserData(login).getV() , 16);
        //b
        BigInteger b = AuthenticationUtil.get_b();
        //B
        BigInteger B = AuthenticationUtil.get_B(b, v);
        //salt
        String salt = AuthenticationUtil.getUserData(login).getSalt();

        //send Salt and B
        outMsg = new Message(serverName, salt);
        outMsg.setTag(Message.TAG_REG);
        outputStream.writeObject(outMsg);

        outMsg = new Message(serverName, B.toString(16));
        outMsg.setTag(Message.TAG_REG);
        outputStream.writeObject(outMsg);

        //u
        BigInteger u = AuthenticationUtil.sha256(A.toString(16) + B.toString(16));

        //S
        BigInteger S = AuthenticationUtil.get_serverS(A, B, v, u);
        //K
        BigInteger K = AuthenticationUtil.sha256(S.toString(16));
        //M1
        BigInteger M = AuthenticationUtil.get_M(login, salt, A, B, K);
        //R
        BigInteger R = AuthenticationUtil.get_R(A, M1, K);

        //get M from client
        inMsg = (Message) inputStream.readObject();
        BigInteger clientM = new BigInteger(inMsg.getText(), 16);

        System.out.println("M1:\n" + M.toString(16));
        System.out.println("Server M1:\n" + clientM.toString(16));

        if(M.compareTo(clientM) == 0) {
            System.out.println("Authentication success.");
        } else {
            System.out.println("Authentication failure. Wrong log:pass.");
            return false;
        }
        //send R to client
        outMsg = new Message(serverName, R.toString(16));
        outMsg.setTag(Message.TAG_REG);
        outputStream.writeObject(outMsg);
        return true;
    }

}
