package laix.client_server;


import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    private static int port = 9898;

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        AuthenticationUtil.loadDataBase();
        ServerSocket serverSock = new ServerSocket(port);
        System.out.println("Server started with port: " + port);

        while(true) {
            Socket clientSock = null;
            while (clientSock == null) {
                clientSock = serverSock.accept();
            }
            new ServerThread(clientSock);
        }
    }
}
