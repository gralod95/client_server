package laix.client_server;


import java.io.Serializable;

public class Message implements Serializable{
    private String name;
    private String text;
    private boolean requestAnswer;
    private int tag;

    public final static int TAG_MSG = 0;
    public final static int TAG_REG = 1;
    public final static int TAG_AUTH = 2;
    public final static int TAG_STOP = 3;

    public Message(String name, String text) {
        this.name = name;
        this.text = text;
        requestAnswer = false;
        tag = Message.TAG_MSG;
    }

    public void setName(String n) {
        name = n;
    }

    public void setText(String t) {
        text = t;
    }

    public String getName() {
        return name;
    }

    public String getText() {
        return text;
    }

    public void print() {
        System.out.println("[" + name + "]:" + text);
    }

    public void setRequestAnswer(boolean b) {
        requestAnswer = b;
    }

    public boolean isRequestAnswer() {
        return requestAnswer;
    }

    public int getTag() {
        return tag;
    }

    public void setTag(int tag) {
        this.tag = tag;
    }
}
