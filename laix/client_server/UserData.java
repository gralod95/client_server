package laix.client_server;

/**
 * Created by La1x on 15.09.2016.
 */
public class UserData {
    private String salt;
    private String v;

    public UserData(String s, String v) {
        this.v = v;
        this.salt = s;
    }

    public void setV(String v) {
        this.v = v;
    }

    public void setSalt(String s) {
        this.salt = s;
    }

    public String getV() {
        return v;
    }

    public String getSalt() {
        return salt;
    }
}
