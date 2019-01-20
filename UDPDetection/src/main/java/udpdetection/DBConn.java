package udpdetection;

import java.sql.*;

public class DBConn {

    private String Driver;
    private String Host;
    private String Database;
    private String Password;

    public DBConn(String Host, String Database, String Password) {
        this.Driver = "org.mariadb.jdbc.Driver";
        if (Host.contains("jdbc:mariadb://")) {
            this.Host = Host;
        } else {
            this.Host = "jdbc:mariadb://" + Host;
        }
        this.Database = Database;
        this.Password = Password;
    }

    private Connection Connect() throws Exception {
        Class.forName(Driver);
        return DriverManager.getConnection(Host, Database, Password);
    }

    public void SendUDPFlood(String toDestination, String fromDestination, Double ratio) {
        try {
            Connection conn = Connect();
            PreparedStatement statement = conn.prepareStatement("INSERT INTO udp_flood (source_ip, destination_ip, ratio) VALUES (?,?,?)");
            statement.setString(1, fromDestination);
            statement.setString(2, toDestination);
            statement.setDouble(3, ratio);
            statement.execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
