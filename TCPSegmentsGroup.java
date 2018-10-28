
import java.util.ArrayList;

public class TCPSegmentsGroup {

    private String ip_src;
    private String ip_dst;
    private int port_src;
    private int port_dst;
    
    public static ArrayList<TransmissionControlProtocol> segments = new ArrayList<TransmissionControlProtocol>();
    
    public TCPSegmentsGroup(String ip_src, String ip_dst, int port_src, int port_dst) {
        this.ip_src = ip_src;
        this.ip_dst = ip_dst;
        this.port_src = port_src;
        this.port_dst = port_dst;
    }
}