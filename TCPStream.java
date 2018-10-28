
import java.util.ArrayList;

public class TCPStream {
    
    private String[] ips;
    private int[] ports;

    public ArrayList<TransmissionControlProtocol> tcppackets =  new ArrayList<TransmissionControlProtocol>();

    // TCP handshake
    private TransmissionControlProtocol hs_syn;
    private TransmissionControlProtocol hs_synack;
    private TransmissionControlProtocol hs_ack;
    
    
    public TCPStream(String ip1, String ip2, int port1, int port2) {
        this.ips = new String[2];
        this.ips[0] = ip1;
        this.ips[1] = ip2;
        this.ports = new int[2];
        this.ports[0] = port1;
        this.ports[1] = port2;
    }

    public boolean areIps(String ip1, String ip2) {
        if(this.ips[0] == ip1 && this.ips[1] == ip2)
            return true;
        else if(this.ips[0] == ip2 && this.ips[1] == ip1)
            return true;
        return false;        
    }

    public boolean arePorts(int port1, int port2) {
        if(this.ports[0] == port1 && this.ports[1] == port2)
            return true;
        else if(this.ports[0] == port2 && this.ports[1] == port1)
            return true;
        return false;
    }
    
    public void add(TransmissionControlProtocol tcp) {
        this.tcppackets.add(tcp);
    }

    public void analyse() {
        
    }
}