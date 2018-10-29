
import java.util.ArrayList;

public class TCPStream {
    
    private String[] ips;
    private int[] ports;

    public ArrayList<TransmissionControlProtocol> tcppackets =  new ArrayList<TransmissionControlProtocol>();
    public ArrayList<TransmissionControlProtocol> client_to_server =  new ArrayList<TransmissionControlProtocol>();
    public ArrayList<TransmissionControlProtocol> server_to_client =  new ArrayList<TransmissionControlProtocol>();

    private String client_ip;
    private String server_ip;

    private int client_port;
    private int server_port;

    private long client_init_seq;
    private long server_init_seq;    
    
    public TCPStream(String ip1, String ip2, int port1, int port2) {
        this.ips = new String[2];
        this.ips[0] = ip1;
        this.ips[1] = ip2;
        this.ports = new int[2];
        this.ports[0] = port1;
        this.ports[1] = port2;
    }

    public boolean areIps(String ip1, String ip2) {
        if(this.ips[0].equals(ip1) && this.ips[1].equals(ip2))
            return true;
        else if(this.ips[0].equals(ip2) && this.ips[1].equals(ip1))
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
        this.findHandshake();
        for(int i=0; i<this.tcppackets.size(); i++) {
            TransmissionControlProtocol tcp = this.tcppackets.get(i);
            if(tcp.getPayloadLength() != 0) {
                if(tcp.getIp().getSource().equals(this.client_ip)) {
                    this.client_to_server.add(tcp);
                }
                else {
                    this.server_to_client.add(tcp);
                }
            }
        }

        System.out.println("client to server: " + this.client_to_server.size());
        System.out.println("server to client: " + this.server_to_client.size());
    }

    private void findHandshake() {
        for(int p = 0; p<3; p++) {
            for(int i=0; i<this.tcppackets.size(); i++) {
                TransmissionControlProtocol tcp = this.tcppackets.get(i);
                if(tcp.getSyn() && !tcp.getAck()) {
                    this.client_ip = tcp.getIp().getSource();
                    this.server_ip = tcp.getIp().getDestination();
                    this.client_port = tcp.getPortSrc();
                    this.server_port = tcp.getPortDst();
                    this.client_init_seq = tcp.getSequence();
                    tcp.setHandshake();
                }
                else if(tcp.getSyn() && tcp.getAck()) {
                    this.server_init_seq = tcp.getSequence();
                    tcp.setHandshake();
                }
                else if(tcp.getAck() && this.server_init_seq+1 == tcp.getAcknowledgment() && !tcp.getFin() && tcp.getPayloadLength() == 0) {
                    tcp.setHandshake();
                }
            }
        }
    }
}