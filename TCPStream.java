
import java.util.ArrayList;

public class TCPStream {
    
    private String[] ips;
    private int[] ports;

    public ArrayList<TransmissionControlProtocol> tcppackets = new ArrayList<TransmissionControlProtocol>();
    //public ArrayList<TransmissionControlProtocol> client_to_server = new ArrayList<TransmissionControlProtocol>();
    //public ArrayList<TransmissionControlProtocol> server_to_client = new ArrayList<TransmissionControlProtocol>();
    public ArrayList<ArrayList<TransmissionControlProtocol>> stream = new ArrayList<ArrayList<TransmissionControlProtocol>>();

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
        int streamno = -1;
        boolean reply = false;
        for(int i=0; i<this.tcppackets.size(); i++) {
            TransmissionControlProtocol tcp = this.tcppackets.get(i);
            if(tcp.getPayloadLength() != 0) {
                if(streamno == -1) {
                    if(tcp.getIp().getSource().equals(this.client_ip) && tcp.getPortSrc() == this.client_port) reply = false;
                    else reply = true;
                }
                if(tcp.getIp().getSource().equals(this.client_ip) && tcp.getPortSrc() == this.client_port) {
                    if(reply == false) {
                        streamno++;
                        reply = true;
                        this.stream.add(new ArrayList<TransmissionControlProtocol>());
                    }
                    // this.client_to_server.add(tcp);
                }
                else {
                    if(reply == true) {
                        streamno++;
                        reply = false;
                        this.stream.add(new ArrayList<TransmissionControlProtocol>());
                    }
                    // this.server_to_client.add(tcp);
                }
                this.stream.get(streamno).add(tcp);
            }
            else {
                for(TransmissionControlProtocol tcp2 : this.tcppackets) {
                    if(tcp2.getSequence() == tcp.getAcknowledgment()-1 || tcp2.getSequence() == tcp.getAcknowledgment()-tcp2.getPayloadLength()) {
                        tcp.setAckof(tcp2.getPacket().getUid());
                        break;
                    }
                }
            }
        }

        // reassemble
        for(int i=0; i<this.stream.size(); i++) {
            if(this.stream.get(i).size() > 1) {
                // calculate total length of the TCP payload
                int size = 0;
                for(TransmissionControlProtocol tcp : this.stream.get(i)) {
                    size += tcp.getPayloadLength();
                    tcp.setSegment();
                    tcp.setReassembledPacket(this.stream.get(i).get(this.stream.get(i).size() - 1).getPacket().getUid());
                }
                byte[] data = new byte[size];
                int offset = 0;
                // reassemble the data
                for(TransmissionControlProtocol tcp : this.stream.get(i)) {
                    byte[] tmp = tcp.getPayload();
                    for(int j = 0; j<tmp.length; j++) {
                        data[offset++] = tmp[j];
                    }            
                }
                // add the final payload to the last package and parse it
                this.stream.get(i).get(this.stream.get(i).size() - 1).setPayload(data);
                this.stream.get(i).get(this.stream.get(i).size() - 1).setLastSegment();
                //this.rebuildpacketid = this.fragments.get(this.fragments.size() - 1).getPacket().getUid();
            }
            this.stream.get(i).get(this.stream.get(i).size() - 1).parseProtocol();
        }
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

        if(this.client_ip == null && this.client_port == 0 && this.server_ip == null && this.server_port == 0) {
            TransmissionControlProtocol tcp = this.tcppackets.get(0);
            this.client_ip = tcp.getIp().getSource();
            this.server_ip = tcp.getIp().getDestination();
            this.client_port = tcp.getPortSrc();
            this.server_port = tcp.getPortDst();
        }
    }
}