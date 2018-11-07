
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Wiresharklike {

    public static boolean filter = false;
    public static boolean mac_addr = false;
    public static String v_mac = ""; 
    public static boolean mac_src = false;
    public static String v_mac_src = ""; 
    public static boolean mac_dst = false;
    public static String v_mac_dst = ""; 
    public static boolean ip_addr = false;
    public static String v_ip_addr = ""; 
    public static boolean ip_src = false;
    public static String v_ip_src = ""; 
    public static boolean ip_dst = false;
    public static String v_ip_dst = ""; 
    public static boolean port = false;
    public static String v_port = ""; 
    public static boolean port_src = false;
    public static String v_port_src = ""; 
    public static boolean port_dst = false;
    public static String v_port_dst = ""; 
    public static boolean tcp = false;
    public static String v_tcp = ""; 
    public static boolean udp = false;
    public static String v_udp = ""; 
    public static boolean http = false;
    public static String v_http = ""; 
    public static boolean dhcp = false;
    public static String v_dhcp = ""; 
    public static boolean arp = false;
    public static String v_arp = ""; 
    public static boolean ethernet = false;
    public static String v_ethernet = ""; 
    public static boolean icmp = false;
    public static String v_icmp = ""; 
    public static boolean ip = false;
    public static String v_ip = ""; 

    private String pcap;

    public static ArrayList<IPFragmentsGroup> ipfraggroup = new ArrayList<IPFragmentsGroup>();

    public static IPFragmentsGroup findIpFragmentsGroup(int id, String source, String destination) {
        for(IPFragmentsGroup ifg : Wiresharklike.ipfraggroup) {
            if(id == ifg.id && source.equals(ifg.source) && destination.equals(ifg.destination)) {
                return ifg;
            }
        }
        return null;
    }

    public static ArrayList<ICMPStream> icmpstreams = new ArrayList<ICMPStream>();

    public static ICMPStream findICMPStream(int id, int sequence) {
        for(ICMPStream is : Wiresharklike.icmpstreams) {
            if(id == is.getId() && sequence == is.getSequence()) {
                return is;
            }
        }
        return null;
    }

    public static ArrayList<TCPStream> tcpstreams = new ArrayList<TCPStream>();

    public static TCPStream findTCPStream(String ip1, String ip2, int port1, int port2) {
        for(TCPStream ts : Wiresharklike.tcpstreams) {
            if(ts.areIps(ip1, ip2) && ts.arePorts(port1, port2)) {
                return ts;
            }
        }
        return null;
    }

    private InputStream is;
    private GlobalHeader globalHeader;
    public static ArrayList<Packet> packets;

    private static final int globalHeaderSize = 24;
    private static final int packetHeaderSize = 16;

    private void readGlobalHeader() {
        try {
            byte[] globalHeaderBuffer = new byte[Wiresharklike.globalHeaderSize];
            if(this.is.read(globalHeaderBuffer) == Wiresharklike.globalHeaderSize) {
                this.globalHeader = new GlobalHeader(globalHeaderBuffer);
            }
        } catch (IOException exception) {
            exception.printStackTrace();
            System.exit(-1);
        } catch(PcapException exception) {
            exception.printStackTrace();
            System.exit(-1);
        }
    }

    public void readPackets() {
        try {
            Wiresharklike.packets = new ArrayList<Packet>();
            byte[] packetHeaderBuffer = new byte[Wiresharklike.packetHeaderSize];
            Packet packet;
            byte[] packetDataBuffer;
            while(this.is.read(packetHeaderBuffer) == Wiresharklike.packetHeaderSize) {
                packet = new Packet(Wiresharklike.packets.size(), packetHeaderBuffer);
                packetDataBuffer = new byte[packet.getDataSize()];
                this.is.read(packetDataBuffer);
                packet.setData(packetDataBuffer);
                Wiresharklike.packets.add(packet);
            }
        } catch (IOException exception) {
            exception.printStackTrace();
            System.exit(-1);
        }
    }

    public Wiresharklike(String pcap) {
        try {
            this.is = new FileInputStream(pcap);
            this.pcap = pcap;
        } catch(FileNotFoundException exception) {
            System.out.println("Pcap file not found.");
            exception.printStackTrace();
            System.exit(-1);
        }
    }

    public void run() {
        this.readGlobalHeader();
        this.readPackets();

        System.out.println("File: " + this.pcap + ", " + packets.size() + " packets found.\n");
        
        try {
            is.close();
        } catch (IOException exception) {
            exception.printStackTrace();
            System.exit(-1);
        }

        /* parsing packets from pcap file */
        for(int i=0; i<packets.size(); i++) {
            packets.get(i).parse();
        }
        
        /* rebuild from IP fragmentation */
        for(int i =0; i<Wiresharklike.ipfraggroup.size(); i++) {
            Wiresharklike.ipfraggroup.get(i).rebuild();
        }
        
        /* analyse TCP stream */
        for(int i =0; i<Wiresharklike.tcpstreams.size(); i++) {
            Wiresharklike.tcpstreams.get(i).analyse();
        }

        /* print */
        for(int i=0; i<packets.size(); i++) {
            if(Wiresharklike.filter) {
                if(Wiresharklike.filter(i)) {
                    packets.get(i).print();
                }
            }
            else {
                packets.get(i).print();
            }
        }
    }

    public static boolean filter(int i) {
        // check for protocol
        if(Wiresharklike.arp == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == AddressResolutionProtocol.class) {
                    return true;
                }
            }
        }
        else if(Wiresharklike.icmp == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == InternetControlMessageProtocol.class) {
                    return true;
                }
            }
        }
        else if(Wiresharklike.ip == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == InternetProtocol.class) {
                    return true;
                }
            }
        }
        else if(Wiresharklike.tcp == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == TransmissionControlProtocol.class) {
                    return true;
                }
            }
        }
        else if(Wiresharklike.udp == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == UserDatagramProtocol.class) {
                    return true;
                }
            }
        }
        else if(Wiresharklike.http == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == HypertextTransferProtocol.class) {
                    return true;
                }
            }
        }

        // check mac addr
        if(Wiresharklike.mac_addr == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == EthernetProtocol.class) {
                    EthernetProtocol eth = (EthernetProtocol) p;
                    if(eth.source.equals(Wiresharklike.v_mac) || eth.destination.equals(Wiresharklike.v_mac)) {
                        return true;
                    }
                }
            }
        }
        else if(Wiresharklike.mac_src == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == EthernetProtocol.class) {
                    EthernetProtocol eth = (EthernetProtocol) p;
                    if(eth.source.equals(Wiresharklike.v_mac_src)) {
                        return true;
                    }
                }
            }
        }
        else if(Wiresharklike.mac_dst == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == EthernetProtocol.class) {
                    EthernetProtocol eth = (EthernetProtocol) p;
                    if(eth.destination.equals(Wiresharklike.v_mac_dst)) {
                        return true;
                    }
                }
            }
        }

        // check ip addr 
        if(Wiresharklike.ip_addr == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == InternetProtocol.class) {
                    InternetProtocol ip = (InternetProtocol) p;
                    if(ip.source.equals(Wiresharklike.v_ip) || ip.destination.equals(Wiresharklike.v_ip)) {
                        return true;
                    }
                }
            }
        }
        else if(Wiresharklike.ip_src == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == InternetProtocol.class) {
                    InternetProtocol ip = (InternetProtocol) p;
                    if(ip.source.equals(Wiresharklike.v_ip_src)) {
                        return true;
                    }
                }
            }
        }
        else if(Wiresharklike.ip_dst == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == InternetProtocol.class) {
                    InternetProtocol ip = (InternetProtocol) p;
                    if(ip.destination.equals(Wiresharklike.v_ip_dst)) {
                        return true;
                    }
                }
            }
        }

        // check tcp or udp port
        if(Wiresharklike.port == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == TransmissionControlProtocol.class) {
                    TransmissionControlProtocol tcp = (TransmissionControlProtocol) p;
                    if(tcp.source == Integer.parseInt(Wiresharklike.v_port) || tcp.destination == Integer.parseInt(Wiresharklike.v_port)) {
                        return true;
                    }
                }
                else if(p.getClass() == UserDatagramProtocol.class) {
                    UserDatagramProtocol udp = (UserDatagramProtocol) p;
                    if(udp.source == Integer.parseInt(Wiresharklike.v_port) || udp.destination == Integer.parseInt(Wiresharklike.v_port)) {
                        return true;
                    }
                }
            }
        }
        else if(Wiresharklike.port_src == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == TransmissionControlProtocol.class) {
                    TransmissionControlProtocol tcp = (TransmissionControlProtocol) p;
                    if(tcp.source == Integer.parseInt(Wiresharklike.v_port_src)) {
                        return true;
                    }
                }
                else if(p.getClass() == UserDatagramProtocol.class) {
                    UserDatagramProtocol udp = (UserDatagramProtocol) p;
                    if(udp.source == Integer.parseInt(Wiresharklike.v_port_src)) {
                        return true;
                    }
                }
            }
        }
        else if(Wiresharklike.port_dst == true) {
            for(Protocol p : Wiresharklike.packets.get(i).protocols) {
                if(p.getClass() == TransmissionControlProtocol.class) {
                    TransmissionControlProtocol tcp = (TransmissionControlProtocol) p;
                    if(tcp.destination == Integer.parseInt(Wiresharklike.v_port_dst)) {
                        return true;
                    }
                }
                else if(p.getClass() == UserDatagramProtocol.class) {
                    UserDatagramProtocol udp = (UserDatagramProtocol) p;
                    if(udp.destination == Integer.parseInt(Wiresharklike.v_port_dst)) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    public static void main(String[] args) {
        if(args.length == 0) {
            System.out.println("No pcap file given.");
            System.exit(-1);
        }
        
        Wiresharklike wiresharklike = new Wiresharklike(args[0]); 

        try {
            if(args.length > 1) {
                for(int i=1; i<args.length - 1; i+=2) {
                    Wiresharklike.parseArgs(args[i], args[i+1]);
                }
                Wiresharklike.filter = true;
            }
        } catch(ArrayIndexOutOfBoundsException exception) {
            System.out.println("Not enougth argument.");
        }
        
        wiresharklike.run();
    }

    public static void parseArgs(String key, String value) {
        switch(key) {
            case "mac.addr":
            Wiresharklike.mac_addr = true;
            Wiresharklike.v_mac = value;
            break;
            case "mac.src":
            Wiresharklike.mac_src = true;
            Wiresharklike.v_mac_src = value;
            break;
            case "mac.dst":
            Wiresharklike.mac_dst = true;
            Wiresharklike.v_mac_dst = value;
            break;
            case "ip.addr":
            Wiresharklike.ip_addr = true;
            Wiresharklike.v_ip = value;
            break;
            case "ip.src":
            Wiresharklike.ip_src = true;
            Wiresharklike.v_ip_src = value;
            break;
            case "ip.dst":
            Wiresharklike.ip_dst = true;
            Wiresharklike.v_ip_dst = value;
            break;
            case "port":
            Wiresharklike.port = true;
            Wiresharklike.v_port = value;
            break;
            case "port.src":
            Wiresharklike.port_src = true;
            Wiresharklike.v_port_src = value;
            break;
            case "port.dst":
            Wiresharklike.port_dst = true;
            Wiresharklike.v_port_dst = value;
            break;            
            case "proto":
                switch(value) {
                    case "tcp":
                    Wiresharklike.tcp = true;
                    break;
                    case "udp":
                    Wiresharklike.udp = true;
                    break;
                    case "http":
                    Wiresharklike.http = true;
                    break;
                    case "dhcp":
                    Wiresharklike.dhcp = true;
                    break;
                    case "arp":
                    Wiresharklike.arp = true;
                    break;
                    case "icmp":
                    Wiresharklike.icmp = true;
                    break;
                }
            break;
        }
    }

    /* util functions */

    /* reverse an array */
    public static void reverse(byte[] array) {
        for(int i=0; i<array.length/2; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = tmp;
        }
    }    

    /* print a byte array in hexadecimal */
    public static void printBytes(byte[] array) {
        for (byte b : array) {
            System.out.format("%02X ", b);
        }
        System.out.println();
    }

    /* transform an array of bytes into an int */
    public static int bytesToInt(byte[] bytes) {
        int v = 0;
        for(int i=0; i<bytes.length; i++) {
            v = v << 8;
            v = v | (bytes[i] & 0xFF);
        }
        return v;
    }

    /* transform an array of bytes into an int */
    public static long bytesToLong(byte[] bytes) {
        long v = 0;
        for(int i=0; i<bytes.length; i++) {
            v = v << 8;
            v = v | (bytes[i] & 0xFF);
        }
        return v;
    }

    /* transform a byte into an array of int */
    public static int[] toBits(byte B) {
        int[] bits = new int[8];
        for(int i=0; i<8; i++) {
            bits[7-i] = (B >> i) & 1;
        }
        return bits;
    }

    /* transform an array byte into an array of int */
    public static int[] arrayToBits(byte[] B) {
        int[] bits = new int[B.length * 8];
        for(int j=0; j<B.length; j++) {
            for(int i=0; i<8; i++) {
                bits[(B.length * 8)-1-j-i] = (B[j] >> i) & 1;
            }
        }
        return bits;
    }

    public static int[] binToBits(byte b) {
        int[] bits = new int[8];
        for(int i=0; i<8; i++) {
            bits[7-i] = (b >> i) & 1;
        }
        return bits;
    }

    /* transform an array of int (bits) into an int */
    public static int restoreInt(int[] bits) {
        int v = 0;
        for(int i=0; i<bits.length; i++) {
            v = (v << 1) | bits[i];
        }
        return v;
    }

    /* return @Mac in String from byte[] @Mac */
    public static String parseMac(byte[] bytes) {        
        String mac = "";
        for(int i=0; i<6; i++) {
            mac += String.format("%02X:", bytes[i]);
        }
        mac = mac.substring(0, mac.length() - 1);
        return mac;
    }

    /* return @IP in String from byte[] @IP */
    public static String parseIp(byte[] bytes) {
        String ip = "";
        for(int i=0; i<4; i++) {
            ip += Integer.parseInt(String.format("%X", bytes[i]), 16) + ".";
        }
        ip = ip.substring(0, ip.length() - 1);
        return ip;
    }

    /* return Protocol from byte[] type */
    public static Protocol parseProtocolType(Packet packet, byte[] bytes) {
        Protocol protocol = null;
        if(Arrays.equals(bytes, InternetProtocol.hexaValue)) {
            protocol = new InternetProtocol(packet);
        }
        else if(Arrays.equals(bytes, AddressResolutionProtocol.hexaValue)) {
            protocol = new AddressResolutionProtocol(packet);
        }
        else if(Arrays.equals(bytes, TransmissionControlProtocol.hexaValue)) {
            protocol = new TransmissionControlProtocol(packet);
        }
        else if(Arrays.equals(bytes, UserDatagramProtocol.hexaValue)) {
            protocol = new UserDatagramProtocol(packet);
        }
        else if(Arrays.equals(bytes, InternetControlMessageProtocol.hexaValue)) {
            protocol = new InternetControlMessageProtocol(packet);
        }
        else {
            protocol = new UnknownProtocol(packet);
        }
        return protocol;
    }

    /* payload in hexa to data */
    public static String byteToAscii(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        String tmp = "";
        for(int i=0; i<bytes.length; i++) {
            tmp = String.format("%02X", bytes[i]);
            if(Integer.parseInt(tmp, 16) >= 32 && Integer.parseInt(tmp, 16) <= 126)
                result.append((char) Integer.parseInt(tmp, 16));
            else if(Integer.parseInt(tmp, 16) == 10)
                result.append("\n");
            else if(Integer.parseInt(tmp, 16) == 9)
                result.append("\t");
            else if(Integer.parseInt(tmp, 16) == 13)
                result.append("");
            else
                result.append(".");
        }
        return result.toString();
    }
}