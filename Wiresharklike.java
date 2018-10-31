
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Wiresharklike {

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
            this.packets = new ArrayList<Packet>();
            byte[] packetHeaderBuffer = new byte[Wiresharklike.packetHeaderSize];
            Packet packet;
            byte[] packetDataBuffer;
            while(this.is.read(packetHeaderBuffer) == Wiresharklike.packetHeaderSize) {
                packet = new Packet(this.packets.size(), packetHeaderBuffer);
                packetDataBuffer = new byte[packet.getDataSize()];
                this.is.read(packetDataBuffer);
                packet.setData(packetDataBuffer);
                this.packets.add(packet);
            }
        } catch (IOException exception) {
            exception.printStackTrace();
            System.exit(-1);
        }
    }

    public Wiresharklike(String pcap) {
        try {
            this.is = new FileInputStream(pcap);
        } catch(FileNotFoundException exception) {
            System.out.println("Pcap file not found.");
            exception.printStackTrace();
            System.exit(-1);
        }

        this.readGlobalHeader();
        this.readPackets();

        System.out.println("File: " + pcap + ", " + packets.size() + " packets found.\n");
        
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
            packets.get(i).print();
        }
    }

    public static void main(String[] args) {
        if(args.length == 0) {
            System.out.println("No pcap file given.");
            System.exit(-1);
        }
        new Wiresharklike(args[0]);        
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