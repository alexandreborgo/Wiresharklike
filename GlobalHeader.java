import java.util.Arrays;

public class GlobalHeader {
    /* 192b = 24B */
    private byte[] header;
    private byte[] magic_number;    /* 32b magic number */
    private boolean ordering;       /* False = swapped; True = identical */    
    private byte[] version_major;   /* 16b major version number */
    private byte[] version_minor;   /* 16b minor version number */
    private float version;          /* version */
    private int thiszone;           /* 32b GMT to local correction */
    private int sigfigs;            /* 32b accuracy of timestamps */
    private int snaplen;            /* 32b max length of captured packets, in octets */
    private int network;            /* 32b data link type */

    private final byte[] identical = {(byte)0xA1, (byte)0xB2, (byte)0xC3, (byte)0xD4}; /* identical ordering */
    private final byte[] swapped = {(byte)0xD4, (byte)0xC3, (byte)0xB2, (byte)0xA1}; /* swapped ordering */    
    private final byte[] major = {(byte)0, (byte)2}; /* identical ordering */
    private final byte[] minor = {(byte)0, (byte)4}; /* swapped ordering */
    
    public GlobalHeader(byte[] bytes) throws PcapException {
        this.header = bytes;

        this.magic_number = Arrays.copyOfRange(this.header, 0, 4);

        if(Arrays.equals(this.magic_number, this.identical)) {
            System.out.println("Identical ordering.");
            this.ordering = true;
        }
        else if(Arrays.equals(this.magic_number, this.swapped)) {
            System.out.println("Swapped ordering.");
            this.ordering = false;
        }
        else {
            throw new PcapException("Invalid ordering found in pcap.");
        }        
        
        this.version_major = Arrays.copyOfRange(this.header, 4, 6);
        this.version_minor = Arrays.copyOfRange(this.header, 6, 8);
        
        if(!ordering) {
            this.reverse(this.version_major);
            this.reverse(this.version_minor);
        }

        if(Arrays.equals(this.version_major, this.major) && Arrays.equals(this.version_minor, this.minor)) {
            this.version = 2.4f;
        }
        else {            
            throw new PcapException("Version not supported.");
        }
    }

    public void printHeaderBytes() {
        for (byte b : this.header) {
            System.out.format("%02X ", b);
        }
        System.out.println();
    }

    public void reverse(byte[] array) {
        for(int i=0; i<array.length/2; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = tmp;
        }
    }
}