

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;

public class IPFragmentsGroup {
    
    public int id;
    public String source = "";
    public String destination = "";
    public ArrayList<InternetProtocol> fragments =  new ArrayList<InternetProtocol>();
    public String fragmentsids = "";
    public int rebuildpacketid = -1;
    
    public IPFragmentsGroup(int id, String source, String destination) {
        this.id = id;
        this.source = source;
        this.destination = destination;
    }
    
    public void add(InternetProtocol ip) {
        this.fragments.add(ip);
    }

    public void rebuild() {
        // sort ip fragments by offset
        Collections.sort(fragments, new Comparator<InternetProtocol>() {
            @Override
            public int compare(InternetProtocol ip1, InternetProtocol ip2)
            {        
                if(ip1.getOffset() < ip2.getOffset()) {
                    return -1;
                }
                return 1;
            }
        });

        // calculate total length of the IP payload
        int size = 0;
        for(InternetProtocol ip : this.fragments) {
            size += ip.getPayloadLength();
        }

        // reassemble the data
        byte[] data = new byte[size];
        int offset = 0;

        for(InternetProtocol ip : this.fragments) {
            this.fragmentsids += ip.packet.getUid() + ", ";
            byte[] tmp = ip.getPayload();
            for(int i = 0; i<tmp.length; i++) {
                data[offset++] = tmp[i];
            }            
        }
        this.fragmentsids = this.fragmentsids.substring(0, this.fragmentsids.length() - 2);

        // add the final payload to the last package and parse it
        this.fragments.get(this.fragments.size() - 1).setPayload(data);
        this.fragments.get(this.fragments.size() - 1).parseProtocol();
        this.fragments.get(this.fragments.size() - 1).setLastFragment();
        this.rebuildpacketid = this.fragments.get(this.fragments.size() - 1).getPacket().getUid();
    }
}

