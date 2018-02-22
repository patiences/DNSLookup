package ca.ubc.cs.cs317.dnslookup;

import java.util.*;

/**
 * Encapsulates a DNS Response.
 */
public class DNSResponse {

    public int transactionId;
    public byte[] byteData;
    public DNSNode DNSNode;
    public int qdCount;
    public int anCount;
    public int nsCount;
    public int arCount;
    public boolean authoritative;
    public List<ResourceRecord> answers;
    public List<ResourceRecord> nameServers;
    public List<ResourceRecord> additionals;


    public DNSResponse(byte[] data) {
        this.byteData = data;
        this.authoritative = false;
        this.answers = new ArrayList<>();
        this.nameServers = new ArrayList<>();
        this.additionals = new ArrayList<>();
        this.qdCount = 0;
        this.anCount = 0;
        this.nsCount = 0;
        this.arCount = 0;
    }
}
