package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;

/**
 * Encapsulates a DNS query.
 */
public class DNSQuery {

    public int id;
    public String hostName;
    public RecordType type;
    public InetAddress server;
    public byte[] query;

    public DNSQuery(int id, String hostName, RecordType type, InetAddress server, byte[] query) {
        this.id = id;
        this.hostName = hostName;
        this.type = type;
        this.server = server;
        this.query = query;
    }
}
