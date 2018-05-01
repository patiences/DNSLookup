package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.net.*;
import java.util.*;

import org.checkerframework.checker.nullness.qual.*;

import java.io.*;

public class DNSLookupService {

	// The default port to use for sending datagram packets 
    private static final int DEFAULT_DNS_PORT = 53;
    // The maximum number of redirections handled 
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private @MonotonicNonNull static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private @MonotonicNonNull static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);
        
        // Close the scanner 
        in.close();
        // Close the socket 
        	socket.close();
        
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them to the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type to search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // Check the cache to see if we already have a value for this query 
        Set<ResourceRecord> cachedResults = cache.getCachedResults(node);
        if (cachedResults.isEmpty()) {
            // Send the query to the root server 
        		if (rootServer != null)
        			retrieveResultsFromServer(node, rootServer);
        }

        // If we are not looking for a CNAME record
        if (node.getType() != RecordType.CNAME) {
            // Yet the answer is a CNAME, resolve that
            DNSNode CNAMENode = new DNSNode(node.getHostName(), RecordType.CNAME);
            if (!cache.getCachedResults(CNAMENode).isEmpty()) {
                ResourceRecord cnameRecordToTry = cache.getCachedResults(CNAMENode).iterator().next();
                return getResults(new DNSNode(cnameRecordToTry.getTextResult(),
                        node.getType()), indirectionLevel++);
            }
        }

        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, @NonNull InetAddress server) {

    		/* Create a DNS query*/
    	
        // Send an A query
        DNSQuery queryData = constructSendQuery(node, server);
        byte[] responseBuffer = null;

        // Only retry queries if they timeout once, then give up
        try {
            responseBuffer = queryServer(queryData);
        } catch (IOException e1) {
            if (e1 instanceof SocketTimeoutException) {
                try {
                    responseBuffer = queryServer(queryData);
                } catch (IOException e2) {
                    // don't attempt again
                    return;
                }
            } else {
                // don't worry about this exception
            }
        }

        if (responseBuffer != null) {
            DNSResponse dnsResponse = parseDNSResponse(responseBuffer);

            // Cache received answers
            if (dnsResponse.anCount > 0) {
                for (ResourceRecord rr : dnsResponse.answers) {
                    cache.addResult(rr);
                }
            }

            // Don't cache authoritative responses

            // Cache records in additional section
            if (dnsResponse.arCount > 0) {
                for (ResourceRecord rr : dnsResponse.additionals) {
                    cache.addResult(rr);
                }
            }

            /* Determine the next query, if any */
            if (dnsResponse.anCount == 0) {
                // Didn't get an answer

                // Find next server to query
                if (dnsResponse.nameServers.size() > 0) {
                    // Get the first authoritative record
                    ResourceRecord nsRR = dnsResponse.nameServers.get(0);
                    String nextServerName = nsRR.getTextResult();
                    // Get all records in the additional section for the next server
                    List<ResourceRecord> nextServerRecords = new ArrayList<>();
                    for (ResourceRecord rr : dnsResponse.additionals) {
                        if (rr.getNode().getHostName().equals(nextServerName)) {
                            nextServerRecords.add(rr);
                        }
                    }

                    // Found a Resource Record in Additional section matching the server
                    if (!nextServerRecords.isEmpty()) {
                        // Use the first record
                        ResourceRecord nextServerRecord = nextServerRecords.get(0);

                        // Case 1: There is an IP address to query
                        if (nextServerRecord.getInetResult() != null) {
                            InetAddress nextAddress = nextServerRecord.getInetResult();
                            // Repeat the query with this server
                            if (nextAddress != null)
                            		retrieveResultsFromServer(node, nextAddress);
                            
                            return;
                        }
                    }

                    // Case 2: Couldn't find a Record in the Additional section with an IP,
                    // must resolve an NS first
                    String textResult = nsRR.getTextResult();
                    if (nsRR.getNode().getType() == RecordType.NS) {
                        // This is a nameserver URL that needs to be resolved to an IP
                        DNSNode newNode = new DNSNode(textResult, RecordType.A);
                        Set<ResourceRecord> rrs = getResults(newNode, 0);
                        if (!rrs.isEmpty()) {
                            for (ResourceRecord rr : rrs) {
                                if (rr.getInetResult() != null) {
                                    // Found the next server to query
                                    InetAddress nextAddress = rr.getInetResult();
                                    if (nextAddress != null)
                                    		retrieveResultsFromServer(node, nextAddress);
                                    return;
                                }
                            }
                        }
                    }

                    // If we reach this point, the resolution was unsuccessful --
                    // could not resolve a next address to go to
                    return;
                }
            }
        }
    }

    /**
     * Handles interactions with the server, namely, sends the query and receives the response. 
     * 
     * @param queryData  	A @DNSQuery containing the information to send. 
     * @return the buffer containing the received response. 
     * @throws IOException if an I/O error occurs while sending or receiving from the socket. 
     */
    private static byte[] queryServer(DNSQuery queryData) throws IOException {

        byte[] query = queryData.query;

        /* Send the DNS query to the server */
        DatagramPacket dnsQueryPacket = new DatagramPacket(query, query.length, queryData.server, DEFAULT_DNS_PORT);
        if (verboseTracing) {
            System.out.format("\n\nQuery ID     %d %s  %s --> %s\n",
                    queryData.id, queryData.hostName, queryData.type,
                    queryData.server.getHostAddress());
        }
        if (socket != null) {
        		socket.send(dnsQueryPacket);
        } else {
        		System.err.println("Socket has not been initialized"); 
        }

        /* Handle response from server */
        byte[] receivedBuf = new byte[1024];
        DatagramPacket receivedPacket = new DatagramPacket(receivedBuf, receivedBuf.length);
        if (socket != null) {
        socket.receive(receivedPacket);
        } else {
        		System.err.println("Socket has not been initialized");
        }

        return receivedBuf;
    }

    /**
     * Constructs the query to send. 
     * 
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     * @return a @DNSQuery with the necessary information. 
     */
    private static DNSQuery constructSendQuery(DNSNode node, InetAddress server) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
        int id = random.nextInt(65536); // generate an id (16 bit) number in [0,65535]
        
        /* Construct DNS Query */

        try {

            // ID
            dataOutputStream.writeShort((short) (id & 0xffff));

            // QR, Opcode, AA, TC, RD, RA, Z, RCODE
            dataOutputStream.writeShort(0x0000);

            // Query Count (QDCOUNT)
            dataOutputStream.writeShort(0x0001);

            // Answer Count (ANCOUNT)
            dataOutputStream.writeShort(0x0000);

            // Name Server Records (NSCOUNT)
            dataOutputStream.writeShort(0x0000);

            // Additional Record Count (ARCOUNT)
            dataOutputStream.writeShort(0x0000);

            // QNAME
            String[] labels = node.getHostName().split("\\.");
            for (String label : labels) {
                byte[] labelBytes = label.getBytes("UTF-8");
                dataOutputStream.writeByte(labelBytes.length);
                dataOutputStream.write(labelBytes);
            }

            // End of QNAME
            dataOutputStream.writeByte(0x00);

            // QTYPE
            // Use the record type given in the DNS node
            short recordType = recordTypeToShort(node.getType());
            dataOutputStream.writeShort(recordType);

            // QCLASS
            dataOutputStream.writeShort(0x0001);

        } catch (IOException e) {
            System.err.println("Failed to construct DNS query, please try again.");
        }
        
        return new DNSQuery(id, node.getHostName(), node.getType(), server,
                byteArrayOutputStream.toByteArray());

    }

    /**
     * Handles the response from the server. 
     * 
     * @param buf	The received buffer. 
     * @return A @DNSResponse object with the parsed information. 
     */
    private static DNSResponse parseDNSResponse(byte[] buf) {
        DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(buf));
        DNSResponse dnsResponse = new DNSResponse(buf); 
        
    		/* Parse header */
        
        try {
            // Bytes 0, 1: ID
            dnsResponse.transactionId = (dataInputStream.readShort() & 0x00ff);

            // Bytes 2, 3: QR, Opcode, AA, TC, RD, RA, Z, RCODE
            short flags = dataInputStream.readShort();
            int rcode = flags & 0xf;
            // Error RCODEs
            if (rcode == 3 || rcode == 5) {
                // Return, no need to parse the rest of the response
                return dnsResponse;
            }

            short aaMask = (short) 0x0400;
            boolean authoritative = (short) (aaMask & flags) == aaMask;
            dnsResponse.authoritative = authoritative;

            // Bytes 4, 5: Query Count (QDCOUNT)
            dnsResponse.qdCount = (int) dataInputStream.readShort();

            // Bytes 6, 7: Answer Count (ANCOUNT)
            dnsResponse.anCount = (int) dataInputStream.readShort();

            // Bytes 8, 9: Name Server Records (NSCOUNT)
            dnsResponse.nsCount = (int) dataInputStream.readShort();

            // Bytes 10, 11: Additional Record Count (ARCOUNT)
            dnsResponse.arCount = (int) dataInputStream.readShort();

            // Header is 12 bytes long
            int nextByteIndex = 12;

    	    	/* Parse Query Section */
            if (dnsResponse.qdCount > 0) {
                nextByteIndex = handleDNSResponseQuerySection(dnsResponse, buf, nextByteIndex);
            }

    	    /* Parse Answer Section */
            if (dnsResponse.anCount > 0) {
                nextByteIndex = handleResourceRecords(dnsResponse, dnsResponse.anCount,
                        buf, nextByteIndex, "ANSWER");
            }

    	    /* Parse Name Server Records Section */
            if (dnsResponse.nsCount > 0) {
                nextByteIndex = handleResourceRecords(dnsResponse, dnsResponse.nsCount,
                        buf, nextByteIndex, "AUTHORITY");
            }
    	
    	    /* Parse Additional Records Section */
            if (dnsResponse.arCount > 0) {
                handleResourceRecords(dnsResponse, dnsResponse.arCount,
                        buf, nextByteIndex, "ADDITIONAL");
            }

            if (verboseTracing) {
                // Print response id and authoritative bit
                System.out.format("Response ID: %s Authoritative = %s\n",
                        dnsResponse.transactionId, dnsResponse.authoritative);
                // Print answers
                System.out.format("  Answers (%d)\n", dnsResponse.anCount);
                for (ResourceRecord rr : dnsResponse.answers) {
                    verbosePrintResourceRecord(rr, rr.getType().getCode());
                }
                // Print name servers
                System.out.format("  Nameservers (%d)\n", dnsResponse.nsCount);
                for (ResourceRecord rr : dnsResponse.nameServers) {
                    verbosePrintResourceRecord(rr, rr.getType().getCode());
                }
                // Print additionals
                System.out.format("  Additional Information (%d)\n", dnsResponse.arCount);
                for (ResourceRecord rr : dnsResponse.additionals) {
                    verbosePrintResourceRecord(rr, rr.getType().getCode());
                }
            }

        } catch (IOException e) {
            System.err.println("Failed to parse DNS response, please try again.");
        }

        return dnsResponse;
    }

    /**
     * Parse the query section of the DNS response.
     *
     * @param dnsResponse
     * @param buf
     * @param startingByteIndex
     * @return the index of the next section in the buffer
     */
    private static int handleDNSResponseQuerySection(DNSResponse dnsResponse, byte[] buf,
                                                     int startingByteIndex) {
        DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(buf));
        int bytesRead = 0;

        try {
            // Start from the starting byte index
            dataInputStream.skipBytes(startingByteIndex);

            // Domain Name
            String domainName = resolveName(buf, startingByteIndex);
            // The following code just reads bytes until we get to the next section in the record.
            // The domain name resolution is done in the method call above
            int labelLength = 0;
            while ((labelLength = dataInputStream.readByte()) != 0) {
                bytesRead++;
                for (int i = 0; i < labelLength; i++) {
                    dataInputStream.readByte();
                    bytesRead++;
                }
            }
            bytesRead++;

            // TYPE
            short type = dataInputStream.readShort();
            RecordType recordType = RecordType.getByCode((int) type);
            bytesRead += 2;

            // CLASS
            dataInputStream.readShort();
            bytesRead += 2;

            // Create DNS node for this DNS response
            DNSNode node = new DNSNode(domainName, recordType);
            dnsResponse.DNSNode = node;

        } catch (IOException e) {
            System.err.println("Failed to handle DNS Response Query Section, please try again.");
        }

        return startingByteIndex + bytesRead;
    }

    /**
     * Parse the resource records sections (Answer, Authority and Additional) of the DNS response.
     *
     * @param dnsResponse
     * @param numRecords
     * @param buf
     * @param startingByteIndex
     * @param section
     * @return the index of the next section in the buffer
     */
    private static int handleResourceRecords(DNSResponse dnsResponse, int numRecords,
                                             byte[] buf, int startingByteIndex, String section) {
        DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(buf));
        int bytesRead = 0;

        try {
            // Start from the starting byte index
            dataInputStream.skipBytes(startingByteIndex);

            for (int i = 0; i < numRecords; i++) {

            		// Domain Name
    	        		/** 
    	        		 * A domain name can be represented as either:
    	        		 * Case 1: Name is a sequence of labels ending in a zero octet
    	        		 * Case 2: Name is a pointer (2 octets beginning with bits 11)
    	        		 * Case 3: Name is a sequence of labels ending with a pointer
    	        		 */
            		String domainName = resolveName(buf, startingByteIndex + bytesRead);

                // This section just reads bytes until we get to the next section in the record.
                // Domain name resolution is done by the above method.
                int labelLength = 0;
                byte dataByte;
                while ((dataByte = dataInputStream.readByte()) != 0) {
                    bytesRead++;
                    // Check if it's a pointer
                    byte mask = (byte) 0xc0;
                    // If top bits are binary 11
                    if ((dataByte & mask) == mask) {
                        dataInputStream.readByte();
                        // bytesRead is incremented at the end of while loop
                        break;
                    } else {
                        // This is a label length
                        labelLength = dataByte;
                        for (int j = 0; j < labelLength; j++) {
                            dataInputStream.readByte();
                            bytesRead++;
                        }
                    }
                }
                bytesRead++;

                // TYPE
                short type = dataInputStream.readShort();
                RecordType recordType = RecordType.getByCode((int) type);
                bytesRead += 2;

                // CLASS
                dataInputStream.readShort();
                bytesRead += 2;

                // TTL
                int ttl = dataInputStream.readInt();
                bytesRead += 4;

                // RDLENGTH
                short rdLength = dataInputStream.readShort();
                bytesRead += 2;

                // RDATA
                // Keep this offset for #resolveName
                int offsetToRDATA = startingByteIndex + bytesRead;
                byte[] rdata = new byte[rdLength];
                for (int j = 0; j < rdLength; j++) {
                    rdata[j] = dataInputStream.readByte();
                    bytesRead++;
                }

                if (shouldKeepRecord(recordType)) {
                    ResourceRecord rr;

                    if (recordType == RecordType.A || recordType == RecordType.AAAA) {
                        // This is an IPV4 or IPV6 address
                        InetAddress address = InetAddress.getByAddress(rdata);
                        rr = new ResourceRecord(domainName, recordType, ttl, address);
                    } else { // Record type CNAME or NS
                        // This is a name server or CNAME record
                        String resolvedName = resolveName(buf, offsetToRDATA);
                        rr = new ResourceRecord(domainName, recordType, ttl, resolvedName);
                    }

                    if (section == "ANSWER") {
                        dnsResponse.answers.add(rr);
                    } else if (section == "AUTHORITY") {
                        dnsResponse.nameServers.add(rr);
                    } else if (section == "ADDITIONAL") {
                        dnsResponse.additionals.add(rr);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to handle resource record, please try again");
        }

        return startingByteIndex + bytesRead;
    }

    /**
     * Builds up the domain name (and handles message compression). 
     * 
     * @param message 				A byte array containing the entire message 
     * @param offsetToNameSection 	The offset from the beginning of the domain name section. 
     * @return a String containing the domain name. 
     */
    private static String resolveName(byte[] message, int offsetToNameSection) {
        return resolveName(message, offsetToNameSection, "");
    }

    /**
     * Builds up a piece of the domain name. To handle message compression (see RFC 1034, 
     * section 4.1.4), we may have to follow multiple pointers to resolve recursive parts of the 
     * domain name, so we can't do this iteratively. 
     * 
     * @param message 			A byte array containing the entire message. 
     * @param startingOffset		The offset to the beginning of this portion of the name. 
     * @param nameSoFar			The constructed name so far. 
     * @return a String containing the resolved domain name so far. 
     */
    private static String resolveName(byte[] message, int startingOffset, String nameSoFar) {
    	
        DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(message));

        String domainName = nameSoFar;
        /** A domain name can be represented as either:
    	 	* Case 1: Name is a sequence of labels ending in a zero octet
    	 	* Case 2: Name is a pointer (2 octets beginning with bits 11)
    	 	* Case 3: Name is a sequence of labels ending with a pointer
    	 	*/
        try {
            // Start from the starting index
            if (startingOffset > 0) {
                dataInputStream.skipBytes(startingOffset);
            }

            int labelLength = 0;
            byte dataByte;
            while ((dataByte = dataInputStream.readByte()) != 0) {
                // Check if it's a pointer
                byte mask = (byte) 0xc0;
                // If top bits are binary 11
                if ((dataByte & mask) == mask) {
                    byte firstOctet = dataByte;
                    byte secondOctet = dataInputStream.readByte();
                    int offset = ((firstOctet << 8) + secondOctet) & 0x3FFF;
                    // Recursively call resolveName to build up domain name
                    domainName = resolveName(message, offset, domainName);
                    break;
                } else {
                    // This is a label length
                    labelLength = dataByte;
                    byte[] label = new byte[labelLength];
                    for (int j = 0; j < labelLength; j++) {
                        label[j] = dataInputStream.readByte();
                    }
                    domainName += new String(label, "US-ASCII");
                    domainName += ".";
                }
            }

            // Remove the trailing period
            if (domainName.endsWith(".")) {
                domainName = domainName.substring(0, domainName.length() - 1);
            }
        } catch (IOException e) {
            System.err.println("Failed to resolve domain name at: " + domainName + ", please try again.");
        }

        return domainName;
    }
    
    /**
     * Determine whether or not we need to create a Resource Record.
     *
     * @param type	the @RecordType. 
     * @return true if one of A, AAAA, CNAME or NS records
     */
    private static boolean shouldKeepRecord(RecordType type) {
        return type == RecordType.A || type == RecordType.AAAA ||
                type == RecordType.CNAME || type == RecordType.NS;
    }
    
    /**
     * Converts the code of a @RecordType to a short. 
     * 
     * @param type 	The record type.
     * @return the code, as a short 
     */
    private static short recordTypeToShort(RecordType type) {
        short returnType;
        switch (type) {
            case A:
                returnType = (short) 0x0001;
                break;
            case AAAA:
                returnType = (short) 0x001c;
                break;
            case NS:
                returnType = (short) 0x0002;
                break;
            case CNAME:
                returnType = (short) 0x0005;
                break;
            default:
                returnType = (short) type.getCode();
        }
        return returnType;
    }

    /**
     * Prints the information contained in this @ResourceRecord, if verbose tracing is enabled.
     * 
     * @param record		Resource record to be printed.
     * @param rtype		The @RecordType of this resource record. 
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
