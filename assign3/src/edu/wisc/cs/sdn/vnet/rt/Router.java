import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

public class Router extends Device {
    // Define constants
    private static final int RIP_PORT = 520;
    private static final String RIP_MULTICAST_IP = "224.0.0.9";
    private static final long RIP_RESPONSE_INTERVAL = 10 * 1000; // 10 seconds in milliseconds
    private static final long ROUTE_TIMEOUT = 30 * 1000; // 30 seconds in milliseconds

		/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

    // Timer for sending RIP responses
    private Timer ripResponseTimer;

    public Router(String host, DumpFile logfile) {
        super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
        this.ripResponseTimer = new Timer();
        // Start RIPv2 only if a static route table is not provided
        if (this.routeTable.isEmpty()) {
            startRIPv2();
        }
    }

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

    private void startRIPv2() {
        // Add entries to the route table for subnets directly reachable via router interfaces
        for (Iface iface : this.interfaces.values()) {
            this.routeTable.insert(iface.getIpAddress(), iface.getSubnetMask(), 0, iface);
        }
        // Send RIP requests out all router interfaces
        sendRIPRequest();
        // Schedule sending unsolicited RIP responses every 10 seconds
        this.ripResponseTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                sendUnsolicitedRIPResponse();
            }
        }, RIP_RESPONSE_INTERVAL, RIP_RESPONSE_INTERVAL);
    }

    private void sendRIPRequest() {
        // Create and send RIP request packet out all router interfaces
        RIPv2 ripRequest = new RIPv2();
        ripRequest.setCommand(RIPv2.COMMAND_REQUEST);
        ripRequest.setEntries(null); // Request for all routes
        sendRIPPacket(ripRequest, null); // null iface means send out all interfaces
    }

    private void sendUnsolicitedRIPResponse() {
        // Create and send unsolicited RIP response packet out all router interfaces
        RIPv2 ripResponse = new RIPv2();
        ripResponse.setCommand(RIPv2.COMMAND_RESPONSE);
        // Include all known routes in the response
        ripResponse.setEntries(this.routeTable.getAllRIPEntries());
        sendRIPPacket(ripResponse, null); // null iface means send out all interfaces
    }

    private void sendRIPPacket(RIPv2 ripPacket, Iface outIface) {
        Ethernet ethernet = new Ethernet();
        ethernet.setEtherType(Ethernet.TYPE_IPv4);
        ethernet.setSourceMACAddress(outIface.getMacAddress().toBytes());
        if (outIface != null) {
            ethernet.setDestinationMACAddress(arpCache.lookup(outIface.getIpAddress()).getMac().toBytes());
        } else {
            ethernet.setDestinationMACAddress("FF:FF:FF:FF:FF:FF".getBytes());
        }
        IPv4 ipv4 = new IPv4();
        ipv4.setSourceAddress(outIface.getIpAddress());
        ipv4.setDestinationAddress(RIP_MULTICAST_IP);
        ipv4.setTtl((byte) 64);
        ipv4.setProtocol(IPv4.PROTOCOL_UDP);
        UDP udp = new UDP();
        udp.setSourcePort(RIP_PORT);
        udp.setDestinationPort(RIP_PORT);
        udp.setPayload(ripPacket);
        ipv4.setPayload(udp);
        ethernet.setPayload(ipv4);
        sendPacket(ethernet, outIface);
    }

    @Override
    public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Router Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		// Check if the Ethernet frame contains an IPv4 packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return; // Drop the packet if it's not IPv4
		}

		// Extract the IPv4 packet
		IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();

		// Verify the checksum of the IPv4 packet
		if (!verifyChecksum(ipv4Packet)) {
			return; // Drop the packet if the checksum is incorrect
		}

		// Decrement the TTL of the IPv4 packet
		ipv4Packet.setTtl((byte) (ipv4Packet.getTtl() - 1));

		// Drop the packet if the TTL is 0
		if (ipv4Packet.getTtl() == 0) {
			return;
		}

		if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
			UDP udpPacket = (UDP) ipv4Packet.getPayload();
			if (udpPacket.getSourcePort() == RIP_PORT && udpPacket.getDestinationPort() == RIP_PORT) {
				RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();
				// Handle RIP packet
				handleRIPPacket(ripPacket, inIface);
				return;
			}
		}

		// Determine whether the packet is destined for one of the router's interfaces
		for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
			// Drop packet if it matches a router interface IP
			if (iface.getValue().getIpAddress() == ipv4Packet.getDestinationAddress())
				return;
		}

		// Lookup the RouteEntry
		RouteEntry routeEntry = this.routeTable.lookup(ipv4Packet.getDestinationAddress());

		// Drop the packet if no matching entry found
		if (routeEntry == null) {
			return;
		}

		// Lookup the next-hop IP address
		int nextHopIp = routeEntry.getGatewayAddress();
		if (nextHopIp == 0) {
			nextHopIp = ipv4Packet.getDestinationAddress();
		}

		// Lookup MAC address corresponding to next-hop IP address
		MACAddress nextHopMac = this.arpCache.lookup(nextHopIp).getMac();
		if (nextHopMac == null) {
			return; // Drop the packet if MAC address not found
		}

		// Update Ethernet header
		etherPacket.setDestinationMACAddress(nextHopMac.toBytes());
		etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());

		ipv4Packet.setChecksum((short)0);
		ipv4Packet.serialize();

		// Send the packet out the correct interface
		this.sendPacket(etherPacket, routeEntry.getInterface());

		System.out.println("*** -> Router Sent packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
        // Other packet handling code
    }

    private void handleRIPPacket(RIPv2 ripPacket, Iface inIface) {
        // Update route table based on received RIP packet
        for (RIPv2Entry entry : ripPacket.getEntries()) {
            // Update route table with RIP entries
            boolean updated = this.routeTable.update(entry, inIface);
            if (updated) {
                // Reset timeout for this route
                this.routeTable.resetTimeout(entry);
            }
        }
        // Send necessary RIP response packets
        if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
            // Send RIP response if request received
            sendUnsolicitedRIPResponse();
        }
    }

	private boolean verifyChecksum(IPv4 ipv4Packet) {
		int headerLength = ipv4Packet.getHeaderLength();
		byte[] headerData = ipv4Packet.serialize();
		int checksum = ipv4Packet.getChecksum();

		// Zero out the checksum field
		headerData[10] = 0;
		headerData[11] = 0;

		// Compute the checksum
		int accumulation = 0;
		for (int i = 0; i < headerLength * 2; ++i) {
			accumulation += (0xff & headerData[i * 2]) << 8 | (0xff & headerData[i * 2 + 1]);
		}

		accumulation = ((accumulation >> 16) & 0xffff) + (accumulation & 0xffff);
		if ((accumulation & 0x10000) != 0) {
			accumulation = (accumulation & 0xffff) + 1; // Add carry bit
		}
		short computedChecksum = (short) (~accumulation & 0xffff);

		// Compare computed checksum with packet's checksum
		return computedChecksum == checksum;
	}
}
