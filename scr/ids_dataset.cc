// IDS Dataset Simulation using ns-3
// This program simulates network scenarios for generating datasets 
// specifically designed for Intrusion Detection Systems (IDS). It 
// utilizes the ns-3 simulation framework (ns-3.43), incorporating various modules 
// such as Internet, Mobility, Energy, and Applications to create realistic 
// and diverse network behaviors.
//
// The simulation models normal network traffic as well as malicious activities 
// to represent real-world scenarios. The following types of attacks are included:
// - DoS (Denial of Service)
// - DDoS (Distributed Denial of Service)
// - Spoofing Attacks
// - Man-in-the-Middle (MITM)
// - and many others...
//
// Features of the simulation:
// - Integration of point-to-point and CSMA communication models
// - Implementation of mobility patterns for wireless nodes
// - Support for energy models to simulate realistic wireless communication
// - Use of UDP Echo for application-layer traffic
// - Flow monitoring for performance metrics collection
// - Compatibility with NetAnim for visualization
//
//
// This code is intended for research and educational purposes, providing a platform 
// for generating high-quality datasets to train and evaluate IDS solutions.

// Required ns-3 core modules
#include "ns3/core-module.h"          // Core functionalities, such as scheduling and logging
#include "ns3/network-module.h"       // Definitions for network devices and nodes
#include "ns3/internet-module.h"      // Internet stack implementation (TCP/IP, routing)

// Communication-related modules
#include "ns3/point-to-point-module.h" // Point-to-point communication model
#include "ns3/csma-module.h"           // CSMA (Carrier Sense Multiple Access) communication model
#include "ns3/applications-module.h"   // Applications like UDP echo server and client

// Visualization and animation modules
#include "ns3/netanim-module.h"        // For NetAnim, a network simulation animator

// Energy-related modules
#include "ns3/energy-module.h"                     // Energy models for simulating power usage
#include "ns3/lr-wpan-module.h"                   // Low-rate wireless personal area network (LR-WPAN)
#include "ns3/wifi-radio-energy-model-helper.h"   // Helper for WiFi radio energy models
#include "ns3/wifi-radio-energy-model.h"          // WiFi-specific energy model implementation

// Wireless communication and mobility
#include "ns3/yans-wifi-helper.h"      // WiFi (802.11) communication model and helper functions
#include "ns3/mobility-module.h"       // Models for node mobility
#include "ns3/wifi-module.h"           // Comprehensive WiFi simulation support
#include "ns3/ssid.h"                  // Service Set Identifier (SSID) management

// Monitoring and flow analysis
#include "ns3/flow-monitor-module.h"   // Flow monitoring tools for analyzing network traffic

// ARP (Address Resolution Protocol) and IPv4 stack
#include "ns3/arp-l3-protocol.h"       // ARP protocol for layer 3 (network layer)
#include "ns3/ipv4-l3-protocol.h"      // IPv4 protocol implementation
#include "ns3/ipv4-interface.h"        // Interface for IPv4 communication
#include "ns3/arp-cache.h"             // ARP cache for storing ARP table entries

// Packet and protocol-level headers
#include "ns3/arp-header.h"            // Header definitions for ARP
#include "ns3/ipv4-header.h"           // Header definitions for IPv4 packets
#include "ns3/ethernet-header.h"       // Ethernet header definitions
#include "ns3/packet.h"                // Packet representation in ns-3

// Node and address management
#include "ns3/ipv4.h"                  // IPv4-specific functions and protocols
#include "ns3/node.h"                  // Representation of a network node
#include "ns3/mac48-address.h"         // MAC address (48-bit) management

// Simulation management and output
#include "ns3/simulator.h"             // Core simulation engine and scheduling
#include "ns3/pcap-file-wrapper.h"     // PCAP file management for trace files

// Traffic control and routing
#include "ns3/traffic-control-module.h" // Traffic control mechanisms for network devices
#include "ns3/log.h"                    // Logging utilities for debugging
#include "ns3/olsr-helper.h"            // Helper for OLSR (Optimized Link State Routing) protocol
#include "ns3/internet-apps-module.h"   // Internet applications like Ping and Traceroute

// Standard libraries
#include <string>                       // String manipulation
#include <vector>                       // Dynamic arrays for managing data



using namespace ns3;  // Importing the ns-3 namespace for easier access to its classes and functions

NS_LOG_COMPONENT_DEFINE("NetworkSimulation"); 
// Defines a logging component with the name "NetworkSimulation" for debugging and logging purposes

// Callback functions for point-to-point devices

/**
 * Callback for when a packet is transmitted on a point-to-point device.
 * Logs the size of the packet and the time of transmission.
 *
 * @param packet A pointer to the packet being transmitted.
 */
void TxCallback(Ptr<const Packet> packet) {
    NS_LOG_UNCOND("Packet transmitted: Size = " << packet->GetSize()
                   << " bytes at " << Simulator::Now().GetSeconds() << " seconds");
}

/**
 * Callback for when a packet is received on a point-to-point device.
 * Logs the size of the packet and the time of reception.
 *
 * @param packet A pointer to the packet being received.
 */
void RxCallback(Ptr<const Packet> packet) {
    NS_LOG_UNCOND("Packet received: Size = " << packet->GetSize()
                   << " bytes at " << Simulator::Now().GetSeconds() << " seconds");
}

// Callback functions for Wi-Fi devices

/**
 * Callback for when a Wi-Fi packet is transmitted.
 * Logs the size of the packet, time of transmission, and the transmission power.
 *
 * @param packet A pointer to the packet being transmitted.
 * @param txPowerW The transmission power in watts.
 */
void WifiTxCallback(Ptr<const Packet> packet, double txPowerW) {
    NS_LOG_UNCOND("Wi-Fi Packet transmitted: Size = " << packet->GetSize()
                   << " bytes at " << Simulator::Now().GetSeconds() << " seconds"
                   << ", TxPower: " << txPowerW << " W");
}

/**
 * Callback for when a Wi-Fi packet is received.
 * Logs the size of the packet, time of reception, signal-to-noise ratio (SNR), 
 * Wi-Fi mode, and preamble type.
 *
 * @param packet A pointer to the packet being received.
 * @param snr The signal-to-noise ratio of the received packet.
 * @param mode The Wi-Fi mode of the received packet (e.g., 802.11b, 802.11n).
 * @param preamble The preamble type used in the transmission (short or long).
 */
void WifiRxCallback(Ptr<const Packet> packet, double snr, WifiMode mode, WifiPreamble preamble) {
    NS_LOG_UNCOND("Wi-Fi Packet received: Size = " << packet->GetSize()
                   << " bytes at " << Simulator::Now().GetSeconds() << " seconds"
                   << ", SNR: " << snr << ", Mode: " << mode << ", Preamble: " << preamble);
}



int main(int argc, char *argv[]) {
    // Setup Command Line Arguments
    // CommandLine is an ns-3 utility for parsing command-line arguments.
    // It allows the user to configure simulation parameters without modifying the code.
    CommandLine cmd;
    cmd.Parse(argc, argv);  // Parses the command-line arguments provided by the user.
        
    // Enable logging for specific components
    // These LogComponentEnable statements enable logging for various ns-3 components at the specified log level.
    // LOG_LEVEL_INFO ensures that informative messages are displayed during the simulation.

    LogComponentEnable("BulkSendApplication", LOG_LEVEL_INFO); 
    // Enables logging for the BulkSendApplication, which sends bulk data over a TCP connection.

    LogComponentEnable("PacketSink", LOG_LEVEL_INFO); 
    // Enables logging for the PacketSink application, which acts as a receiver for bulk data or other network traffic.

    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO); 
    // Enables logging for the UDP Echo Client application, which generates UDP packets for an echo server.

    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO); 
    // Enables logging for the UDP Echo Server application, which responds to packets sent by the echo client.

    LogComponentEnable("TcpL4Protocol", LOG_LEVEL_INFO); 
    // Enables logging for the TCP Layer 4 Protocol, providing detailed logs about TCP operations.

    LogComponentEnable("UdpL4Protocol", LOG_LEVEL_INFO); 
    // Enables logging for the UDP Layer 4 Protocol, providing insights into UDP operations.

// Node Container Declarations
// A NodeContainer is used to manage collections of nodes in ns-3 simulations.
// The following NodeContainers represent different network elements in the simulation.

NodeContainer coreRouters, distributionSwitches, accessSwitchesHR, enterpriseClients, vpnServer, remoteClients, wifiApNode, wifiStaNodes, dmzServers;
// Uncommented containers like webServer and webClient can be added if needed.

// Create nodes for each network element
coreRouters.Create(1);               // Creates 1 core router (Node 0)

distributionSwitches.Create(2);      // Creates 2 distribution switches (Nodes 1 and 2)

accessSwitchesHR.Create(1);          // Creates 1 access switch (Node 3)

// enterpriseClients.Create(3);       // (Commented out) Creates 3 enterprise client nodes (Nodes 4 to 6)
enterpriseClients.Create(10);        // Creates 10 enterprise client nodes

dmzServers.Create(5);                // Creates 5 DMZ (Demilitarized Zone) servers (Nodes 7 to 11)

vpnServer.Create(1);                 // Creates 1 VPN server (Node 12)

wifiApNode.Create(1);                // Creates 1 Wi-Fi Access Point node (Node 13)

// wifiStaNodes.Create(5);            // (Commented out) Creates 5 Wi-Fi station nodes (Nodes 14 to 18)
wifiStaNodes.Create(10);             // Creates 10 Wi-Fi station nodes

// remoteClients.Create(4);           // (Commented out) Creates 4 remote client nodes (Nodes 19 to 22)
remoteClients.Create(10);            // Creates 10 remote client nodes

// Notes:
// - Adjust the number of nodes in each category based on the simulation requirements.
// - Uncomment lines if additional nodes (e.g., webServer, webClient) are needed.
// - Node IDs are sequentially assigned as they are created.


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Combine All Nodes for Internet Installation

// Create a NodeContainer to hold all the nodes for the network.
NodeContainer allNodes;

// Add all previously created nodes to the combined NodeContainer.
// This ensures the Internet stack is installed on all relevant nodes in the simulation.
allNodes.Add(coreRouters);
allNodes.Add(distributionSwitches);
allNodes.Add(accessSwitchesHR);
allNodes.Add(enterpriseClients);
allNodes.Add(dmzServers);
allNodes.Add(vpnServer);
allNodes.Add(wifiApNode);
allNodes.Add(wifiStaNodes);
allNodes.Add(remoteClients);

// Install the Internet protocol stack on all nodes in the combined NodeContainer.
// This enables IP communication between nodes.
InternetStackHelper internet;
internet.Install(allNodes);

NS_LOG_INFO("Setting up Mobility...");
// Log an informational message indicating the start of mobility setup.

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Define Mobility Model for All Nodes

// Create a MobilityHelper to manage node mobility.
MobilityHelper mobility;

// Set a constant position mobility model for all nodes.
// "ns3::ConstantPositionMobilityModel" ensures nodes remain stationary throughout the simulation.
mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

// Apply the defined mobility model to all nodes in the network.
mobility.Install(allNodes);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Network Topology Configuration and IP Address Assignment
//
// This section configures the network topology by creating links between various network components 
// (e.g., core routers, switches, enterprise clients, servers) using Point-to-Point, CSMA, and Wi-Fi models. 
// Additionally, IP addresses are assigned to all devices for seamless communication.
//
// Key Components:
// 1. **Point-to-Point Links**:
//    - High-speed links between core routers, distribution switches, and the VPN server.
//
// 2. **CSMA Networks**:
//    - Configured for the enterprise network, DMZ servers, and inter-switch communication with appropriate 
//      data rates and delays.
//
// 3. **Wi-Fi Networks**:
//    - Configures a Wi-Fi access point (AP) and station nodes (STAs) with the 802.11a standard.
//    - Uses the `YansWifiChannel` and `MinstrelWifiManager` for channel and rate management.
//
// 4. **VPN Links**:
//    - Creates dedicated Point-to-Point links between the VPN server and remote clients.
//
// 5. **IP Address Assignment**:
//    - Assigns unique IP subnets to all links and devices for proper routing and communication.
//    - Uses a structured approach with `Ipv4AddressHelper` for dynamic and manual IP allocation.
//
// This configuration lays the foundation for data flow between different components, enabling effective 
// communication across the simulated network.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Create Point-to-Point Links
PointToPointHelper pointToPoint;
pointToPoint.SetDeviceAttribute("DataRate", StringValue("10Gbps"));
pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));


// Core Router to Distribution Switches
NetDeviceContainer p2pDevices1 = pointToPoint.Install(coreRouters.Get(0), distributionSwitches.Get(0));
NetDeviceContainer p2pDevices2 = pointToPoint.Install(coreRouters.Get(0), distributionSwitches.Get(1));

// VPN Server to Core Router
PointToPointHelper vpnLink;
vpnLink.SetDeviceAttribute("DataRate", StringValue("500Mbps"));
vpnLink.SetChannelAttribute("Delay", StringValue("20ms"));
NetDeviceContainer vpnToCore = vpnLink.Install(vpnServer.Get(0), coreRouters.Get(0));

// CSMA Helper for Enterprise Network
CsmaHelper csmaEnterprise;
csmaEnterprise.SetChannelAttribute("DataRate", StringValue("500Mbps"));
csmaEnterprise.SetChannelAttribute("Delay", StringValue("2ms"));

// Enterprise Clients and Access Switch
NodeContainer enterpriseNetworkNodes;
enterpriseNetworkNodes.Add(enterpriseClients);
enterpriseNetworkNodes.Add(accessSwitchesHR.Get(0));
NetDeviceContainer enterpriseDevices = csmaEnterprise.Install(enterpriseNetworkNodes);

// Verify number of devices installed for enterprise network
NS_LOG_INFO("Number of devices in enterpriseDevices: " << enterpriseDevices.GetN());

// Access Switch and Distribution Switch 0
NodeContainer accessToDistNodes;
accessToDistNodes.Add(accessSwitchesHR.Get(0));
accessToDistNodes.Add(distributionSwitches.Get(0));
NetDeviceContainer accessToDistDevices = csmaEnterprise.Install(accessToDistNodes);

// CSMA Helper for DMZ Network
CsmaHelper csmaDmz;
csmaDmz.SetChannelAttribute("DataRate", StringValue("1Gbps"));
csmaDmz.SetChannelAttribute("Delay", StringValue("2ms"));

// DMZ Servers and Distribution Switch 1
NodeContainer dmzNetworkNodes;
dmzNetworkNodes.Add(dmzServers);
dmzNetworkNodes.Add(distributionSwitches.Get(1));
NetDeviceContainer dmzDevices = csmaDmz.Install(dmzNetworkNodes);

// Wi-Fi AP Node and Distribution Switch 0
CsmaHelper csmaWifiAp;
csmaWifiAp.SetChannelAttribute("DataRate", StringValue("1Gbps"));
csmaWifiAp.SetChannelAttribute("Delay", StringValue("2ms"));

NodeContainer wifiApToDistNodes;
wifiApToDistNodes.Add(wifiApNode.Get(0));
wifiApToDistNodes.Add(distributionSwitches.Get(0));
NetDeviceContainer wifiApToDistDevices = csmaWifiAp.Install(wifiApToDistNodes);

// Wi-Fi Devices Setup
YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
YansWifiPhyHelper wifiPhy;
wifiPhy.SetChannel(wifiChannel.Create());

WifiHelper wifi;
wifi.SetRemoteStationManager("ns3::MinstrelWifiManager");
wifi.SetStandard(WIFI_STANDARD_80211a);

Ssid ssid = Ssid("ns-3-WiFi");

// Wi-Fi AP Device
WifiMacHelper wifiMac;
wifiMac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
NetDeviceContainer wifiApDevice = wifi.Install(wifiPhy, wifiMac, wifiApNode);

// Wi-Fi STA Devices
wifiMac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
NetDeviceContainer wifiStaDevices = wifi.Install(wifiPhy, wifiMac, wifiStaNodes);

// VPN Devices (Remote Clients and VPN Server)
std::vector<NetDeviceContainer> vpnDevices;
for (uint32_t i = 0; i < remoteClients.GetN(); ++i) {
    NetDeviceContainer vpnLinkDevices = vpnLink.Install(vpnServer.Get(0), remoteClients.Get(i));
    vpnDevices.push_back(vpnLinkDevices);
}

Ipv4AddressHelper address;

// Assign IP addresses to core router links
address.SetBase("10.1.0.0", "255.255.255.252");
address.Assign(p2pDevices1);
address.NewNetwork();

address.SetBase("10.1.0.4", "255.255.255.252");
address.Assign(p2pDevices2);
address.NewNetwork();

// Assign IP addresses to VPN link
address.SetBase("10.1.0.8", "255.255.255.252");
Ipv4InterfaceContainer vpnInterfaces = address.Assign(vpnToCore);
address.NewNetwork();

// Assign IP addresses to Enterprise Network (Enterprise Clients and Access Switch)
NS_LOG_INFO("Assigning IP addresses to Enterprise Network...");
address.SetBase("10.1.1.0", "255.255.255.0");
Ipv4InterfaceContainer enterpriseInterfaces = address.Assign(enterpriseDevices);
address.NewNetwork();

// Verify each client’s assigned IP to ensure uniqueness
for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    NS_LOG_UNCOND("Enterprise Client " << i << " IP Address: " << enterpriseInterfaces.GetAddress(i));
}

// Assign IP addresses to Access Switch and Distribution Switch 0
NS_LOG_INFO("Assigning IP addresses to Access Switch and Distribution Switch...");
address.SetBase("10.1.2.0", "255.255.255.0");
Ipv4InterfaceContainer accessToDistInterfaces = address.Assign(accessToDistDevices);
address.NewNetwork();

// Assign IP addresses to DMZ Network (DMZ Servers and Distribution Switch 1)
NS_LOG_INFO("Assigning IP addresses to DMZ Network...");
address.SetBase("10.3.1.0", "255.255.255.0");
Ipv4InterfaceContainer dmzInterfaces = address.Assign(dmzDevices);
address.NewNetwork();

// Assign IP addresses to Wi-Fi AP and Distribution Switch 0
NS_LOG_INFO("Assigning IP addresses to Wi-Fi AP and Distribution Switch...");
address.SetBase("10.1.3.0", "255.255.255.0");
Ipv4InterfaceContainer wifiApToDistInterfaces = address.Assign(wifiApToDistDevices);
address.NewNetwork();

// Assign IP addresses to Wi-Fi Devices (AP and STAs)
NS_LOG_INFO("Assigning IP addresses to Wi-Fi Devices...");
address.SetBase("10.2.1.0", "255.255.255.0");
Ipv4InterfaceContainer apInterface = address.Assign(wifiApDevice);
Ipv4InterfaceContainer staInterfaces = address.Assign(wifiStaDevices);
address.NewNetwork();

// Assign IP addresses to VPN Devices (Remote Clients and VPN Server)
NS_LOG_INFO("Assigning IP addresses to VPN Devices...");
for (uint32_t i = 0; i < vpnDevices.size(); ++i) {
    std::ostringstream subnet;
    subnet << "10.1.0." << (i * 4 + 20);  // Start from 10.1.0.20, increment by 4 for each /30 subnet
    address.SetBase(subnet.str().c_str(), "255.255.255.252");
    address.Assign(vpnDevices[i]);
    address.NewNetwork();
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Initialize NetAnim for visualization
AnimationInterface anim("network-visualization.xml");

// Set Positions for Nodes (including labels and colors)
anim.SetConstantPosition(coreRouters.Get(0), 50.0, 50.0);
anim.UpdateNodeDescription(coreRouters.Get(0), "Core Router");
anim.UpdateNodeColor(coreRouters.Get(0), 255, 0, 0);

// Position and label Distribution Switches
anim.SetConstantPosition(distributionSwitches.Get(0), 30.0, 30.0);
anim.UpdateNodeDescription(distributionSwitches.Get(0), "Dist Switch 0");
anim.SetConstantPosition(distributionSwitches.Get(1), 70.0, 30.0);
anim.UpdateNodeDescription(distributionSwitches.Get(1), "Dist Switch 1");

// Enterprise Clients with labeling
for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    anim.SetConstantPosition(enterpriseClients.Get(i), 20.0 + i * 10.0, 20.0);
    anim.UpdateNodeDescription(enterpriseClients.Get(i), "Enterprise Client " + std::to_string(i));
}

// Position for Wi-Fi STA Nodes (spread horizontally below enterprise clients)
for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    anim.SetConstantPosition(wifiStaNodes.Get(i), 20.0 + i * 10.0, 10.0); // Adjusted X positions for each STA node
    anim.UpdateNodeDescription(wifiStaNodes.Get(i), "Wi-Fi STA " + std::to_string(i));
    anim.UpdateNodeColor(wifiStaNodes.Get(i), 0, 0, 255); // Color Wi-Fi STAs blue
}

// Position for Remote Clients (spread horizontally, positioned below the VPN server)
for (uint32_t i = 0; i < remoteClients.GetN(); ++i) {
    anim.SetConstantPosition(remoteClients.Get(i), 60.0 + i * 10.0, 90.0); // Adjust X positions for each remote client
    anim.UpdateNodeDescription(remoteClients.Get(i), "Remote Client " + std::to_string(i));
    anim.UpdateNodeColor(remoteClients.Get(i), 0, 255, 0); // Color Remote Clients green
}

// Enable packet metadata for all nodes for a detailed view of traffic
anim.EnablePacketMetadata(true);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Server Setup in the DMZ
//
// This section configures various servers in the DMZ (Demilitarized Zone) of the network to simulate real-world 
// services. Each server is installed on designated DMZ nodes, using appropriate ports and protocols, with 
// specific start and stop times for their applications.
//
// Configured Servers:
// 1. **Web Server**:
//    - Hosts HTTP (port 80) and HTTPS (port 443) services on DMZ Server 0.
//
// 2. **Email Server**:
//    - Provides SMTP (port 25), IMAP (port 143), and POP3 (port 110) services on DMZ Server 1.
//
// 3. **DNS Server**:
//    - Simulates a DNS server (port 53) on DMZ Server 2. Uses `UdpEchoServerHelper` as a placeholder.
//
// 4. **FTP and SSH Servers**:
//    - FTP (port 21) and SSH (port 22) services are hosted on DMZ Server 3.
//
// 5. **UDP Echo Server**:
//    - A basic UDP echo server (port 9) is installed on DMZ Server 4.
//
// 6. **Streaming Server**:
//    - Configures an RTSP streaming server (port 554) on DMZ Server 0.
//
// Key Details:
// - Applications start at `appStartTime` (1.0 seconds) and stop at `appStopTime` (1500.0 seconds).
// - Each server listens on its designated port for incoming connections.
// - IP addresses are dynamically assigned to servers from the DMZ subnet for seamless communication.
//
// This setup emulates common server functionalities in a secure DMZ environment, enabling realistic traffic 
// generation for network simulations.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

double appStartTime = 1.0;
double appStopTime = 1500.0;

NS_LOG_INFO("Setting up Web Server in DMZ...");

uint16_t httpPort = 80; // HTTP port
uint16_t httpsPort = 443; // HTTPS port

// HTTP Server Setup
Address httpServerAddress(InetSocketAddress(Ipv4Address::GetAny(), httpPort));
PacketSinkHelper httpServerHelper("ns3::TcpSocketFactory", httpServerAddress);
ApplicationContainer httpServerApp = httpServerHelper.Install(dmzServers.Get(0));
httpServerApp.Start(Seconds(appStartTime));
httpServerApp.Stop(Seconds(appStopTime));

// HTTPS Server Setup
Address httpsServerAddress(InetSocketAddress(Ipv4Address::GetAny(), httpsPort));
PacketSinkHelper httpsServerHelper("ns3::TcpSocketFactory", httpsServerAddress);
ApplicationContainer httpsServerApp = httpsServerHelper.Install(dmzServers.Get(0));
httpsServerApp.Start(Seconds(appStartTime));  // Starting HTTPS slightly later for staggering
httpsServerApp.Stop(Seconds(appStopTime));

Ipv4Address webServerIp = dmzInterfaces.GetAddress(0);

// Proceed with setting up other servers as per your existing code

NS_LOG_INFO("Setting up Email Server in DMZ...");

// Ports for SMTP, IMAP, and POP3
constexpr uint16_t smtpPort = 25;
constexpr uint16_t imapPort = 143;
constexpr uint16_t pop3Port = 110;

// SMTP Server Setup
Address smtpServerAddress(InetSocketAddress(Ipv4Address::GetAny(), smtpPort));
PacketSinkHelper smtpServerHelper("ns3::TcpSocketFactory", smtpServerAddress);
ApplicationContainer smtpServerApp = smtpServerHelper.Install(dmzServers.Get(1));
smtpServerApp.Start(Seconds(appStartTime));
smtpServerApp.Stop(Seconds(appStopTime));

// IMAP Server Setup
Address imapServerAddress(InetSocketAddress(Ipv4Address::GetAny(), imapPort));
PacketSinkHelper imapServerHelper("ns3::TcpSocketFactory", imapServerAddress);
ApplicationContainer imapServerApp = imapServerHelper.Install(dmzServers.Get(1));
imapServerApp.Start(Seconds(appStartTime));
imapServerApp.Stop(Seconds(appStopTime));

// POP3 Server Setup
Address pop3ServerAddress(InetSocketAddress(Ipv4Address::GetAny(), pop3Port));
PacketSinkHelper pop3ServerHelper("ns3::TcpSocketFactory", pop3ServerAddress);
ApplicationContainer pop3ServerApp = pop3ServerHelper.Install(dmzServers.Get(1));
pop3ServerApp.Start(Seconds(appStartTime));
pop3ServerApp.Stop(Seconds(appStopTime));

Ipv4Address emailServerIp = dmzInterfaces.GetAddress(1);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

NS_LOG_INFO("Setting up DNS Server in DMZ...");

// DNS Server on DMZ Server 2
uint16_t dnsPort = 53; // DNS port
// Note: UdpEchoServer is not a true DNS server; consider using a custom DNS application if needed
UdpEchoServerHelper dnsServerHelper(dnsPort);
ApplicationContainer dnsServerApp = dnsServerHelper.Install(dmzServers.Get(2));
dnsServerApp.Start(Seconds(appStartTime));
dnsServerApp.Stop(Seconds(appStopTime));

Ipv4Address dnsServerIp = dmzInterfaces.GetAddress(2);

NS_LOG_INFO("Setting up FTP and SSH Servers in DMZ...");

// FTP Server on DMZ Server 3
uint16_t ftpPort = 21; // FTP control port
Address ftpServerAddress(InetSocketAddress(Ipv4Address::GetAny(), ftpPort));
PacketSinkHelper ftpServerHelper("ns3::TcpSocketFactory", ftpServerAddress);
ApplicationContainer ftpServerApp = ftpServerHelper.Install(dmzServers.Get(3));
ftpServerApp.Start(Seconds(appStartTime));
ftpServerApp.Stop(Seconds(appStopTime));

Ipv4Address ftpServerIp = dmzInterfaces.GetAddress(3);

// SSH Server on DMZ Server 3
uint16_t sshPort = 22; // SSH port
Address sshServerAddress(InetSocketAddress(Ipv4Address::GetAny(), sshPort));
PacketSinkHelper sshServerHelper("ns3::TcpSocketFactory", sshServerAddress);
ApplicationContainer sshServerApp = sshServerHelper.Install(dmzServers.Get(3));
sshServerApp.Start(Seconds(appStartTime));
sshServerApp.Stop(Seconds(appStopTime));

NS_LOG_INFO("Setting up UDP Echo Server in DMZ...");

// UDP Echo Server on DMZ Server 4
uint16_t echoPort = 9; // UDP Echo port
UdpEchoServerHelper echoServerHelper(echoPort);
ApplicationContainer echoServerApp = echoServerHelper.Install(dmzServers.Get(4));
echoServerApp.Start(Seconds(appStartTime));
echoServerApp.Stop(Seconds(appStopTime));

Ipv4Address echoServerIp = dmzInterfaces.GetAddress(4);


// Streaming Server on DMZ
uint16_t streamPort = 554;  // Typical RTSP port
PacketSinkHelper streamServer("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), streamPort));
ApplicationContainer streamServerApp = streamServer.Install(dmzServers.Get(0));  // Could use the main DMZ server
streamServerApp.Start(Seconds(appStartTime));
streamServerApp.Stop(Seconds(appStopTime));

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Application Installation on All (Enterprize, Wi-fi, Remote Clients) Clients
//
// This section sets up various realistic client applications on the enterprise client nodes. 
// These applications mimic real-world traffic patterns, including HTTP, HTTPS, email, DNS, FTP, 
// SSH, UDP Echo, and streaming services. Each client is configured with variable parameters to 
// emulate diverse usage scenarios, adding realism to the network simulation.
//
// Applications Configured:
// 1. **HTTP and HTTPS Clients**:
//    - Enterprise clients interact with a web server using HTTP (port 80) and HTTPS (port 443).
//    - Configured with staggered start times, variable payload sizes, and realistic inter-request delays.
//
// 2. **Email Clients**:
//    - Enterprise clients send/receive emails using SMTP (port 25), IMAP (port 143), and POP3 (port 110).
//    - Realistic variability in email sizes and inter-email intervals is incorporated.
//
// 3. **DNS Clients**:
//    - Clients send DNS queries to the DNS server (port 53).
//    - Configured with randomized packet sizes and intervals to mimic real browsing behavior.
//
// 4. **FTP Clients**:
//    - Clients simulate FTP file transfers to/from an FTP server (port 21).
//    - Realistic file sizes (1 MB to 10 MB) and staggered transfers are set up for each client.
//
// 5. **SSH Clients**:
//    - Clients establish SSH sessions to the SSH server (port 22).
//    - Variability in session size and idle time between commands simulates realistic SSH behavior.
//
// 6. **UDP Echo Clients**:
//    - Clients communicate with the UDP Echo server (port 9) with variable packet sizes and intervals.
//    - This simulates basic UDP-based communication traffic.
//
// 7. **Streaming Clients**:
//    - Clients stream video from a server (RTSP on port 554) with randomized packet sizes, data rates, 
//      and on/off times to emulate video streaming patterns.
//
// Key Details:
// - Randomized start times, payload sizes, and intervals ensure realistic traffic patterns.
// - Staggered application start times prevent simultaneous traffic bursts.
// - Applications stop at the predefined `appStopTime` to maintain consistency across the simulation.
//
// This configuration creates a rich and diverse traffic environment, suitable for testing and evaluating 
// network performance under realistic enterprise usage scenarios.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
NS_LOG_INFO("Installing Applications on Enterprise Clients...");

Ptr<UniformRandomVariable> randPayloadSize = CreateObject<UniformRandomVariable>();
randPayloadSize->SetAttribute("Min", DoubleValue(512));       // Min payload size (bytes)
randPayloadSize->SetAttribute("Max", DoubleValue(10 * 1024)); // Max payload size (10 KB)

Ptr<ExponentialRandomVariable> randInterRequestTime = CreateObject<ExponentialRandomVariable>();
randInterRequestTime->SetAttribute("Mean", DoubleValue(0.5)); // Average inter-request interval (seconds)

for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> clientNode = enterpriseClients.Get(i);

    // Realistic HTTP Client Setup
    OnOffHelper httpClientHelper("ns3::TcpSocketFactory", InetSocketAddress(webServerIp, httpPort));
    httpClientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.2]"));
    httpClientHelper.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=1.5]")); // Random delays between requests
    httpClientHelper.SetAttribute("DataRate", StringValue("1Mbps"));  // Data rate for HTTP requests
    httpClientHelper.SetAttribute("PacketSize", UintegerValue(randPayloadSize->GetValue()));

    ApplicationContainer httpClientApp = httpClientHelper.Install(clientNode);
    httpClientApp.Start(Seconds(5.0 + i + randInterRequestTime->GetValue())); // Staggered start times
    httpClientApp.Stop(Seconds(appStopTime));

    // Realistic HTTPS Client Setup
    OnOffHelper httpsClientHelper("ns3::TcpSocketFactory", InetSocketAddress(webServerIp, httpsPort));
    httpsClientHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.3]"));
    httpsClientHelper.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=2.0]"));
    httpsClientHelper.SetAttribute("DataRate", StringValue("500Kbps")); // Slower rate for HTTPS
    httpsClientHelper.SetAttribute("PacketSize", UintegerValue(randPayloadSize->GetValue()));

    ApplicationContainer httpsClientApp = httpsClientHelper.Install(clientNode);
    httpsClientApp.Start(Seconds(6.0 + i + randInterRequestTime->GetValue()));
    httpsClientApp.Stop(Seconds(appStopTime));
}

    
    
    // Email Client Protocol Selection and Realistic Setup
NS_LOG_INFO("Setting up Realistic Email Applications on Enterprise Clients...");

Ptr<UniformRandomVariable> randProtocol = CreateObject<UniformRandomVariable>();
randProtocol->SetAttribute("Min", DoubleValue(0.0));
randProtocol->SetAttribute("Max", DoubleValue(2.0));

Ptr<UniformRandomVariable> emailSizeRand = CreateObject<UniformRandomVariable>();
emailSizeRand->SetAttribute("Min", DoubleValue(50 * 1024));  // Minimum 50 KB
emailSizeRand->SetAttribute("Max", DoubleValue(150 * 1024)); // Maximum 150 KB

Ptr<ExponentialRandomVariable> emailIntervalRand = CreateObject<ExponentialRandomVariable>();
emailIntervalRand->SetAttribute("Mean", DoubleValue(30.0));  // Average time between emails (in seconds)

for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> clientNode = enterpriseClients.Get(i);

    int protocolChoice = randProtocol->GetInteger();  // Integer selection for protocol
    Address emailDestAddress;
    uint16_t emailPort;
    std::string protocolName;

    if (protocolChoice == 0) {
        // SMTP (Outgoing Email)
        emailDestAddress = InetSocketAddress(emailServerIp, smtpPort);
        emailPort = smtpPort;
        protocolName = "SMTP";
    } else if (protocolChoice == 1) {
        // IMAP (Incoming, typically for downloading large emails)
        emailDestAddress = InetSocketAddress(emailServerIp, imapPort);
        emailPort = imapPort;
        protocolName = "IMAP";
    } else {
        // POP3 (Incoming, often for downloading smaller batches)
        emailDestAddress = InetSocketAddress(emailServerIp, pop3Port);
        emailPort = pop3Port;
        protocolName = "POP3";
    }

    NS_LOG_INFO("Client " << clientNode->GetId() << " is using " << protocolName);

    // Configure BulkSendHelper for email client with variable sizes and realistic timing
    for (uint32_t j = 0; j < 10; ++j) {  // Assume each client sends/receives multiple emails
        BulkSendHelper emailClientHelper("ns3::TcpSocketFactory", emailDestAddress);

        // Vary email size within 50 KB to 150 KB
        emailClientHelper.SetAttribute("MaxBytes", UintegerValue(emailSizeRand->GetValue()));

        ApplicationContainer emailClientApp = emailClientHelper.Install(clientNode);
        emailClientApp.Start(Seconds(10.0 + i * 2 + emailIntervalRand->GetValue()));  // Staggered start times
        emailClientApp.Stop(Seconds(appStopTime));  // Ensure active for the entire simulation
    }
}



// DNS Client Application with Realistic Traffic Patterns
NS_LOG_INFO("Setting up Realistic DNS Applications on Enterprise Clients...");

Ptr<ExponentialRandomVariable> dnsIntervalRand = CreateObject<ExponentialRandomVariable>();
dnsIntervalRand->SetAttribute("Mean", DoubleValue(0.5)); // Average interval of 0.5 seconds between requests

Ptr<UniformRandomVariable> dnsPacketSizeRand = CreateObject<UniformRandomVariable>();
dnsPacketSizeRand->SetAttribute("Min", DoubleValue(64));   // Minimum packet size (typical small DNS request)
dnsPacketSizeRand->SetAttribute("Max", DoubleValue(512));  // Maximum packet size (DNS response)

for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> clientNode = enterpriseClients.Get(i);

    // Set a variable number of DNS requests to mimic realistic browsing patterns
    uint32_t dnsRequestCount = 20 + i * 5; // Each client may make multiple DNS requests

    for (uint32_t j = 0; j < dnsRequestCount; ++j) {
        UdpEchoClientHelper dnsClientHelper(dnsServerIp, dnsPort);

        // Randomize packet size to simulate variable DNS request/response sizes
        dnsClientHelper.SetAttribute("PacketSize", UintegerValue(dnsPacketSizeRand->GetValue()));

        // Adjust interval between packets to simulate realistic query patterns
        dnsClientHelper.SetAttribute("MaxPackets", UintegerValue(1));
        dnsClientHelper.SetAttribute("Interval", TimeValue(Seconds(dnsIntervalRand->GetValue())));

        ApplicationContainer dnsClientApp = dnsClientHelper.Install(clientNode);
        dnsClientApp.Start(Seconds(15.0 + i * 0.5 + j * 0.1));  // Staggered starts for each client and request
        dnsClientApp.Stop(Seconds(appStopTime));                 // Active for the entire simulation
    }
}


// Realistic FTP Client Application
NS_LOG_INFO("Setting up Realistic FTP Applications on Enterprise Clients...");

Ptr<UniformRandomVariable> ftpFileSizeRand = CreateObject<UniformRandomVariable>();
ftpFileSizeRand->SetAttribute("Min", DoubleValue(1 * 1024 * 1024));    // Minimum file size: 1 MB
ftpFileSizeRand->SetAttribute("Max", DoubleValue(10 * 1024 * 1024));   // Maximum file size: 10 MB

Ptr<ExponentialRandomVariable> ftpTransferIntervalRand = CreateObject<ExponentialRandomVariable>();
ftpTransferIntervalRand->SetAttribute("Mean", DoubleValue(1.0)); // Average interval between file transfers of 1 second

for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> clientNode = enterpriseClients.Get(i);

    // Define the number of FTP transfers per client to mimic real FTP usage patterns
    uint32_t ftpTransferCount = 3 + i % 3; // Each client has between 3-5 transfers

    for (uint32_t j = 0; j < ftpTransferCount; ++j) {
        BulkSendHelper ftpClientHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, ftpPort));

        // Set the file size to transfer, simulating a real FTP session with varied file sizes
        uint32_t fileSize = ftpFileSizeRand->GetValue();
        ftpClientHelper.SetAttribute("MaxBytes", UintegerValue(fileSize));

        // Create and configure the FTP application for each transfer
        ApplicationContainer ftpClientApp = ftpClientHelper.Install(clientNode);

        // Stagger start time for each transfer, incorporating some idle time between transfers
        double transferStartTime = 20.0 + i * 0.5 + j * ftpTransferIntervalRand->GetValue();
        ftpClientApp.Start(Seconds(transferStartTime));
        ftpClientApp.Stop(Seconds(appStopTime));
    }
}


// Realistic SSH Client Application
NS_LOG_INFO("Setting up Realistic SSH Applications on Enterprise Clients...");

Ptr<ExponentialRandomVariable> sshSessionSizeRand = CreateObject<ExponentialRandomVariable>();
sshSessionSizeRand->SetAttribute("Mean", DoubleValue(500 * 1024)); // Mean session size around 500 KB, with variability

Ptr<ExponentialRandomVariable> sshIntervalRand = CreateObject<ExponentialRandomVariable>();
sshIntervalRand->SetAttribute("Mean", DoubleValue(0.2)); // Average interval between commands (0.2 seconds)

Ptr<UniformRandomVariable> sshIdleTimeRand = CreateObject<UniformRandomVariable>();
sshIdleTimeRand->SetAttribute("Min", DoubleValue(1.0)); // Minimum idle time (1 second)
sshIdleTimeRand->SetAttribute("Max", DoubleValue(5.0)); // Maximum idle time (5 seconds)

for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> clientNode = enterpriseClients.Get(i);

    // Define number of SSH sessions per client to simulate multiple interactions
    uint32_t sshSessionCount = 2 + i % 3; // Each client has between 2-4 sessions

    for (uint32_t j = 0; j < sshSessionCount; ++j) {
        BulkSendHelper sshClientHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, sshPort));

        // Set session size with some variability to simulate realistic data exchange per session
        uint32_t sessionSize = sshSessionSizeRand->GetValue();
        sshClientHelper.SetAttribute("MaxBytes", UintegerValue(sessionSize));

        // Create and configure the SSH application for each session
        ApplicationContainer sshClientApp = sshClientHelper.Install(clientNode);

        // Stagger start time for each session, with idle times to mimic realistic usage
        double sessionStartTime = 25.0 + i * 0.5 + j * sshIdleTimeRand->GetValue();
        sshClientApp.Start(Seconds(sessionStartTime));
        sshClientApp.Stop(Seconds(appStopTime));
    }
}

// Realistic UDP Echo Client Application
NS_LOG_INFO("Setting up Realistic UDP Echo Client on Enterprise Client...");

// Set up variables for realistic traffic behavior
Ptr<UniformRandomVariable> packetSizeRand = CreateObject<UniformRandomVariable>();
packetSizeRand->SetAttribute("Min", DoubleValue(128));   // Minimum packet size (128 bytes)
packetSizeRand->SetAttribute("Max", DoubleValue(1500));  // Maximum packet size (1500 bytes, typical MTU size)

Ptr<ExponentialRandomVariable> intervalRand = CreateObject<ExponentialRandomVariable>();
intervalRand->SetAttribute("Mean", DoubleValue(0.1));    // Average interval around 0.1 seconds for variability

Ptr<UniformRandomVariable> maxPacketsRand = CreateObject<UniformRandomVariable>();
maxPacketsRand->SetAttribute("Min", DoubleValue(10));
maxPacketsRand->SetAttribute("Max", DoubleValue(50));    // Randomize total packets sent per session

for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> clientNode = enterpriseClients.Get(i);

    UdpEchoClientHelper echoClient(echoServerIp, echoPort);

    // Apply realistic, variable attributes
    uint32_t packetSize = packetSizeRand->GetInteger();             // Random packet size between 128-1500 bytes
    double interval = intervalRand->GetValue();                     // Random interval between packets
    uint32_t maxPackets = maxPacketsRand->GetInteger();             // Random number of packets to send

    echoClient.SetAttribute("MaxPackets", UintegerValue(maxPackets));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(interval)));
    echoClient.SetAttribute("PacketSize", UintegerValue(packetSize));

    // Install and start the UDP echo application
    ApplicationContainer echoClientApp = echoClient.Install(clientNode);
    echoClientApp.Start(Seconds(12.0 + i * 0.5)); // Stagger start times slightly
    echoClientApp.Stop(Seconds(appStopTime));
}

   
// Realistic Streaming Client on Enterprise Client
NS_LOG_INFO("Setting up Realistic Streaming Client on Enterprise Client...");

// Configure variability in streaming behavior
Ptr<UniformRandomVariable> streamPacketSizeRand = CreateObject<UniformRandomVariable>();
streamPacketSizeRand->SetAttribute("Min", DoubleValue(512));   // Minimum packet size (512 bytes)
streamPacketSizeRand->SetAttribute("Max", DoubleValue(1500));  // Maximum packet size (1500 bytes)

Ptr<ExponentialRandomVariable> streamOnTimeRand = CreateObject<ExponentialRandomVariable>();
streamOnTimeRand->SetAttribute("Mean", DoubleValue(2.0));      // Average "on" time around 2 seconds

Ptr<ExponentialRandomVariable> streamOffTimeRand = CreateObject<ExponentialRandomVariable>();
streamOffTimeRand->SetAttribute("Mean", DoubleValue(0.5));     // Average "off" time around 0.5 seconds

Ptr<UniformRandomVariable> streamDataRateRand = CreateObject<UniformRandomVariable>();
streamDataRateRand->SetAttribute("Min", DoubleValue(1.5));     // Minimum data rate (1.5 Mbps for low-resolution streams)
streamDataRateRand->SetAttribute("Max", DoubleValue(8.0));     // Maximum data rate (8 Mbps for high-resolution streams)

for (uint32_t i = 0; i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> clientNode = enterpriseClients.Get(i);

    // Configure the OnOff application for streaming behavior
    OnOffHelper streamClient("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address("10.3.1.1"), streamPort));

    uint32_t packetSize = streamPacketSizeRand->GetInteger();          // Variable packet size
    double dataRate = streamDataRateRand->GetValue();                  // Variable data rate
    double onTime = streamOnTimeRand->GetValue();                      // Variable "on" time
    double offTime = streamOffTimeRand->GetValue();                    // Variable "off" time

    streamClient.SetAttribute("PacketSize", UintegerValue(packetSize));
    streamClient.SetAttribute("DataRate", DataRateValue(DataRate(dataRate * 1e6)));  // Convert Mbps to bps
    streamClient.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=" + std::to_string(onTime) + "]"));
    streamClient.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=" + std::to_string(offTime) + "]"));

    ApplicationContainer streamClientApp = streamClient.Install(clientNode);
    streamClientApp.Start(Seconds(100.0 + i * 0.5)); // Slight stagger in start times
    streamClientApp.Stop(Seconds(appStopTime));
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// HTTP/HTTPS Application for Wi-Fi Clients
NS_LOG_INFO("Installing HTTP/HTTPS Applications on Wi-Fi Clients with Wi-Fi specific patterns...");

for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> clientNode = wifiStaNodes.Get(i);

    // Revised HTTP Client Setup
    BulkSendHelper httpClientHelper("ns3::TcpSocketFactory", InetSocketAddress(webServerIp, httpPort));
    Ptr<UniformRandomVariable> httpPacketSize = CreateObject<UniformRandomVariable>();
    httpPacketSize->SetAttribute("Min", DoubleValue(512));    // Smaller min packet size
    httpPacketSize->SetAttribute("Max", DoubleValue(1500));   // Larger max packet size for variability

    uint32_t httpMaxBytes = httpPacketSize->GetInteger();
    httpClientHelper.SetAttribute("MaxBytes", UintegerValue(httpMaxBytes));
    ApplicationContainer httpClientApp = httpClientHelper.Install(clientNode);
    httpClientApp.Start(Seconds(6.0 + i * 0.75)); // More staggered start times
    httpClientApp.Stop(Seconds(appStopTime));

    // Revised HTTPS Client Setup
    BulkSendHelper httpsClientHelper("ns3::TcpSocketFactory", InetSocketAddress(webServerIp, httpsPort));
    Ptr<UniformRandomVariable> httpsPacketSize = CreateObject<UniformRandomVariable>();
    httpsPacketSize->SetAttribute("Min", DoubleValue(512));
    httpsPacketSize->SetAttribute("Max", DoubleValue(2000));   // Extended max for HTTPS

    uint32_t httpsMaxBytes = httpsPacketSize->GetInteger();
    httpsClientHelper.SetAttribute("MaxBytes", UintegerValue(httpsMaxBytes));
    ApplicationContainer httpsClientApp = httpsClientHelper.Install(clientNode);
    httpsClientApp.Start(Seconds(6.5 + i * 0.75)); // Similar staggered start
    httpsClientApp.Stop(Seconds(appStopTime));
}
// Email Application for Wi-Fi Clients
NS_LOG_INFO("Installing Email Applications on Wi-Fi Clients with Wi-Fi specific characteristics...");

Ptr<UniformRandomVariable> emailProtocolRand = CreateObject<UniformRandomVariable>();
emailProtocolRand->SetAttribute("Min", DoubleValue(0.0));
emailProtocolRand->SetAttribute("Max", DoubleValue(2.0));

for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> clientNode = wifiStaNodes.Get(i);

    int protocolChoice = emailProtocolRand->GetInteger();
    Address emailDestAddress;
    uint16_t emailPort;

    if (protocolChoice == 0) {
        emailDestAddress = InetSocketAddress(emailServerIp, smtpPort);
        emailPort = smtpPort;
        NS_LOG_INFO("Wi-Fi Client " << clientNode->GetId() << " is using SMTP");
    } else if (protocolChoice == 1) {
        emailDestAddress = InetSocketAddress(emailServerIp, imapPort);
        emailPort = imapPort;
        NS_LOG_INFO("Wi-Fi Client " << clientNode->GetId() << " is using IMAP");
    } else {
        emailDestAddress = InetSocketAddress(emailServerIp, pop3Port);
        emailPort = pop3Port;
        NS_LOG_INFO("Wi-Fi Client " << clientNode->GetId() << " is using POP3");
    }

    BulkSendHelper emailClientHelper("ns3::TcpSocketFactory", emailDestAddress);
    Ptr<UniformRandomVariable> emailSizeRand = CreateObject<UniformRandomVariable>();
    emailSizeRand->SetAttribute("Min", DoubleValue(30 * 1024));   // Smaller email sizes
    emailSizeRand->SetAttribute("Max", DoubleValue(80 * 1024));   // Email sizes vary between 30-80 KB

    uint32_t emailSize = emailSizeRand->GetInteger();
    emailClientHelper.SetAttribute("MaxBytes", UintegerValue(emailSize));
    ApplicationContainer emailClientApp = emailClientHelper.Install(clientNode);
    emailClientApp.Start(Seconds(10.0 + i * 0.5));  // Slightly different stagger
    emailClientApp.Stop(Seconds(appStopTime));
}
// DNS Application for Wi-Fi Clients
NS_LOG_INFO("Setting up DNS Client on Wi-Fi Clients...");

for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> clientNode = wifiStaNodes.Get(i);
    UdpEchoClientHelper dnsClientHelper(dnsServerIp, dnsPort);
    Ptr<UniformRandomVariable> packetSizeRand = CreateObject<UniformRandomVariable>();
    packetSizeRand->SetAttribute("Min", DoubleValue(50));
    packetSizeRand->SetAttribute("Max", DoubleValue(256));

    uint32_t packetSize = packetSizeRand->GetInteger();
    dnsClientHelper.SetAttribute("MaxPackets", UintegerValue(10));  // Increased packet count
    dnsClientHelper.SetAttribute("Interval", TimeValue(Seconds(0.5)));  // Faster interval
    dnsClientHelper.SetAttribute("PacketSize", UintegerValue(packetSize));

    ApplicationContainer dnsClientApp = dnsClientHelper.Install(clientNode);
    dnsClientApp.Start(Seconds(15.0 + i * 0.2));
    dnsClientApp.Stop(Seconds(appStopTime));
}
// Streaming Application for Wi-Fi Clients
NS_LOG_INFO("Setting up Realistic Streaming Client on Wi-Fi Clients...");

Ptr<UniformRandomVariable> streamPacketSizeRandWiFi = CreateObject<UniformRandomVariable>();
streamPacketSizeRandWiFi->SetAttribute("Min", DoubleValue(400)); // Smaller packet sizes for lower quality
streamPacketSizeRandWiFi->SetAttribute("Max", DoubleValue(1200));

Ptr<ExponentialRandomVariable> streamOnTimeRandWiFi = CreateObject<ExponentialRandomVariable>();
streamOnTimeRandWiFi->SetAttribute("Mean", DoubleValue(1.5));

Ptr<ExponentialRandomVariable> streamOffTimeRandWiFi = CreateObject<ExponentialRandomVariable>();
streamOffTimeRandWiFi->SetAttribute("Mean", DoubleValue(0.7));

Ptr<UniformRandomVariable> streamDataRateRandWiFi = CreateObject<UniformRandomVariable>();
streamDataRateRandWiFi->SetAttribute("Min", DoubleValue(1.0));
streamDataRateRandWiFi->SetAttribute("Max", DoubleValue(4.0));

for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> clientNode = wifiStaNodes.Get(i);

    OnOffHelper streamClientWiFi("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address("10.3.1.1"), streamPort));
    uint32_t packetSize = streamPacketSizeRandWiFi->GetInteger();
    double dataRate = streamDataRateRandWiFi->GetValue();
    double onTime = streamOnTimeRandWiFi->GetValue();
    double offTime = streamOffTimeRandWiFi->GetValue();

    streamClientWiFi.SetAttribute("PacketSize", UintegerValue(packetSize));
    streamClientWiFi.SetAttribute("DataRate", DataRateValue(DataRate(dataRate * 1e6)));
    streamClientWiFi.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=" + std::to_string(onTime) + "]"));
    streamClientWiFi.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=" + std::to_string(offTime) + "]"));

    ApplicationContainer streamClientAppWiFi = streamClientWiFi.Install(clientNode);
    streamClientAppWiFi.Start(Seconds(100.0 + i * 0.3));  // Different staggered start for Wi-Fi
    streamClientAppWiFi.Stop(Seconds(appStopTime));
}
// FTP Application for Wi-Fi Clients
NS_LOG_INFO("Installing FTP Application on Wi-Fi Clients with realistic traffic patterns...");

for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> clientNode = wifiStaNodes.Get(i);

    // FTP Client Setup with smaller, realistic transfer sizes
    BulkSendHelper ftpClientHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, ftpPort));
    Ptr<UniformRandomVariable> ftpFileSizeRand = CreateObject<UniformRandomVariable>();
    ftpFileSizeRand->SetAttribute("Min", DoubleValue(500 * 1024));    // Min 500 KB
    ftpFileSizeRand->SetAttribute("Max", DoubleValue(2 * 1024 * 1024)); // Max 2 MB

    uint32_t fileSize = ftpFileSizeRand->GetInteger();
    ftpClientHelper.SetAttribute("MaxBytes", UintegerValue(fileSize));
    ApplicationContainer ftpClientApp = ftpClientHelper.Install(clientNode);
    ftpClientApp.Start(Seconds(20.0 + i * 1.0));  // Staggered starts
    ftpClientApp.Stop(Seconds(appStopTime));
}
// SSH Application for Wi-Fi Clients
NS_LOG_INFO("Installing SSH Application on Wi-Fi Clients with realistic traffic characteristics...");

for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> clientNode = wifiStaNodes.Get(i);

    // SSH Client Setup with variable session sizes
    BulkSendHelper sshClientHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, sshPort));
    Ptr<UniformRandomVariable> sshSessionSizeRand = CreateObject<UniformRandomVariable>();
    sshSessionSizeRand->SetAttribute("Min", DoubleValue(100 * 1024));  // Min 100 KB session
    sshSessionSizeRand->SetAttribute("Max", DoubleValue(700 * 1024));  // Max 700 KB session

    uint32_t sessionSize = sshSessionSizeRand->GetInteger();
    sshClientHelper.SetAttribute("MaxBytes", UintegerValue(sessionSize));
    ApplicationContainer sshClientApp = sshClientHelper.Install(clientNode);
    sshClientApp.Start(Seconds(25.0 + i * 1.2));  // Different staggered start for Wi-Fi clients
    sshClientApp.Stop(Seconds(appStopTime));
}
// UDP Echo Application for Wi-Fi Clients
NS_LOG_INFO("Setting up UDP Echo Client on Wi-Fi Clients with realistic traffic patterns...");

for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> clientNode = wifiStaNodes.Get(i);

    UdpEchoClientHelper echoClientHelper(echoServerIp, echoPort);
    Ptr<UniformRandomVariable> echoPacketSizeRand = CreateObject<UniformRandomVariable>();
    echoPacketSizeRand->SetAttribute("Min", DoubleValue(128)); // Smaller packet size for typical echo traffic
    echoPacketSizeRand->SetAttribute("Max", DoubleValue(1024)); 

    uint32_t echoPacketSize = echoPacketSizeRand->GetInteger();
    echoClientHelper.SetAttribute("MaxPackets", UintegerValue(15));  // Increase packet count for session duration
    echoClientHelper.SetAttribute("Interval", TimeValue(Seconds(0.5))); // Faster interval for lightweight query-like traffic
    echoClientHelper.SetAttribute("PacketSize", UintegerValue(echoPacketSize));

    ApplicationContainer echoClientApp = echoClientHelper.Install(clientNode);
    echoClientApp.Start(Seconds(12.0 + i * 0.5));  // Slightly different staggered start for Wi-Fi clients
    echoClientApp.Stop(Seconds(appStopTime));
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  
NS_LOG_INFO("Installing Applications on Remote Clients...");

for (uint32_t i = 0; i < remoteClients.GetN(); ++i) {
    Ptr<Node> clientNode = remoteClients.Get(i);

    // HTTP Client Setup with Burst and Idle Times
    BulkSendHelper httpClientHelper("ns3::TcpSocketFactory", InetSocketAddress(webServerIp, httpPort));
    uint32_t httpFileSize = 256 * 1024 + rand() % (1 * 1024 * 1024); // Between 256 KB to 1 MB
    httpClientHelper.SetAttribute("MaxBytes", UintegerValue(httpFileSize));
    ApplicationContainer httpClientApp = httpClientHelper.Install(clientNode);
    httpClientApp.Start(Seconds(5.0 + i * 10));  // Staggered start with bursts
    httpClientApp.Stop(Seconds(30.0 + i * 20));  // Short bursts within a window

    // HTTPS Client with Slow Start, Increasing Payloads
    BulkSendHelper httpsClientHelper("ns3::TcpSocketFactory", InetSocketAddress(webServerIp, httpsPort));
    uint32_t httpsFileSize = 128 * 1024 + rand() % (1 * 1024 * 1024); // Between 128 KB to 1 MB
    httpsClientHelper.SetAttribute("MaxBytes", UintegerValue(httpsFileSize));
    ApplicationContainer httpsClientApp = httpsClientHelper.Install(clientNode);
    httpsClientApp.Start(Seconds(12.0 + i * 15));  // Slightly delayed, increasing requests
    httpsClientApp.Stop(Seconds(appStopTime));

    // Email Client with Mixed Protocols and Random Idle Times
    Ptr<UniformRandomVariable> randProtocol = CreateObject<UniformRandomVariable>();
    randProtocol->SetAttribute("Min", DoubleValue(0.0));
    randProtocol->SetAttribute("Max", DoubleValue(2.0));
    
    int protocolChoice = randProtocol->GetInteger();
    Address emailDestAddress;
    uint16_t emailPort;

    if (protocolChoice == 0) {
        emailDestAddress = InetSocketAddress(emailServerIp, smtpPort);
        emailPort = smtpPort;
    } else if (protocolChoice == 1) {
        emailDestAddress = InetSocketAddress(emailServerIp, imapPort);
        emailPort = imapPort;
    } else {
        emailDestAddress = InetSocketAddress(emailServerIp, pop3Port);
        emailPort = pop3Port;
    }

    BulkSendHelper emailClientHelper("ns3::TcpSocketFactory", emailDestAddress);
    uint32_t emailSize = 20 * 1024 + rand() % (80 * 1024); // Between 20 KB and 100 KB
    emailClientHelper.SetAttribute("MaxBytes", UintegerValue(emailSize));
    ApplicationContainer emailClientApp = emailClientHelper.Install(clientNode);
    emailClientApp.Start(Seconds(20.0 + i * 10 + rand() % 15));  // Randomized start and idle periods
    emailClientApp.Stop(Seconds(appStopTime));

    // DNS Client with Variable Intervals to Mimic Caching
    UdpEchoClientHelper dnsClientHelper(dnsServerIp, dnsPort);
    dnsClientHelper.SetAttribute("MaxPackets", UintegerValue(3));  // Fewer packets to reflect caching
    dnsClientHelper.SetAttribute("Interval", TimeValue(Seconds(1.5 + rand() % 3)));  // Randomized interval between 1.5-4.5 seconds
    dnsClientHelper.SetAttribute("PacketSize", UintegerValue(48));  // Small packet size, 48 bytes
    ApplicationContainer dnsClientApp = dnsClientHelper.Install(clientNode);
    dnsClientApp.Start(Seconds(30.0 + i * 5));
    dnsClientApp.Stop(Seconds(150.0 + i * 10));

    // FTP Client with Mixed File Sizes and Dynamic Start Times
    BulkSendHelper ftpClientHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, ftpPort));
    uint32_t ftpFileSize = 200 * 1024 + rand() % (3 * 1024 * 1024); // Between 200 KB to 3 MB
    ftpClientHelper.SetAttribute("MaxBytes", UintegerValue(ftpFileSize));
    ApplicationContainer ftpClientApp = ftpClientHelper.Install(clientNode);
    ftpClientApp.Start(Seconds(40.0 + i * 8 + rand() % 20));  // Staggered with added randomness
    ftpClientApp.Stop(Seconds(appStopTime));
        

    // SSH Client with Frequent Disconnections and Fluctuating Session Sizes
    BulkSendHelper sshClientHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, sshPort));
    uint32_t sshSessionSize = 100 * 1024 + rand() % (300 * 1024); // Between 100 KB to 400 KB
    sshClientHelper.SetAttribute("MaxBytes", UintegerValue(sshSessionSize));
    ApplicationContainer sshClientApp = sshClientHelper.Install(clientNode);
    sshClientApp.Start(Seconds(50.0 + i * 6 + rand() % 10));  // Irregular intervals
    sshClientApp.Stop(Seconds(appStopTime));

    // UDP Echo Client with Random Packet Sizes and Extended Intervals
    NS_LOG_INFO("Setting up UDP Echo Client on Remote Client...");
    UdpEchoClientHelper echoClient(echoServerIp, echoPort);
    echoClient.SetAttribute("MaxPackets", UintegerValue(10));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(2.0 + rand() % 2)));  // Randomized intervals between 2-4 seconds
    echoClient.SetAttribute("PacketSize", UintegerValue(256 + rand() % 512));  // Packet size between 256 to 768 bytes
    ApplicationContainer echoClientApp = echoClient.Install(clientNode);
    echoClientApp.Start(Seconds(55.0 + i * 4 + rand() % 20));
    echoClientApp.Stop(Seconds(appStopTime));

    // Streaming Client with Variable Rates and Occasional Pauses
    OnOffHelper streamClient("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address("10.3.1.1"), streamPort));
    streamClient.SetConstantRate(DataRate("1Mbps"), 512 + rand() % 1024);  // Variable packet size up to 1 KB
    ApplicationContainer streamClientApp = streamClient.Install(clientNode);
    streamClientApp.Start(Seconds(60.0 + i * 3 + rand() % 20));  // Random start times and rates
    streamClientApp.Stop(Seconds(160.0));
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

 //////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Attack Simulation Code
//
// This section simulates various types of cyberattacks on different network components in the ns-3 simulation. 
// Each attack is configured with realistic parameters, including staggered start times, specific data rates, 
// and targeted servers, to mimic real-world scenarios and evaluate the impact on network performance.
//
// Simulated Attacks:
// 1. **SYN Flood Attack on HTTP Server**:
//    - A Denial of Service (DoS) attack where multiple clients generate TCP SYN packets targeting the HTTP server.
//    - Simulated with continuous packet generation to exhaust server resources.
//
// 2. **UDP Flood Attack on DNS Server**:
//    - A high-rate flood attack using UDP packets directed at the DNS server.
//    - Configured with large data rates to overload the server's capacity.
//
// 3. **ICMP Flood Attack on Core Router**:
//    - An attack generating ICMP Echo Requests (ping) at high frequencies to overwhelm the router.
//
// 4. **Port Scanning Attack**:
//    - Multiple clients scan a predefined list of ports on the HTTP/HTTPS server in the DMZ to identify open ports.
//
// 5. **Man-in-the-Middle (MitM) Simulation**:
//    - Redirects HTTP traffic from specific clients to a fake HTTP server, simulating a MitM attack.
//
// 6. **Brute Force Attacks**:
//    - Simulates credential brute forcing on FTP and SSH servers with multiple login attempts.
//
// 7. **SQL Injection Simulation**:
//    - Simulates malicious SQL injection payloads sent to the HTTP server, attempting to exploit vulnerabilities.
//
// 8. **ARP Spoofing**:
//    - A simulated redirection attack where a malicious client spoofs ARP replies to redirect traffic to itself.
//
// 9. **Zero-Day Exploit**:
//    - Simulates an advanced attack on HTTP and HTTPS servers using high-data-rate traffic patterns with malicious payloads.
//
// 10. **Distributed Denial of Service (DDoS)**:
//     - Multiple nodes from different subnets send high-rate UDP packets to the HTTP server, overwhelming its resources.
//
// 11. **VPN Tunnel Flooding**:
//     - A high-rate flood attack targeting the VPN server to disrupt secure communication channels.
//
// 12. **Credential Stuffing on VPN Server**:
//     - Multiple clients simulate login attempts with stolen credentials to gain unauthorized access.
//
// 13. **Botnet Communication Simulation**:
//     - Simulates botnet Command-and-Control (C&C) communication, with bots periodically sending data to a C&C server.
// 14. - **Other attack types
//
// Key Features:
// - Each attack is configured with specific start/stop times, targeted IPs, and realistic traffic patterns.
// - Staggered initiation times for attackers to mimic real-world distributed attack behaviors.
// - Uses ns-3 helpers such as `BulkSendHelper`, `OnOffHelper`, and `UdpEchoClientHelper` to configure attack traffic.
//
// This comprehensive setup provides a detailed framework for testing network resilience against various attack vectors.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

 
 // SYN Flood Attack on HTTP Server
NS_LOG_INFO("Starting SYN Flood Attack on HTTP Server...");

double attackStartTime = 60.0;    // When the attack should begin
double attackStopTime = 100.0;    // When the attack should stop (reduced from 140.0 to 100.0)
double attackInterval = 0.001;    // Interval between SYN packets
uint32_t numClients = 3;          // Number of attacking clients (use a subset of remoteClients)

// Configure SYN flood attack on HTTP server
for (uint32_t i = 0; i < numClients && i < remoteClients.GetN(); ++i) {
    Ptr<Node> attackerNode = remoteClients.Get(i);

    // Configure BulkSendHelper to generate SYN packets to HTTP server
    BulkSendHelper synFlood("ns3::TcpSocketFactory", InetSocketAddress(webServerIp, httpPort));
    synFlood.SetAttribute("MaxBytes", UintegerValue(0));  // 0 for continuous sends

    // Install on attacking node
    ApplicationContainer synFloodApp = synFlood.Install(attackerNode);
    synFloodApp.Start(Seconds(attackStartTime + i * 0.1));  // Stagger start slightly for each client
    synFloodApp.Stop(Seconds(attackStopTime));
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UDP Flood Attack on DNS Server
NS_LOG_INFO("Starting UDP Flood Attack on DNS Server...");

double udpFloodStartTime = 100.0;   // Attack start time (revised from 70.0 to 100.0)
double udpFloodStopTime = 125.0;    // Attack end time (revised from 120.0 to 125.0)
uint32_t floodClients = 3;          // Number of attacking clients (subset of enterpriseClients)
DataRate floodDataRate("100Mbps");   // High data rate for flood

// Configure UDP flood on DNS server
for (uint32_t i = 0; i < floodClients && i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> attackerNode = enterpriseClients.Get(i);

    // Set up OnOffHelper to generate high-rate UDP packets to DNS server
    OnOffHelper udpFlood("ns3::UdpSocketFactory", InetSocketAddress(dnsServerIp, dnsPort));
    udpFlood.SetConstantRate(floodDataRate, 512);  // 512-byte packets at 100 Mbps

    // Install the flood application on each attacking client
    ApplicationContainer udpFloodApp = udpFlood.Install(attackerNode);
    udpFloodApp.Start(Seconds(udpFloodStartTime + i * 0.1));  // Slightly stagger each start time
    udpFloodApp.Stop(Seconds(udpFloodStopTime));
} 

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ICMP Flood Attack on Core Router
NS_LOG_INFO("Starting ICMP Flood Attack on Core Router...");

double icmpFloodStartTime = 205.0;   // Attack start time (revised from 300.0 to 205.0)
double icmpFloodStopTime = 255.0;    // Attack end time (reduced from 400.0 to 255.0)
uint32_t icmpFloodClients = 3;       // Number of clients initiating the ICMP flood

// ICMP flood targeting the core router
Ipv4Address coreRouterIp = coreRouters.Get(0)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();  // Get the IP of core router

for (uint32_t i = 0; i < icmpFloodClients && i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> attackerNode = wifiStaNodes.Get(i);

    // Setup PingHelper to generate ICMP Echo requests rapidly
    UdpEchoClientHelper icmpFloodHelper(coreRouterIp, 0);  // ICMP packets use a port number of 0
    icmpFloodHelper.SetAttribute("MaxPackets", UintegerValue(1000000));  // Large number of packets to simulate flood
    icmpFloodHelper.SetAttribute("Interval", TimeValue(Seconds(0.001))); // Send every 1 ms
    icmpFloodHelper.SetAttribute("PacketSize", UintegerValue(64));       // Typical ICMP packet size

    // Install the flood application on each attacking client
    ApplicationContainer icmpFloodApp = icmpFloodHelper.Install(attackerNode);
    icmpFloodApp.Start(Seconds(icmpFloodStartTime + i * 0.1));  // Slightly stagger each start time
    icmpFloodApp.Stop(Seconds(icmpFloodStopTime));
} 
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Port Scanning Attack on HTTP/HTTPS Server in DMZ
NS_LOG_INFO("Starting Port Scanning Attack on HTTP/HTTPS Server...");

double scanStartTime = 150.0;    // Start time of the scan (revised from 80.0 to 150.0)
double scanStopTime = 168.0;     // Stop time of the scan (revised from 130.0 to 175.0)
uint32_t numScanClients = 3;     // Number of clients initiating the scan

// Target the HTTP/HTTPS server's IP in the DMZ
Ipv4Address targetServerIp = dmzInterfaces.GetAddress(0);
std::vector<uint16_t> portsToScan = {21, 22, 25, 53, 80, 110, 123, 143, 179, 443, 500, 587};  // Removed duplicate 80

// Set up a scan from multiple clients
for (uint32_t i = 0; i < numScanClients && i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> attackerNode = wifiStaNodes.Get(i);

    for (uint16_t port : portsToScan) {
        // Configure BulkSendHelper to attempt connections on each port
        BulkSendHelper portScanHelper("ns3::TcpSocketFactory", InetSocketAddress(targetServerIp, port));
        portScanHelper.SetAttribute("MaxBytes", UintegerValue(512));  // Small packet to simulate a connection attempt

        // Install the scan application on each attacking client
        ApplicationContainer portScanApp = portScanHelper.Install(attackerNode);
        portScanApp.Start(Seconds(scanStartTime + i * 0.1 + port * 0.01));  // Stagger slightly for each port
        portScanApp.Stop(Seconds(scanStopTime));
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Man-in-the-Middle (MitM) Simulation: Redirect HTTP Traffic to a Fake Server
NS_LOG_INFO("Setting up Fake HTTP Server for MitM Attack...");

// Define Fake HTTP Server Port
uint16_t fakeHttpPort = 8081;

// Fake HTTP Server Setup
Address fakeServerAddress(InetSocketAddress(Ipv4Address::GetAny(), fakeHttpPort));
PacketSinkHelper fakeHttpServerHelper("ns3::TcpSocketFactory", fakeServerAddress);
ApplicationContainer fakeHttpServerApp = fakeHttpServerHelper.Install(dmzServers.Get(1));  // Use a different DMZ server for the fake server
fakeHttpServerApp.Start(Seconds(10.0));   // Start after the legitimate server
fakeHttpServerApp.Stop(Seconds(450.0));

// Get the IP of the fake HTTP server
Ipv4Address fakeServerIp = dmzInterfaces.GetAddress(1);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Redirecting a Subset of Clients to the Fake Server (MitM Simulation)
NS_LOG_INFO("Redirecting HTTP Traffic from Specific Clients to Fake Server...");

double redirectStartTime = 262.0;   // Start time for clients redirected to the fake server (revised from 515.0 to 262.0)
double redirectStopTime = 313.0;    // Stop time for redirection (revised from 630.0 to 313.0)
uint32_t numMitmClients = 2;        // Number of clients affected by the MitM attack

// Configure clients to connect to the fake server
for (uint32_t i = 0; i < numMitmClients && i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> mitmClientNode = enterpriseClients.Get(i);

    // HTTP Client redirected to the Fake Server
    BulkSendHelper mitmHttpClientHelper("ns3::TcpSocketFactory", InetSocketAddress(fakeServerIp, fakeHttpPort));
    mitmHttpClientHelper.SetAttribute("MaxBytes", UintegerValue(1024 * 1024));  // 1 MB traffic

    // Install on affected client node
    ApplicationContainer mitmHttpClientApp = mitmHttpClientHelper.Install(mitmClientNode);
    mitmHttpClientApp.Start(Seconds(redirectStartTime + i * 0.1));  // Slight stagger for each client
    mitmHttpClientApp.Stop(Seconds(redirectStopTime));
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Brute Force Attack on FTP Server
NS_LOG_INFO("Starting Brute Force Attack on FTP Server...");

double bruteForceStartTime = 347.0;   // Attack start time (revised from 620.0 to 347.0)
double bruteForceStopTime = 367.0;    // Attack stop time (revised from 660.0 to 367.0)
uint32_t numAttackClients = 3;        // Number of clients involved in brute force attack
//uint16_t ftpPort = 21;               // FTP control port

// Configure brute force attack on FTP server
//Ipv4Address ftpServerIp = dmzInterfaces.GetAddress(3);  // IP of the FTP server in DMZ

for (uint32_t i = 0; i < numAttackClients && i < remoteClients.GetN(); ++i) {
    Ptr<Node> attackerNode = remoteClients.Get(i);

    for (uint32_t attempt = 0; attempt < 10; ++attempt) {  // Simulate multiple login attempts
        // Configure BulkSendHelper to send a short burst to the FTP server
        BulkSendHelper bruteForceHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, ftpPort));
        bruteForceHelper.SetAttribute("MaxBytes", UintegerValue(512));  // Small packet to simulate a connection attempt

        // Install the brute force application on each attacking client
        ApplicationContainer bruteForceApp = bruteForceHelper.Install(attackerNode);
        bruteForceApp.Start(Seconds(bruteForceStartTime + i * 0.1 + attempt * 0.5));  // Staggered timing for each attempt
        bruteForceApp.Stop(Seconds(bruteForceStopTime));
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SQL Injection Simulation on HTTP Server
NS_LOG_INFO("Starting SQL Injection Simulation on HTTP Server...");

double sqlInjectionStartTime = 368.0;   // Start time for SQL injection attempts (revised from 700.0 to 368.0)
double sqlInjectionStopTime = 433.0;    // End time for SQL injection attempts (revised from 850.0 to 433.0)
uint32_t sqlInjectionClients = 3;       // Number of clients involved in SQL injection simulation
//uint16_t httpPort = 80;                // HTTP server port

// Common SQL injection payloads (as examples)
std::vector<std::string> sqlPayloads = {
    "' OR '1'='1",
    "' OR 'a'='a",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "'; SELECT * FROM users WHERE 'a'='a",
    "' UNION SELECT NULL, NULL, NULL --"
};

// Configure SQL injection attempts on HTTP server
Ipv4Address httpServerIp = dmzInterfaces.GetAddress(0);  // IP of the HTTP server in DMZ

for (uint32_t i = 0; i < sqlInjectionClients && i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> attackerNode = enterpriseClients.Get(i);

    for (size_t payloadIndex = 0; payloadIndex < sqlPayloads.size(); ++payloadIndex) {
        // Configure OnOffHelper with a fake "HTTP" payload simulating an SQL injection attempt
        OnOffHelper sqlInjectionHelper("ns3::TcpSocketFactory", InetSocketAddress(httpServerIp, httpPort));
        sqlInjectionHelper.SetAttribute("PacketSize", UintegerValue(sqlPayloads[payloadIndex].size() + 50));  // Adjusted packet size
        sqlInjectionHelper.SetAttribute("DataRate", StringValue("2Mbps"));  // Control the injection traffic rate

        // Set the SQL payload as the pattern
        sqlInjectionHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
        sqlInjectionHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));

        // Install the application on the attacking client
        ApplicationContainer sqlInjectionApp = sqlInjectionHelper.Install(attackerNode);
        sqlInjectionApp.Start(Seconds(sqlInjectionStartTime + i * 0.1 + payloadIndex * 0.5));  // Staggered payload delivery
        sqlInjectionApp.Stop(Seconds(sqlInjectionStopTime));
    }
} 
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Brute Force Attack on SSH Server
NS_LOG_INFO("Starting Brute Force Attack on SSH Server...");

double sshBruteForceStartTime = 169.0;   // Start time for SSH brute force (revised from 170.0 to 169.0)
double sshBruteForceStopTime = 184.0;    // End time for SSH brute force (revised from 200.0 to 184.0)
uint32_t sshAttackClients = 3;           // Number of clients involved in SSH brute force
//uint16_t sshPort = 22;                   // SSH server port

// Configure brute force attack on SSH server
Ipv4Address sshServerIp = dmzInterfaces.GetAddress(3);  // Assume the SSH server is on dmzServers.Get(3)

for (uint32_t i = 0; i < sshAttackClients && i < remoteClients.GetN(); ++i) {
    Ptr<Node> attackerNode = remoteClients.Get(i);

    for (uint32_t attempt = 0; attempt < 20; ++attempt) {  // Simulate 20 connection attempts per client
        BulkSendHelper sshBruteForceHelper("ns3::TcpSocketFactory", InetSocketAddress(sshServerIp, sshPort));
        sshBruteForceHelper.SetAttribute("MaxBytes", UintegerValue(512));  // Small packets for login attempts

        ApplicationContainer sshBruteForceApp = sshBruteForceHelper.Install(attackerNode);
        sshBruteForceApp.Start(Seconds(sshBruteForceStartTime + i * 0.2 + attempt * 0.2));  // Staggered attempts
        sshBruteForceApp.Stop(Seconds(sshBruteForceStopTime));
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FTP Login Attempt Flood on FTP Server
NS_LOG_INFO("Starting FTP Login Attempt Flood on FTP Server...");

double ftpBruteForceStartTime = 483.0;   // Start time for FTP brute force (revised from 800.0 to 483.0)
double ftpBruteForceStopTime = 533.0;    // End time for FTP brute force (revised from 900.0 to 533.0)
uint32_t ftpAttackClients = 2;           // Number of clients involved in FTP brute force
//uint16_t ftpPort = 21;                   // FTP server port

// Configure brute force attack on FTP server
//Ipv4Address ftpServerIp = dmzInterfaces.GetAddress(3);  // Assume the FTP server is also on dmzServers.Get(3)

for (uint32_t i = 0; i < ftpAttackClients && i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> attackerNode = enterpriseClients.Get(i);

    for (uint32_t attempt = 0; attempt < 30; ++attempt) {  // Simulate 30 login attempts per client
        BulkSendHelper ftpBruteForceHelper("ns3::TcpSocketFactory", InetSocketAddress(ftpServerIp, ftpPort));
        ftpBruteForceHelper.SetAttribute("MaxBytes", UintegerValue(1024));  // Slightly larger packet for FTP attempt

        ApplicationContainer ftpBruteForceApp = ftpBruteForceHelper.Install(attackerNode);
        ftpBruteForceApp.Start(Seconds(ftpBruteForceStartTime + i * 0.1 + attempt * 0.1));  // Staggered attempts
        ftpBruteForceApp.Stop(Seconds(ftpBruteForceStopTime));
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Botnet C&C Communication Simulation
NS_LOG_INFO("Setting up Botnet C&C Communication Simulation...");

// Define C&C Server in DMZ on a specific port
uint16_t cncPort = 9999;
Address cncServerAddress(InetSocketAddress(Ipv4Address::GetAny(), cncPort));
PacketSinkHelper cncServerHelper("ns3::TcpSocketFactory", cncServerAddress);
ApplicationContainer cncServerApp = cncServerHelper.Install(dmzServers.Get(4));  // C&C server on DMZ Server 4
cncServerApp.Start(Seconds(20.0));   // Start early to listen for bot communications
cncServerApp.Stop(Seconds(700.0));

Ipv4Address cncServerIp = dmzInterfaces.GetAddress(4);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Configure Bot Clients to Communicate with the C&C Server
NS_LOG_INFO("Configuring Bot Clients for C&C Communication...");

double botCommStartTime = 546.0;      // Start time for bot communication (revised from 900.0 to 546.0)
double botCommStopTime = 607.0;       // End time for bot communication (revised from 1000.0 to 608.0)
uint32_t botClients = 3;              // Number of bot clients
DataRate botDataRate("500kbps");      // Low data rate typical for botnet communication

for (uint32_t i = 0; i < botClients && i < wifiStaNodes.GetN(); ++i) {
    Ptr<Node> botNode = wifiStaNodes.Get(i);

    // Configure OnOffHelper to simulate periodic communication to C&C server
    OnOffHelper botCommHelper("ns3::TcpSocketFactory", InetSocketAddress(cncServerIp, cncPort));
    botCommHelper.SetAttribute("DataRate", DataRateValue(botDataRate));
    botCommHelper.SetAttribute("PacketSize", UintegerValue(128)); // Small packets, typical for bot traffic
    botCommHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
    botCommHelper.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=5.0]")); // Periodic communication

    // Install bot communication application
    ApplicationContainer botCommApp = botCommHelper.Install(botNode);
    botCommApp.Start(Seconds(botCommStartTime + i * 0.2));  // Slightly staggered start times
    botCommApp.Stop(Seconds(botCommStopTime));
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// VPN Tunnel Flooding Attack on VPN Server
NS_LOG_INFO("Starting VPN Tunnel Flooding Attack...");

double vpnFloodStartTime = 608.0;      // Attack start time (revised from 300.0 to 608.0)
double vpnFloodStopTime = 633.0;       // Attack end time (revised from 350.0 to 633.0)
uint32_t vpnFloodClients = 3;          // Number of clients involved in VPN flooding
DataRate vpnFloodDataRate("50Mbps");    // High data rate for flooding

// Configure VPN flood traffic targeting the VPN server
Ipv4Address vpnServerIp = vpnInterfaces.GetAddress(0);  // Assuming the VPN server IP is the first address in vpnInterfaces
uint16_t vpnPort = 443;                                // Typical VPN port (can adjust based on your setup)

for (uint32_t i = 0; i < vpnFloodClients && i < remoteClients.GetN(); ++i) {
    Ptr<Node> floodNode = remoteClients.Get(i);

    // Set up OnOffHelper to generate high-rate VPN traffic
    OnOffHelper vpnFloodHelper("ns3::TcpSocketFactory", InetSocketAddress(vpnServerIp, vpnPort));
    vpnFloodHelper.SetConstantRate(vpnFloodDataRate, 1024);  // 50 Mbps, 1 KB packets

    // Install the flooding application on each attacking client
    ApplicationContainer vpnFloodApp = vpnFloodHelper.Install(floodNode);
    vpnFloodApp.Start(Seconds(vpnFloodStartTime + i * 0.1));  // Slight staggered start for each client
    vpnFloodApp.Stop(Seconds(vpnFloodStopTime));
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Credential Stuffing Attack on VPN Server
NS_LOG_INFO("Starting Credential Stuffing Attack on VPN Server...");

double credentialStuffingStartTime = 444.0;    // Start time for credential stuffing (revised from 160.0 to 444.0)
double credentialStuffingStopTime = 483.0;     // End time for credential stuffing (revised from 190.0 to 483.0)
uint32_t stuffingClients = 3;                   // Number of clients involved in credential stuffing
//uint16_t vpnPort = 443;                        // VPN server port

// Configure credential stuffing attack targeting the VPN server
//Ipv4Address vpnServerIp = vpnInterfaces.GetAddress(0);  // Assuming the VPN server IP is the first address in vpnInterfaces

for (uint32_t i = 0; i < stuffingClients && i < remoteClients.GetN(); ++i) {
    Ptr<Node> stuffingNode = remoteClients.Get(i);

    for (uint32_t attempt = 0; attempt < 15; ++attempt) {  // Simulate 15 login attempts per client
        // Use BulkSendHelper to simulate short connection attempts to VPN server
        BulkSendHelper credentialStuffingHelper("ns3::TcpSocketFactory", InetSocketAddress(vpnServerIp, vpnPort));
        credentialStuffingHelper.SetAttribute("MaxBytes", UintegerValue(512));  // Small packets for login attempts

        // Install the credential stuffing application on each attacking client
        ApplicationContainer credentialStuffingApp = credentialStuffingHelper.Install(stuffingNode);
        credentialStuffingApp.Start(Seconds(credentialStuffingStartTime + i * 0.2 + attempt * 0.1));  // Staggered attempts
        credentialStuffingApp.Stop(Seconds(credentialStuffingStopTime));
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// XSS Attack
// Define application timing and target server details
double xssStartTime = 728.0;    // Start time for XSS attack (revised from 1000.0 to 728.0)
double xssStopTime = 788.0;     // End time for XSS attack (reduced from 1120.0 to 788.0)
uint32_t xssClients = 2;        // Number of clients participating in the XSS attack
//uint16_t httpPort = 80;        // HTTP server port

// Get the IP address of the HTTP server in the DMZ
//Ipv4Address httpServerIp = dmzInterfaces.GetAddress(0);

// Define XSS payloads
std::vector<std::string> xssPayloads = {
    "GET /search?q=<script>alert('XSS1')</script> HTTP/1.1",
    "GET /profile?name=<script>alert('XSS2')</script> HTTP/1.1",
    "GET /comments?id=1'><script>alert('XSS3')</script> HTTP/1.1",
    "GET /index.html?page=<script>alert('XSS4')</script> HTTP/1.1"
};

// Loop over client nodes to install XSS traffic-generating applications
for (uint32_t i = 0; i < xssClients && i < enterpriseClients.GetN(); ++i) {
    Ptr<Node> attackerNode = enterpriseClients.Get(i);

    for (size_t payloadIndex = 0; payloadIndex < xssPayloads.size(); ++payloadIndex) {
        // Configure OnOffHelper with HTTP packets containing XSS payloads
        OnOffHelper xssAttack("ns3::TcpSocketFactory", InetSocketAddress(httpServerIp, httpPort));
        xssAttack.SetAttribute("PacketSize", UintegerValue(xssPayloads[payloadIndex].size() + 50));  // Adjusted for header size
        xssAttack.SetAttribute("DataRate", StringValue("500kbps"));  // Adjusted rate for XSS attack traffic
        xssAttack.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
        xssAttack.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));

        // Install the XSS attack application on the attacking client node
        ApplicationContainer xssAttackApp = xssAttack.Install(attackerNode);
        xssAttackApp.Start(Seconds(xssStartTime + i * 0.1 + payloadIndex * 0.2));  // Staggered start for each payload
        xssAttackApp.Stop(Seconds(xssStopTime));
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ARP Spoofing
// Define application timing and malicious node details
double arpPoisonStartTime = 321.0;    // Start time for ARP Poisoning attack (revised from 520.0 to 321.0)
double arpPoisonStopTime = 346.0;     // End time for ARP Poisoning attack (revised from 570.0 to 346.0)
uint32_t numArpAttackers = 1;         // Number of nodes conducting ARP spoofing

// Define target node for ARP Poisoning (example: HTTP server)
Ptr<Node> targetNode = dmzServers.Get(0);      // Targeted HTTP server
Ipv4Address targetIp = targetNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();  // Obtain target IP

// Define the IP of the malicious node (the ARP Poisoning source)
Ptr<Node> maliciousNode = enterpriseClients.Get(2);  // Assign a client node as the attacker
Ipv4Address attackerIp = maliciousNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();

// Set up a redirection mechanism on the malicious node to intercept traffic to the target IP
OnOffHelper arpPoisoningApp("ns3::UdpSocketFactory", InetSocketAddress(targetIp, 80));  // Simulate redirection
arpPoisoningApp.SetAttribute("DataRate", StringValue("1Mbps"));  // Control rate for spoofing packets
arpPoisoningApp.SetAttribute("PacketSize", UintegerValue(128));  // Small packet size for ARP poison effect

// Install the ARP Poisoning application on the malicious node
ApplicationContainer arpPoisonApp = arpPoisoningApp.Install(maliciousNode);
arpPoisonApp.Start(Seconds(arpPoisonStartTime));
arpPoisonApp.Stop(Seconds(arpPoisonStopTime));

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Zero Day Attack
// Define application timing and target node details
double zeroDayStartTime = 933.0;      // Start time for zero-day exploit (revised from 800.0 to 533.0)
double zeroDayStopTime = 983.0;       // End time for zero-day exploit (revised from 900.0 to 583.0)
//uint16_t httpPort = 80;              // HTTP port typically targeted for such exploits
//uint16_t httpsPort = 443;            // HTTPS port also a target for such attacks

// Define target node for zero-day exploit (example: HTTP/HTTPS server)
Ptr<Node> targetNodeZeroDay = dmzServers.Get(0);      // Targeted server in the DMZ
Ipv4Address targetIpZeroDay = targetNodeZeroDay->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();  // Obtain target IP

// Select nodes to simulate zero-day exploit traffic
Ptr<Node> attackerNodeZeroDay = enterpriseClients.Get(1);  // Choose an enterprise client as attacker

// Define unusual traffic pattern representing exploit behavior
OnOffHelper zeroDayApp("ns3::TcpSocketFactory", InetSocketAddress(targetIpZeroDay, httpPort));
zeroDayApp.SetAttribute("DataRate", StringValue("10Mbps"));   // Higher data rate to simulate exploit traffic
zeroDayApp.SetAttribute("PacketSize", UintegerValue(1024)); // Large packet size representing malicious payloads

// Install the zero-day exploit application on the attacker node
ApplicationContainer zeroDayExploitApp = zeroDayApp.Install(attackerNodeZeroDay);
zeroDayExploitApp.Start(Seconds(zeroDayStartTime));
zeroDayExploitApp.Stop(Seconds(zeroDayStopTime));

// Configure additional attacks on HTTPS port to increase threat vector
OnOffHelper zeroDayAppHttps("ns3::TcpSocketFactory", InetSocketAddress(targetIpZeroDay, httpsPort));
zeroDayAppHttps.SetAttribute("DataRate", StringValue("10Mbps"));   // Similar high data rate
zeroDayAppHttps.SetAttribute("PacketSize", UintegerValue(1024));

 // Install the application on the attacker node
ApplicationContainer zeroDayExploitAppHttps = zeroDayAppHttps.Install(attackerNodeZeroDay);
zeroDayExploitAppHttps.Start(Seconds(zeroDayStartTime));
zeroDayExploitAppHttps.Stop(Seconds(zeroDayStopTime));
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// DDoS Attack 
// DDoS Attack Timing and Target Details
double ddosStartTime = 583.0;        // Attack start time (revised from 950.0 to 583.0)
double ddosStopTime = 608.0;         // Attack end time (revised from 1000.0 to 608.0)
uint16_t ddosTargetPort = 80;        // Target port on the server (e.g., HTTP)

Ptr<Node> ddosTargetNode = dmzServers.Get(0);   // Target server in DMZ for DDoS
Ipv4Address ddosTargetIp = ddosTargetNode->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();

// Parameters for DDoS Attack Configuration
DataRate ddosDataRate("100Mbps");    // High data rate to simulate heavy load
uint32_t ddosPacketSize = 1024;      // Packet size in bytes

// Select nodes from different subnets for a realistic distributed attack
std::vector<Ptr<Node>> ddosAttackers;
ddosAttackers.push_back(enterpriseClients.Get(0));  // Example from enterprise clients
ddosAttackers.push_back(wifiStaNodes.Get(1));       // Example from Wi-Fi clients
ddosAttackers.push_back(remoteClients.Get(2));      // Example from remote clients

// Configure the attack on each selected attacker node
for (uint32_t i = 0; i < ddosAttackers.size(); ++i) {
    Ptr<Node> attackerNode = ddosAttackers[i];

    // Configure OnOffHelper to simulate UDP flood
    OnOffHelper ddosAttackHelper("ns3::UdpSocketFactory", InetSocketAddress(ddosTargetIp, ddosTargetPort));
    ddosAttackHelper.SetConstantRate(ddosDataRate, ddosPacketSize);

    // Install DDoS attack application on each attacker
    ApplicationContainer ddosAttackApp = ddosAttackHelper.Install(attackerNode);
    ddosAttackApp.Start(Seconds(ddosStartTime + i * 0.5)); // Stagger each attacker’s start time
    ddosAttackApp.Stop(Seconds(ddosStopTime));
}

// Enable PCAP capture on the target server for analysis
csmaDmz.EnablePcap("ddos-attack-traffic", ddosTargetNode->GetId(), true); // Capture on the target server

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Network Configuration: Enabling Routing and IP Forwarding
//
// This section configures key network devices, such as routers and switches, to enable IP forwarding, 
// allowing them to forward packets between different networks. Additionally, routing tables are populated 
// to ensure devices can route packets efficiently throughout the network.
//
// Key Steps:
// 1. **Core Router Configuration**:
//    - The core router is enabled for IP forwarding, allowing it to route traffic between various subnets.
//
// 2. **Distribution Switch Configuration**:
//    - Each distribution switch is configured to forward packets, ensuring connectivity between 
//      access switches and the core network.
//
// 3. **Access Switch Configuration**:
//    - Access switches are set up to forward packets between enterprise clients and higher-level switches.
//
// 4. **Wi-Fi Access Point Configuration**:
//    - The Wi-Fi AP is enabled for IP forwarding to route traffic between wireless clients and the network.
//
// 5. **Routing Table Population**:
//    - Once IP addresses are assigned and forwarding is enabled, the `Ipv4GlobalRoutingHelper` populates 
//      global routing tables across all devices. This ensures all nodes have routes to their destinations.
//
// This configuration is critical for enabling seamless communication between nodes in the simulated network.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


// For Core Router
Ptr<Node> coreRouterNode = coreRouters.Get(0);
coreRouterNode->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));

// For Distribution Switches
for (uint32_t i = 0; i < distributionSwitches.GetN(); ++i) {
    distributionSwitches.Get(i)->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
}

// For Access Switches
for (uint32_t i = 0; i < accessSwitchesHR.GetN(); ++i) {
    accessSwitchesHR.Get(i)->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));
}

// For Wi-Fi AP Node
wifiApNode.Get(0)->GetObject<Ipv4>()->SetAttribute("IpForward", BooleanValue(true));

// After assigning all IP addresses
Ipv4GlobalRoutingHelper::PopulateRoutingTables();


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Traffic Capture and Monitoring Configuration
//
// This section enables PCAP (Packet Capture) on key devices in the network to monitor and analyze traffic. 
// PCAP files are generated for capturing all packets passing through critical points in the network, 
// especially to track and investigate attack scenarios.
//
// Key Monitoring Points:
// 1. **Core Router**:
//    - Captures all traffic passing through the core router, providing a complete overview of network activity.
//
// 2. **VPN Server**:
//    - Monitors traffic to and from the VPN server, particularly for attacks such as Credential Stuffing 
//      and Tunnel Flooding.
//
// 3. **DMZ Servers**:
//    - Specific PCAP files are generated for each DMZ server to capture attack-specific traffic:
//      - HTTP/HTTPS Server: SYN Flood, SQL Injection, HTTP Spoofing.
//      - FTP Server: Login Attempt Floods and Brute Force attacks.
//      - SSH Server: Brute Force attempts targeting SSH access.
//      - DNS Server: UDP Flood attacks targeting DNS services.
//      - Botnet C&C Server: Tracks botnet communication patterns.
//
// 4. **Distribution and Access Switches**:
//    - Traffic flows between the core router, distribution switches, and access switches are captured to 
//      analyze intra-network traffic and its impact during attack simulations.
//
// 5. **Wi-Fi Access Point**:
//    - Captures traffic on the Wi-Fi Access Point to monitor wireless client interactions and potential 
//      malicious activities.
//
// **Purpose of PCAP Files**:
// - Enables detailed analysis of traffic patterns and anomalies during attacks.
// - Assists in debugging and evaluating the effectiveness of intrusion detection systems (IDS).
// - Provides a mechanism for post-simulation forensic analysis.
//
// **Configuration Highlights**:
// - Promiscuous mode (`true`) is enabled for each PCAP capture to include all packets on the respective link.
// - Files are named to reflect the target device or attack being monitored for clarity.
//
// This configuration is essential for monitoring network behavior under normal and attack conditions.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


// Capturing All Traffic in a Single PCAP File

pointToPoint.EnablePcap("all-network-traffic", coreRouters.Get(0)->GetDevice(0), true);  // Set promiscuous mode to true


NS_LOG_INFO("Enabling PCAP files on critical points for attack monitoring...");

// 1. VPN Server Node: Capture VPN-related traffic for attacks like Credential Stuffing and Tunnel Flooding
vpnLink.EnablePcap("vpn-server-traffic", vpnToCore.Get(0), true);  // Device 0 on VPN server end of vpnToCore link

// 2. DMZ Servers - Monitoring HTTP, HTTPS, FTP, SSH, and DNS servers

// HTTP/HTTPS Server: Capture SYN Flood, SQL Injection, HTTP Spoofing
csmaDmz.EnablePcap("http-https-server-traffic", dmzServers.Get(0)->GetDevice(1), true); // Device 1 for HTTP/HTTPS on dmzServers.Get(0)

// FTP Server: Capture FTP Login Attempt Flood and Brute Force
csmaDmz.EnablePcap("ftp-server-traffic", dmzServers.Get(3)->GetDevice(1), true); // Device 1 for FTP on dmzServers.Get(3)

// SSH Server: Capture SSH Brute Force attempts
csmaDmz.EnablePcap("ssh-server-traffic", dmzServers.Get(3)->GetDevice(1), true); // Device 1 for SSH on dmzServers.Get(3)

// DNS Server: Capture UDP Flood targeting DNS
csmaDmz.EnablePcap("dns-server-traffic", dmzServers.Get(2)->GetDevice(1), true); // Device 1 for DNS on dmzServers.Get(2)

// Botnet C&C Server: Capture communication to/from bot nodes
csmaDmz.EnablePcap("botnet-cnc-server-traffic", dmzServers.Get(4)->GetDevice(1), true); // Device 1 for Botnet C&C on dmzServers.Get(4)

// 3. Core Router - Enable PCAP to capture all traffic passing through the core
pointToPoint.EnablePcap("core-router-traffic", p2pDevices1.Get(0), true);  // Confirmed Device 0 for core router’s link to dist switch 0

// 4. Distribution and Access Switches - Capturing intra-network traffic flow

// Distribution Switch 0: Enable PCAP to capture traffic between Core Router and Enterprise network
pointToPoint.EnablePcap("distribution-switch-0-traffic", p2pDevices1.Get(1), true);  // Device 1 for dist switch 0’s link to core router

// Distribution Switch 1: Capture traffic between Core Router and DMZ network
pointToPoint.EnablePcap("distribution-switch-1-traffic", p2pDevices2.Get(1), true); // Device 1 for dist switch 1’s link to core router

// Access Switch: Already generated and confirmed
csmaEnterprise.EnablePcap("access-switch-traffic", accessSwitchesHR.Get(0)->GetDevice(1), true); // Device 1 on access switch for enterprise clients

// 5. Wi-Fi Access Point (Missing file)
wifiPhy.EnablePcap("wifi-ap-traffic", wifiApDevice.Get(0), 0);  // Explicit capture on the AP's Wi-Fi device

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Flow Monitoring and Simulation Finalization
//
// This section enables flow monitoring, optional packet tracing, and finalizes the simulation. 
//
// Key Features:
// 1. **Flow Monitor**:
//    - Tracks traffic statistics (throughput, delay, jitter, packet loss) for all network nodes.
//    - Results are saved to `flowmon-results.xml` for analysis.
//
// 2. **Packet Tracing (Optional)**:
//    - Enables packet metadata and routing table tracking for visualization and debugging.
//
// 3. **Simulation Finalization**:
//    - Runs the simulation, saves results, and cleans up resources.
//
// Outputs:
// - `flowmon-results.xml`: Detailed traffic flow statistics.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////
    // Flow Monitor (Optional)
    ///////////////////////////////
    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> flowmon = flowmonHelper.InstallAll();  // Install on all nodes
    //flowmon->SerializeToXmlFile("flowmon-results.xml", true, true);
    

    
    // Enable Packet Animation Tracing
    //anim.EnablePacketMetadata(true);  // Records packet details
    //anim.EnableIpv4RouteTracking("routingtable-trace.xml", Seconds(0), Seconds(20), Seconds(0.25));  // Record route changes
    
    // After simulation run
    Simulator::Stop(Seconds(appStopTime));
    //Simulator::Stop(Seconds(200));
    Simulator::Run();
    
    // Serialize Flow Monitor results
    flowmon->SerializeToXmlFile("flowmon-results.xml", true, true);
    Simulator::Destroy();

    return 0;
}


