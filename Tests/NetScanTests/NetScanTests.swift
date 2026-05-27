import Testing
import Foundation
import Core
@testable import NetScan

@Test func networkModuleExists() {
    #expect(true)
}

// MARK: - IP Conversion
@Test func ipv4ToUInt32Valid() {
    let result = ipv4ToUInt32("192.168.1.1")
    #expect(result != nil)
}

@Test func ipv4ToUInt32Invalid() {
    let result = ipv4ToUInt32("invalid")
    #expect(result == nil)
}

@Test func uint32ToIPv4RoundTrip() {
    let ip = "10.0.0.1"
    let u32 = ipv4ToUInt32(ip)
    #expect(u32 != nil)
    let back = uint32ToIPv4(u32!)
    #expect(back == ip)
}

// MARK: - Subnet CIDR Parsing
@Test func subnetValidCIDR() {
    let subnet = Subnet(cidr: "192.168.1.0/24")
    #expect(subnet != nil)
    #expect(subnet?.prefix == 24)
    #expect(subnet?.network == "192.168.1.0")
}

@Test func subnetInvalidCIDR() {
    #expect(Subnet(cidr: "") == nil)
    #expect(Subnet(cidr: "invalid") == nil)
    #expect(Subnet(cidr: "192.168.1.0/33") == nil)
    #expect(Subnet(cidr: "192.168.1.0/abc") == nil)
}

@Test func subnetUsableHostCount() {
    let subnet = Subnet(cidr: "10.0.0.0/30")
    #expect(subnet != nil)
    // /30 = 4 addresses total: network, 2 usable, broadcast
    #expect(subnet?.usableHostCount == 2)
}

@Test func subnetBroadcastAddress() {
    let subnet = Subnet(cidr: "192.168.1.0/24")
    #expect(subnet?.broadcast == "192.168.1.255")
}

// MARK: - NetworkInterface Subnet
@Test func networkInterfaceSubnetComputation() {
    let iface = NetworkInterface(name: "en0", ip: "192.168.1.100", netmask: "255.255.255.0")
    let subnet = iface.subnet
    #expect(subnet != nil)
    #expect(subnet?.network == "192.168.1.0")
    #expect(subnet?.broadcast == "192.168.1.255")
    #expect(subnet?.prefix == 24)
}

@Test func networkInterfaceSubnetNonAligned() {
    let iface = NetworkInterface(name: "en1", ip: "10.0.0.5", netmask: "255.255.255.248")
    let subnet = iface.subnet
    #expect(subnet != nil)
    #expect(subnet?.network == "10.0.0.0")
    #expect(subnet?.prefix == 29)
}

// MARK: - ConcurrencyGate
@Test func concurrencyGateBasic() async {
    let gate = ConcurrencyGate(maxConcurrency: 2)
    await gate.waitIfNeeded()
    await gate.waitIfNeeded()
    await gate.signal()
    await gate.signal()
}

// MARK: - PortScanner Construction
@Test func portScannerCreation() {
    _ = PortScanner()
}

@Test func portScannerCustomConcurrency() {
    _ = PortScanner(maxConcurrency: 16)
}

// MARK: - UDPScanner Construction
@Test func udpScannerCreation() {
    _ = UDPScanner()
}

// MARK: - NetworkDiscovery
@Test func networkDiscoveryCreation() {
    _ = NetworkDiscovery()
}

@Test func networkDiscoveryCustomConcurrency() {
    _ = NetworkDiscovery(maxConcurrency: 16)
}

// MARK: - NetworkError Mapping (integration)
@Test func networkErrorFromPortScanTypes() {
    let timeout = NetworkError.connectionTimeout("scan timed out")
    let refused = NetworkError.connectionRefused("connection reset")
    let unreachable = NetworkError.networkUnreachable

    #expect(timeout.errorDescription?.contains("timed out") == true)
    #expect(refused.errorDescription?.contains("refused") == true)
    #expect(unreachable.errorDescription?.contains("unreachable") == true)
}
