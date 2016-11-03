from scapy.all import *
import re
import json

class ProcessPacket:

    def __init__(self):
        ''' Initializes constants needed to process the packet and then 
            processes the packet
        '''

        self.get_input()

    def get_input(self):
        '''Reads given pcap file and parses it'''

        user_directory = "/Users/andreawu/Downloads/cfd/correct_stream.pcap"
        self.process_pcap(user_directory)
             
    def process_pcap(self, pcap_file):
        '''Processes each packet in packet capture
        Input:
        - pcap_file: packet capture file to be processed
        Output:
        - This function doesn't return anything, but it creates a pcap file
          with the new IP/MAC addresses
        '''

        packets = rdpcap(pcap_file)
        ind = 0 
        # Loop through each individual packet in the pcap file
        for p in packets:
            if p[IP].src == "178.248.225.226":
                # Write new pcap file 
                new_filename = str(ind) + "outside.pcap"
            else:
                new_filename = str(ind) + "inside.pcap"
            ind += 1
            wrpcap(new_filename, p)

p = ProcessPacket()
