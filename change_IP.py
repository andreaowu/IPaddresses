from scapy.all import *
import os
import re
import json

class ProcessPacket:

    def __init__(self):
        ''' Initializes constants needed to process the packet and then 
            processes the packet
        '''
    
        # Initializes IP addresses and MAC addresses to be used in new packet
        self.src_ip = ""
        self.dst_ip = ""
        self.src_mac = ""
        self.dst_mac = ""
        
        # Gets configuration file and grabs the new IP/MAC addresses
        success = self.get_config()

        # If parsed successfully, there will be new packets with the new
        # configurations
        if success:
            self.get_input()

    def get_config(self):
        ''' Gets the configuration file, parses and saves the contents
            Output:
            - True: configuration file is parsed successfully
            - False: configuration file is not parsed successfully
        '''

        # config_file = "/users/andreawu/config.json"
        config_file = raw_input("Enter location for config file, make sure file is in json format\n")

        # Check that file exists, otherwise quit
        if not os.path.exists(config_file):
            print "ERROR: Given path for config does not exist. " \
                  "Did not craft new packets."
            return False

        # Open and read contents
        config_contents = open(config_file, "r").read()
        new = json.loads(config_contents)

        # Set new IP/MAC addresses according to configuration file contents
        self.src_ip = new["src_ip"]
        self.dst_ip = new["dst_ip"]
        self.src_mac = new["src_mac"]
        self.dst_mac = new["dst_mac"]
        return True

    def get_input(self):
        '''Reads given pcap file and parses it'''

        user_directory = "/Users/andreawu/change_ip"
        #user_directory = raw_input("Enter location for pcap file\n")

        # Check that file exists, otherwise quit
        if not os.path.exists(user_directory):
            print "ERROR: Given path for packet capture directory does " \
                  "not exist. Did not craft new packets."
            return

        path_contents = os.listdir(user_directory)
        processed = False
        for x in path_contents:
            # File is a pcap file
            if x.endswith(".pcap"):
                self.process_pcap(user_directory + "/" + x)
                processed = True
        # No pcaps were processed/found in given directory
        if not processed:
            print "Warning: No pcaps created - provided directory " \
                  "has no pcap files.\n"
            
    def process_pcap(self, pcap_file):
        '''Processes each packet in packet capture
        Input:
        - pcap_file: packet capture file to be processed
        Output:
        - This function doesn't return anything, but it creates a pcap file
          with the new IP/MAC addresses
        '''

        packets = rdpcap(pcap_file)
        new_packets = [] # stores each packet as it's processed

        # Loop through each individual packet in the pcap file
        for p in packets:
            # Process one packet at a time, add result to list of new packets
            new_packets.append(self.process_one_packet(p, pcap_file))
        
        # Write new pcap file 
        new_filename = pcap_file[:len(pcap_file) - 5] + "_new.pcap"
        wrpcap(new_filename, new_packets)

    def format_hex(self, string):
        '''Format string into hex
        Inputs: 
        - string: given string to change into needed hex format
        Outputs:
        - string: string without the 0x part of the hex as well as exactly
          two digits 
        Examples:
        - given '0x5f', this method will return '5f'
        - given '0xf', this method will return '0f'
        '''
        
        # Get rid of leading 0x
        string = string.replace("0x", "")

        # Pad with zero if necessary
        if len(string) < 2:
            string = "0" + string
        return string

    def process_basics(self, pcap_file):
        ''' Changes IP/MAC addresses in original packet to new addresses.
            Also updates checksums.
        Inputs:
        - pcap_file: file of one individual packet to change 
        Outputs:
        - pkt: the first packet in given pcap_file with new addresses
        '''

        pkt = rdpcap(pcap_file)[0]

        # Change IP/MAC addresses
        pkt[IP].src = self.src_ip
        pkt[IP].dst = self.dst_ip
        pkt[Ether].src = self.src_mac
        pkt[Ether].dst = self.dst_mac

        # Update checksums
        del pkt[IP].chksum

        #del pkt[UDP].chksum
        pkt = pkt.__class__(str(pkt))
        return pkt

    def ip_to_hex(self, ip, orig):
        '''Changes list of IP addresses into regex strings for later use.
        Inputs:
        - ip: list of hex'd IP addresses separated out
        - orig: 0 means given IP address is a new IP address that needs to 
                replace an IP address in the pcap file
                1 means given IP address is an original IP address found in
                the pcap file
        Outputs:
        - regex: string that will match to IP address
        Examples:
        - ip: ['0a', '03', '00', '15'] -> this would have been '10.3.0.100' in
          the original configuration file
        '''

        ip_hex = ip.split(".")
        regex = r''
    
        # Loop through each part of the IP list
        for ind in range(len(ip_hex)):
            ip_hex[ind] = self.format_hex(str(hex(int(ip_hex[ind]))))
            if not orig:
                regex += ip_hex[ind] + " \g<" + str(ind * 2 + 2) + ">" 
            else:
                regex += "(" + ip_hex[ind] + " )" + "(|\s{2}.{16}\\n00[0-9a-f]0\s{2})?"

        # Take off the last regex group
        if not orig:
            regex = regex[:-5]
        else:
            regex = regex[:-32]

        return regex

    def find_and_replace(self, orig, new, contents):
        '''Finds and replaces orig with new in contents'''
        return re.sub(orig, new, contents)

    def process_udp_payload(self, pkt, pcap_file):
        '''Change IP addresses in the payload part of packets.
        Input:
        - pkt: individual packet
        - pcap_file: original pcap file provided
        Output:
        - new_pcap_file: new pcap file with new IP addresses 
        '''

        # Change original IP addresses into hex
        src_ip_hex = self.ip_to_hex(self.src_ip, 0)
        dst_ip_hex = self.ip_to_hex(self.dst_ip, 0)
        orig_src_hex = self.ip_to_hex(pkt[IP].src, 1)
        orig_dst_hex = self.ip_to_hex(pkt[IP].dst, 1)

        # Use tshark to read the hex so can change the UDP payload
        old_file_name = pcap_file.replace("pcap", "txt")
        os.system("tshark -x -r " + pcap_file + " &> " + old_file_name)
        new_file = open(old_file_name, "r")
        contents = new_file.read()
        new_file.close()

        # Replace IP addresses in payload
        contents = self.find_and_replace(orig_src_hex, src_ip_hex, contents)
        contents = self.find_and_replace(orig_dst_hex, dst_ip_hex, contents)

        # Write new text file with updated content
        new_txt_file = pcap_file[0:len(pcap_file) - 5] + "_new.txt"
        new_file = open(new_txt_file, "w")
        new_file.write(contents)
        new_file.close()

        # Change text file back into a pcap file
        new_pcap_file = new_txt_file.replace("txt", "pcap")
        os.system("text2pcap " + new_txt_file + " " + new_pcap_file)
        os.system("rm " + old_file_name)
        os.system("rm " + new_txt_file)

        return new_pcap_file

    def process_one_packet(self, pkt, pcap_file):
        '''Process one packet at a time.
         Input:
        - pkt: individual packet
        - pcap_file: original pcap file provided
        Output:
        - pkt: finished packet with IP addresses changed to new ones
        '''

        new_pcap_file = self.process_udp_payload(pkt, pcap_file)
        pkt = self.process_basics(new_pcap_file)
        return pkt

p = ProcessPacket()
