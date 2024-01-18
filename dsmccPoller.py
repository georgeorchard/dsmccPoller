#from bitstring import BitArray
from sys import argv
import struct
import base64
import sys
import binascii
import subprocess
import io
import os
from datetime import datetime
import xml.etree.ElementTree as ET
#import hexdump
import pkgutil
import re

applicationVersionNumber = "1.0.0"
version_count=1
cont_count = 1

def calculate_section_crc(section):
    """
    A function that calculates the CRC of a section
    
    Parameters:
    section (string): String of Hex Bytes
    
    Returns:
    int: 32-bit integer of the CRC value
    """

    # Convert section from hex string to bytes
    section_bytes = section # bytes.fromhex(section)
    
    # Initialize the CRC value
    crc = 0xFFFFFFFF

    # CRC-32 polynomial
    polynomial = 0x04C11DB7

    # Calculate the CRC
    for byte in section_bytes:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc <<= 1
                crc ^= (-1 & polynomial)
            else:
                crc <<= 1
    
    # Convert the CRC value to hex string
    crc_hex = hex(crc & 0xFFFFFFFF)[2:].zfill(8).upper()
    #print ("Calculated CRC:", crc_hex)
    return (crc & 0xFFFFFFFF)
    

        
        
        
        

def sendStuffedPacket(output_stream):
    """
    A function to send a stuffed packet to an Output Stream
    
    Parameters:
    output_stream (file): The output stream
    
    Returns:
    null
    """
    stuffed_packet = bytes ([0x47])
    stuffed_packet += b'\x1F\xFF\x10'
    stuffed_packet += b'\xFF' * 184
    output_stream.write(stuffed_packet) 
    
    
    
    

    

    
    
    
    
def buildDSMCCPacket(scte35_payload, version_count, packet, cont_count):
    """
    Function to build a DSMCC Payload from the SCTE Payload
    
    Arguments:
    scte35_payload (packet[]): The payload packets of the SCTE35
    version_count (int): The version of the DSMCC payload
    packet (packet): The SCTE35 packet.
    cont_count (int): The continuity counter.
    
    Returns:
    Byte[]: DSMCC Packet
    """
    """
    print("v "+ str(version_count))
    print("c "+str(cont_count))
    """
    #print ("\nBuilding Descriptor with SCTE payload")
    
    
    #DESCRIPTOR LIST SECTION - SPLICE INFORMATION - [A178-1r1_Dynamic-substitution-of-content  Table 3] - This information just goes before the SCTE35 data

    #24 bits
    #8 bits: DVB_data_length
    #3 bits: reserved for future use
    #1 bit: event type
    #4 bits: timeline type
    #8 bits: private data length
    dsm_descriptor = bytes ([
    0x01   ,             # length of header
    0xE1 ,                # RRR/Event type 0/ timeline type 0001
    0                 # length of private dats
    ])
    #add the SCTE35 payload to the private data byte
    dsm_descriptor += scte35_payload

    # Base64 encode the SCTE35 payload
    encoded_payload = base64.b64encode(dsm_descriptor) 


   
    
    
    #DATA IN BEFORE DSMCC SECTION FORMAT - STREAM DATA
    #8 bits
    dsmcc_packet = bytes ([0x47])
    
    #Next 16 bits from the packet, contains PID!
    dsmcc_packet += packet [1:3]
    #print(packet[1:3])
    
    #8 bits
    byte4 = cont_count | 0x10
    dsmcc_packet += byte4.to_bytes (1, 'big')
    
    
    
    
    
    #DSMCC PACKET SECTION - [ISO/IEC 13818-6:1998  Table 9-2]
    
    #Length of DSM-CC Packet
    #4 is the data that goes in before the table_id (stream data)
    
    #6 (should be 5) as this is the data after the dsmcc_section_length field and before we put the dsmcc descriptor field in
    #encoded payload is the splice information from SCTE35
    #4 (should be 12) as this is the length of the streamEventDescriptor without the private data bytes)
    
    #8 is the CRC_32
    dsmcc_len = 6 + len (encoded_payload) + 4 + 8 + 4   
    
    # 8 bits - Table ID
    # x3D means that section contains stream descriptors - [ISO/IEC 13818-6:1998  Table 9-3]
    dsmcc_packet += b'\x00\x3D'  
    
    
    #8 bits
    #1 bit: section_syntax_indicator
    #1 bit: private_indicator
    #2 bits: reserved
    #4 bits: start of DSMCC_section_length (length of everything after this field)
    dsmcc_siglen = dsmcc_len - 1
    dsmcc_packet += (((dsmcc_siglen & 0x0F00) >> 8) + 0xB0).to_bytes (1, 'big')
    
    #8 bits - rest of DSMCC_section_length
    dsmcc_packet += (dsmcc_siglen & 0x00FF).to_bytes (1, 'big')
    
    
    # TID Ext, do-it-now       ETSI TS 102 809 V1.2.1 / Section B32.  TID Ext = EventId 1 (14 bits), Bits 14/15 zero = 0x0001
    #16 bits - table_id_extension (do-it-now)
    dsmcc_packet += b'\x00\x01'
    
    
    # Version 1 (RR/VVVVV/C)   RR / 5 BIts of Version number / Current/Next indicator (always 1)   Version 1 = 11000011 = C3
    #Mask version count to 5 bits so cycles round.
    version_count = version_count & 0b11111
    version_field = 0xC0 + (version_count << 1 ) + 0x01  # Build RR/VVVVV/C
    
    #8 bits 
    #2 bits: reserved
    #5 bits: version_number
    #1 bit: current_next_indicator
    dsmcc_packet += (version_field & 0x00FF).to_bytes (1, 'big')
    #dsmcc_packet += b'\xC3'
    
   
    #16 bits 
    #8 bits: section
    #8 bits: last section
    dsmcc_packet += b'\x00\x00'

    
    
    
    #STREAM EVENT DESCRIPTOR SECTION - [ISO/IEC 13818-6:1998  Table 8-6]
    #8 bits - descriptorTag - x1a = 26 which is Stream Event Descriptor
    dsmcc_packet += b'\x1a'
    
    #8 bits - Descriptor length (think this should be 10 + len(encoded_payload))
    dsmcc_payload_len = len (encoded_payload) + 4
    dsmcc_packet += (dsmcc_payload_len & 0x00FF).to_bytes (1, 'big') 
    
    
    #80 bits - rest of descriptor
    #16 bits: eventID
    #31 bits: reserved
    #33 bits: eventNPT
    dsmcc_packet += b'\x00\x01\xFF\xFF\xFF\xFE\x00\x00\x00\x00'

    #THE PRIVATE DATA BYTES THE SCTE SECTION - Add the SCTE35 payload into the DSMCC Packet
    dsmcc_packet += encoded_payload # DSM-CC Descriptor - SCTE35 payload
    
    
    
    #32 Bits - The CRC_32 Section as sectionSyntaxIndicator == 1 FINAL PART FROM [ISO/IEC 13818-6:1998  Table 9-2]
    dsmcc_crc = calculate_section_crc (dsmcc_packet [5:(dsmcc_len + 3)])                
    dsmcc_packet += dsmcc_crc.to_bytes (4, 'big')

    #Padding to make the packet it 188 bits.
    dsmcc_packet += b'\xFF' * (188-len (dsmcc_packet))

    return(dsmcc_packet)

    

def processFile(input_file, interval, count, pid):
    """
    Function to create the TS file based on the input file name, interval, and count
    Parameters:
    input_file(String): The file name
    interval(int): Time between packets (milliseconds)
    count(int): The count of packets
    pid(int): The PID to send on
    Returns: 
    None
    """
    #get that bitrate
    # Run the tsbitrate command and capture the output
    output = subprocess.check_output(['tsbitrate', input_file], text=True)

    # Use a regular expression to extract the bitrate value
    bitrate_match = re.search(r'TS bitrate: ([0-9,]+) b/s', output)
    
    if bitrate_match:
        bitrate_str = bitrate_match.group(1)
        # Remove commas and convert to an integer
        bitrate = int(bitrate_str.replace(',', ''))
        #print(bitrate)
    else:
        print("Bitrate not found in the output.")
        return None
    
    byteRate = bitrate/8
    packetRate = byteRate/188
    packetRateMs = int(packetRate//1000)
    #print(packetRateMs)
    
    nullPacketsBetween = packetRateMs*interval
    version_count = 1
    cont_count = 1
    with open(input_file, 'wb') as file:
        
        for i in range(0,count):
            bytesNumber = i.to_bytes(4, 'big')
            #find new PID for data packet
            dataPID = pid
            hex_dataPID = '0x{:04x}'.format(dataPID)
            #for the packet
            result = 'FF' + hex_dataPID[2:]  # Skip the '0x' prefix when concatenating
            result = bytes.fromhex(result)
            dsmcc_packet = buildDSMCCPacket(bytesNumber, version_count, result, cont_count)
            file.write(dsmcc_packet)
            for j in range(0,nullPacketsBetween):
                sendStuffedPacket(file)
            
            
    

    
if __name__ == "__main__":

    
    input_file = argv[1]
    
    if not(input_file.endswith(".ts")):
        input_file = input_file + ".ts"
    interval = int(argv[2])
    count = int(argv[3])
    pid = int(argv[4])
    processFile(input_file, interval, count, pid)
    
    
    
   

