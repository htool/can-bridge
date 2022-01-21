#!/usr/bin/python

import os
import io
import sys
import asyncio
import subprocess
import can
import binascii
import socket
import codecs

# Local CANoe port
host = '127.0.0.1'
port = 8086
# port = 8080

time = '000000'

sys.stderr.write("Starting 'candump can0'\n" )
bus = can.Bus(channel='can0', interface='socketcan')

sys.stderr.write("Starting /dev/can0 listener.\n" )

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
	# Read can0 interface
  message = bus.recv()
  if len(message) > 0:
    if message.is_error_frame != True:
      can0_msg = repr(message) + '\n'
      print('CAN0:   ' + can0_msg)
      can0_id = int(message.arbitration_id)
      # sys.stderr.write(str(can0_id) + '\n')
      can0_id = '{:08x}'.format(can0_id)
      # sys.stderr.write(can0_id + '\n')
      can0_id = can0_id[6:8] + can0_id[4:6] + can0_id[2:4] + can0_id[0:2]
      # sys.stderr.write(can0_id + '\n')
      can0_data = message.data.hex()
      can0_length = '0' + str(len(can0_data)/2)
      #print ('<CANoe: ' + can0_id + ' ' + can0_length + ' ' + time + ' ' + can0_data+ '\n')
      can0_hex = can0_id + '08' + time + can0_data
      print ('<CANoe: ' + can0_hex + '\n')
      can0_bytes = bytearray.fromhex(can0_hex)
      # sys.stderr.write('<CANoe: ' + repr(can0_bytes) + '\n')
      # Write can0 to /dev/can0
      # os.write(0, can0_bytes)
      # Write can0 to CANoe
      try:
        mySocket.send(can0_bytes)
      except:
        pass

#  try:
#    print ("Try to do os.read")
#    dev_data = os.read(dev, 16)
#    if len(dev_data) > 0:
#      print ("DEV:  " + dev_data.hex())
#  except: 
#    True
#
#  print ("End of loop")

#  # Read /dev/can0
#  devcan0 = os.read(0, 16)
#  sys.stderr.write('>DevCAN: ' + repr(devcan0) + '\n')
#  if len(devcan0) > 0:
#    hex = (" ".join(["{:02x}".format(x) for x in devcan0])).upper().split()
#    msg1 = '>DevCAN: ' + ' '.join(hex) + '\n'
#    sys.stderr.write(msg1)
#    # msg = "DevCAN: can0  " + hex[7] + hex[6] + hex[5] + hex[4] + "     [8]  " + ' '.join(hex[8:16]) + "\n"
#    msg_hex = hex[7] + hex[6] + hex[5] + hex[4] + ''.join(hex[8:16])
#    sys.stderr.write('>DevCAN: ' + msg_hex + '\n')
#    sys.stdout.write(msg_hex)

  try:
    data = mySocket.recv(16)
    if len(data) > 0:
      data = binascii.hexlify(data).decode()
      print (">CANoe: " + repr(data))
      # 0332ff8c08caefb47d990000ffffffff
      time = data[10:16]
      packet_id = int(data[6:8]+data[4:6]+data[2:4]+data[0:2],16)
      if packet_id != 0:
        # print (">CANoe: packet_id: " + repr(packet_id))
        packet_data = []
        for n in range(0,8):
          packet_hex = data[16+(n*2):18+(n*2)]
          packet_int = int(packet_hex, 16)
          packet_data.append(packet_int)
        # print (">CANoe: packet_data: " + repr(packet_data))
        packet = can.Message(arbitration_id=packet_id, data=packet_data, is_extended_id=True)
        try:
          bus.send(packet)
          # print("Message " + repr(packet) + " sent on {}".format(bus.channel_info))
        except can.CanError:
          print("Message NOT sent")
        #print (">CANoe: " + data + ' = ' + packet)
  except:
    try:
      mySocket.connect((host,port))
    except:
      pass
