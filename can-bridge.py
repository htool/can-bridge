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
import threading
import time

# Local CANoe port
host = '127.0.0.1'
port = 8086
# port = 8080

packet_time = 'caefb4'

sys.stderr.write("Starting 'candump can0'\n" )
bus = can.Bus(channel='can0', interface='socketcan', bitrate=125000)

sys.stderr.write("Starting /dev/can0 listener.\n" )

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  mySocket.connect((host,port))
except:
  pass

def int_can0_to_dev_can0():
  # Read interface can0 using python-can bus and write to /dev/can0 using CANoe tcp connection
  while True:
    message = bus.recv()
    if len(message) > 0:
	    if message.is_error_frame != True:
	      can0_msg = repr(message)
	      # print('CAN0:   ' + can0_msg)
	      can0_id = int(message.arbitration_id)
	      # sys.stderr.write(str(can0_id) + '\n')
	      can0_id = '{:08x}'.format(can0_id)
	      # sys.stderr.write(can0_id + '\n')
	      can0_id = can0_id[6:8] + can0_id[4:6] + can0_id[2:4] + can0_id[0:2]
	      # sys.stderr.write(can0_id + '\n')
	      can0_data = message.data.hex()
	      #print ('<CANoe: ' + can0_id + ' 08 ' + packet_time + ' ' + can0_data+ '\n')
	      can0_hex = can0_id + '08' + packet_time + can0_data
	      print ('<CANoe:  ' + can0_hex)
	      can0_bytes = binascii.a2b_hex(can0_hex)
	      # print('<CANoe: ' + repr(can0_bytes) + '\n')
	      # print('<CANoe: ' + str((binascii.b2a_hex(can0_bytes))) + '\n')
	      # Write can0 to CANoe
	      try:
	        mySocket.send(can0_bytes)
	      except:
	        pass
    time.sleep(0.001)


def dev_can0_to_int_can0():
  # read from /dev/can0 using CANoe tcp socket and write to interface can0 using python-can bus
  while True:
    try:
	    received = mySocket.recv(16)
	    if len(received) > 0:
	      data = binascii.hexlify(received).decode()
	      # print (">CANoe: " + repr(data))
	      # 0332ff8c08caefb47d990000ffffffff
	      packet_time_hex = data[10:16]
	      if int(packet_time_hex, 16) != 0:
	        packet_time = packet_time_hex
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
	        bus.send(packet)
	        try:
	          # bus.send(packet)
	          print(">CANoe: Message " + repr(packet))
	        except can.CanError:
	          print("Message NOT sent")
	        #print (">CANoe: " + data + ' = ' + packet)
    except:
	    try:
	      mySocket.connect((host,port))
	    except:
	      pass
    time.sleep(0.001)


if __name__ == "__main__":
  CANoe2can0 = threading.Thread(target=int_can0_to_dev_can0)
  can02CANoe = threading.Thread(target=dev_can0_to_int_can0)
  CANoe2can0.start()
  can02CANoe.start()


