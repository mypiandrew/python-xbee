#! /usr/bin/python
"""
test_base.py

By Paul Malmsten, 2010
pmalmsten@gmail.com

Tests the XBeeBase superclass module for XBee API conformance.
"""
import unittest
from xbee.thread.base import XBeeBase
from xbee.tests.Fake import Serial


class TestReadFromDevice(unittest.TestCase):
    """
    XBeeBase class should properly read and extract data from a valid
    API frame
    """

    def test_read(self):
        """
        _wait_for_frame should properly read a frame of data
        """
        device = Serial()
        device.set_read_data(b'\x7E\x00\x01\x00\xFF')
        xbee = XBeeBase(device)

        frame = xbee._wait_for_frame()
        self.assertEqual(frame.data, b'\x00')

    def test_read_invalid_followed_by_valid(self):
        """
        _wait_for_frame should skip invalid data
        """
        device = Serial()
        device.set_read_data(b'\x7E\x00\x01\x00\xFA' + b'\x7E\x00\x01\x05\xFA')
        xbee = XBeeBase(device)

        frame = xbee._wait_for_frame()
        self.assertEqual(frame.data, b'\x05')

    def test_read_escaped(self):
        """
        _wait_for_frame should properly read a frame of data
        Verify that API mode 2 escaped bytes are read correctly
        """
        device = Serial()
        device.set_read_data(
            b'\x7E\x00\x04\x7D\x5E\x7D\x5D\x7D\x31\x7D\x33\xE0')

        xbee = XBeeBase(device, escaped=True)

        frame = xbee._wait_for_frame()
        self.assertEqual(frame.data, b'\x7E\x7D\x11\x13')


if __name__ == '__main__':
    unittest.main()
