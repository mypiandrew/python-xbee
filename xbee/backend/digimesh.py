"""
digimesh.py

By Matteo Lucchesi, 2011
Inspired by code written by Amit Synderman, Marco Sangalli and Paul Malmsten
matteo@luccalug.it http://matteo.luccalug.it

This module provides an XBee (Digimesh) API library.

Updated by Thom Nichols http://blog.thomnichols.org

Modified to support DigiMesh S8 SMT modules

"""


class DigiMesh(object):
    """
    Provides an implementation of the XBee API for DigiMesh modules
    with recent firmware.

    Commands may be sent to a device by instantiating this class with
    a serial port object (see PySerial) and then calling the send
    method with the proper information specified by the API. Data may
    be read from a device synchronously by calling wait_read_frame. For
    asynchronous reads, see the definition of XBeeBase.
    """
    # Packets which can be sent to an XBee

    # Format:
    #  {
    #    name of command: [
    #      {name: field name, len: field length, default: default value sent}
    #      ...
    #    ]
    #    ...
    #  }
    api_commands = {
        "at": [
            {'name': 'id',               'len': 1,      'default': b'\x08'},
            {'name': 'frame_id',         'len': 1,      'default': b'\x00'},
            {'name': 'command',          'len': 2,      'default': None},
            {'name': 'parameter',        'len': None,   'default': None}
        ],
        "queued_at": [
            {'name': 'id',               'len': 1,      'default': b'\x09'},
            {'name': 'frame_id',         'len': 1,      'default': b'\x00'},
            {'name': 'command',          'len': 2,      'default': None},
            {'name': 'parameter',        'len': None,   'default': None}
        ],
        # todo: Explicit Addressing Command Frame
        "remote_at": [
            {'name': 'id',               'len': 1,      'default': b'\x17'},
            {'name': 'frame_id',         'len': 1,      'default': b'\x00'},
            {'name': 'dest_addr_long',   'len': 8,      'default': None},
            {'name': 'reserved',         'len': 2,      'default': b'\xFF\xFE'},
            {'name': 'options',          'len': 1,      'default': b'\x02'},
            {'name': 'command',          'len': 2,      'default': None},
            {'name': 'parameter',        'len': None,   'default': None}
        ],
        "tx": [
            {'name': 'id',               'len': 1,      'default': b'\x10'},
            {'name': 'frame_id',         'len': 1,      'default': b'\x00'},
            {'name': 'dest_addr',        'len': 8,      'default': None},
            {'name': 'reserved',         'len': 2,      'default': b'\xFF\xFE'},
            {'name': 'broadcast_radius', 'len': 1,      'default': b'\x00'},
            {'name': 'options',          'len': 1,      'default': b'\x00'},
            {'name': 'data',             'len': None,   'default': None}
        ]
    }

    # Packets which can be received from an XBee

    # Format:
    #   {
    #       id byte received from XBee: {
    #           name: name of response
    #           structure: [
    #               {'name': name of field,     'len': length of field}
    #               ...
    #           ]
    #           parse_as_io_samples: name of field to parse as io
    #       }
    #       ...
    #   }
    api_responses = {
        b'\x88': {
            'name': 'at_response',
            'structure': [
                {'name': 'frame_id',          'len': 1},
                {'name': 'command',           'len': 2},
                {'name': 'status',            'len': 1},
                {'name': 'parameter',         'len': None}
            ],
            'parsing': [
                ('parameter', lambda self, original: self._parse_ND_at_response(original))  # ADDED 
            ]
        },
        b'\x8A': {
            'name': 'status',
            'structure': [
                {'name': 'status',            'len': 1}
            ]
        },
        b'\x8B': {
            'name': 'tx_status',
            'structure': [
                {'name': 'frame_id',          'len': 1},
                {'name': 'reserved',          'len': 2, 'default': b'\xFF\xFE'},
                {'name': 'retries',           'len': 1},
                {'name': 'deliver_status',    'len': 1},
                {'name': 'discover_status',   'len': 1}
            ]
        },
        b'\x90': {
            'name': 'rx',
            'structure': [
                {'name': 'source_addr',       'len': 8},
                {'name': 'reserved',          'len': 2},
                {'name': 'options',           'len': 1},
                {'name': 'data',              'len': None}
            ]
        },
        # todo: Explicit RX Indicator
        # b'\x91': {
        #     'name': 'explicit_rx_indicator',
        #     'structure': [
        #         {'name': 'source_addr',       'len': 2},
        #         {'name': 'rssi',              'len': 1},
        #         {'name': 'options',           'len': 1},
        #         {'name': 'rf_data',           'len': None}
        #     ]
        # },
        b'\x95': {
            'name': 'node_id',
            'structure': [
                {'name': 'source_addr_long',  'len': 8},
                {'name': 'network_addr',      'len': 2},
                {'name': 'options',           'len': 1},
                {'name': 'source_addr',       'len': 2},
                {'name': 'network_addr_long', 'len': 8},
                {'name': 'node_id',           'len': 'null_terminated'},
                {'name': 'parent',            'len': 2},
                {'name': 'unknown',           'len': None}]},

        b'\x97': {
            'name': 'remote_at_response',
            'structure': [
                {'name': 'frame_id',          'len': 1},
                {'name': 'source_addr',       'len': 8},
                {'name': 'reserved',          'len': 2},
                {'name': 'command',           'len': 2},
                {'name': 'status',            'len': 1},
                {'name': 'parameter',         'len': None}
            ],
            'parsing': [
                ('parameter', lambda self, original: self._parse_IS_at_response(original))  # Added
            ]
        }
    }

    def _parse_IS_at_response(self, packet_info):
        """
        If the given packet is a successful remote AT response for an IS
        command, parse the parameter field as IO data.
        """
        if packet_info['id'] in ('at_response', 'remote_at_response') and \
                packet_info['command'].lower() == b'is' and \
                packet_info['status'] == b'\x00':
            return self._parse_samples(packet_info['parameter'])
        else:
            return packet_info['parameter']

    def _parse_ND_at_response(self, packet_info):
        """
        If the given packet is a successful AT response for an ND
        command, parse the parameter field.
 
        Page 141 
        https://www.digi.com/resources/documentation/digidocs/pdfs/90002126.pdf
        """
        if packet_info['id'] == 'at_response' and \
                packet_info['command'].lower() == b'nd' and \
                packet_info['status'] == b'\x00':
            result = {}

            # Parse each field directly
            # MY<CR> (2 bytes) (always 0xFFFE)
            result['my'] = packet_info['parameter'][0:2]
            # SH<CR> (4 bytes)
            result['sh'] = packet_info['parameter'][2:6]
            # SL<CR> (4 bytes) Note: For some reason this often gets shown partially/fully as ASCII not Hex Bytes
            result['sl'] = packet_info['parameter'][6:10]
            # DB<CR> *Contains the detected signal strength of the response in negative dBm units) 
            # This docs page implies it's 1 byte, not explicitly specified in PDF manual. 
            # https://www.digi.com/resources/documentation/Digidocs/90001477/reference/r_cmd_db.htm?TocPath=AT%20commands%7CDiagnostic%20commands%7C_____2			
            # 0x28 - 0x6E (-40 dBm to -110 dBm) [read-only] 
            # ------------------------------------------------------------
            # Not included in the S8 Module I had
            #result['db'] = packet_info['parameter'][10] ## Assumption docs do not specify

            # NI <CR> (variable, 0-20 bytes plus 0x00 character)
            
            # First find the node identifier field null terminator
            null_terminator_index = 10
            while packet_info['parameter'][null_terminator_index:
                                           null_terminator_index+1] != b'\x00':
                null_terminator_index += 1
            # NI therefor is everything inbetween
            # try adding .decode("hex") to this 
            # https://stackoverflow.com/questions/9641440/convert-from-ascii-string-encoded-in-hex-to-plain-ascii
            result['node_identifier'] = \
                packet_info['parameter'][10:null_terminator_index]

            # PARENT_NETWORK ADDRESS<CR> (2 bytes)
            result['parent_address'] = \
                packet_info['parameter'][null_terminator_index+1:
                                         null_terminator_index+3]
            # DEVICE_TYPE<CR> (1 byte: 0 = Coordinator, 1 = Router, 2 = End Device)
            result['device_type'] = \
                packet_info['parameter'][null_terminator_index+3:
                                         null_terminator_index+4]
            # STATUS<CR> (1 byte: reserved)
            result['status'] = \
                packet_info['parameter'][null_terminator_index+4:
                                         null_terminator_index+5]
            # PROFILE_ID<CR> (2 bytes)
            result['profile_id'] = \
                packet_info['parameter'][null_terminator_index+5:
                                         null_terminator_index+7]
            # MANUFACTURER_ID<CR> (2 bytes)
            result['manufacturer'] = \
                packet_info['parameter'][null_terminator_index+7:
                                         null_terminator_index+9]

            # ********** These could be included in the response but are not by default  ****************
            # DIGI DEVICE TYPE<CR> (4 bytes. Optionally included based on NO settings.)
            #result['manufacturer'] = \
            #    packet_info['parameter'][null_terminator_index+9:
            #                             null_terminator_index+13]
            #
            # RSSI OF LAST HOP<CR> (1 byte. Optionally included based on NO settings.)
            #result['manufacturer'] = \
            #    packet_info['parameter'][null_terminator_index+13:
            #                             null_terminator_index+14]

            #  ********* Due to optional last two fields this approach is falible on digimesh devices **********
            # Simple check to ensure a good parse (assumes NO setting is as default (0) )
            if null_terminator_index+9 != len(packet_info['parameter']):
                raise ValueError("Improper ND response length: expected {0}, "
                                 "read {1} bytes".format(
                                     len(packet_info['parameter']),
                                     null_terminator_index+9)
                                 )

            return result
        else:
            return packet_info['parameter']


    def __init__(self, *args, **kwargs):
        """
        Call the super class constructor to save the serial port
        """
        super(DigiMesh, self).__init__(*args, **kwargs)

    def _parse_samples_header(self, io_bytes):
        """
        _parse_samples_header: binary data in XBee IO data format ->
                        (int, [int ...], [int ...], int, int)

        _parse_samples_header will read the first three bytes of the
        binary data given and will return the number of samples which
        follow, a list of enabled digital inputs, a list of enabled
        analog inputs, the dio_mask, and the size of the header in bytes

        _parse_samples_header is overloaded here to support the additional
        IO lines offered by the XBee S8 SMT Digimesh Module

        ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        Taken from Zigbee method but appears just as valid for digimesh

        Note the additional IO lines provided by the SPI interface (P5-P9) cannot 
        be read back/monitored these can be either SPI or Dig Out functions 
        only (not Dig in) 
        
        https://www.digi.com/resources/documentation/Digidocs/90001506/reference/r_queried_sampling.htm

        """
        header_size = 4

        # number of samples (always 1?) is the first byte
        sample_count = byteToInt(io_bytes[0])

        # bytes 1 and 2 are the DIO mask; bits 9 and 8 aren't used
        dio_mask = (byteToInt(io_bytes[1]) << 8 |
                    byteToInt(io_bytes[2])) & 0x1CFF

        # byte 3 is the AIO mask
        aio_mask = byteToInt(io_bytes[3])

        # sorted lists of enabled channels; value is position of bit in mask
        dio_chans = []
        aio_chans = []

        for i in range(0, 13):
            if dio_mask & (1 << i):
                dio_chans.append(i)

        dio_chans.sort()

        for i in range(0, 8):
            if aio_mask & (1 << i):
                aio_chans.append(i)

        aio_chans.sort()

        return (sample_count, dio_chans, aio_chans, dio_mask, header_size)
