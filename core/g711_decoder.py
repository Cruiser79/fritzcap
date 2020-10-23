#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
##################################################################################
# Simple FritzCap python port
# Simplifies generation and examination of traces taken from AVM FritzBox and/or SpeedPort
# Traces can be examined using WireShark
# (c) neil.young 2010 (spongebob.squarepants in http://www.ip-phone-forum.de/)
# based on the Windows GUI exe with same name
##################################################################################
# Copyright (c) 2010, neil.young
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the <organization> nor the
#      names of its contributors may be used to endorse or promote products
#      derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##################################################################################

import struct, datetime, array, os, subprocess

from log import Log


''' Class strips G.711 audio RTP streams from a PCAP file and extracts the audio to separate streams, mixes on demand '''
class G711Decoder:

    # Packet lengths we recognize
    lenmap = [
          # PacketLength, AudioChunkLength, Offset of audio data, descriptive text
          {'len': 306, 'chunk': 240, 'offs': 66, 'encap' : 'VDSL' },        # VDSL
          {'len': 226, 'chunk': 160, 'offs': 66, 'encap' : 'VDSL' },        # VDSL
                                                                            # VDSL ComfortNoise ?? not seen yet

          {'len': 232, 'chunk': 160, 'offs': 72, 'encap' : 'DSLPPPoE' },    # DSL (PPPoE)
          {'len': 312, 'chunk': 240, 'offs': 72, 'encap' : 'DSLPPPoE' },    # DSL (PPPoE)
          {'len': 73,  'chunk': 0,   'offs': 72, 'encap' : 'DSLPPPoE' },    # DSL (PPPoE) ComfortNoise

          {'len': 214, 'chunk': 160, 'offs': 54, 'encap' : 'DSLETH'  },     # DSL (ETH)
          {'len': 294, 'chunk': 240, 'offs': 54, 'encap' : 'DSLETH'  },     # DSL (ETH)
          {'len': 55,  'chunk': 0,   'offs': 54, 'encap' : 'DSLETH'  },     # DSL (ETH) ComfortNoise
          {'len': 236, 'chunk': 160, 'offs': 76, 'encap' : 'DSLPPPoE' }, # DSL (PPPoE)
    ]

    # Table lookup G.711 A -> PCM 16
    alaw2linear = array.array('h', [
          -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736,
          -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784,
          -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368,
          -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392,
         -22016,-20992,-24064,-23040,-17920,-16896,-19968,-18944,
         -30208,-29184,-32256,-31232,-26112,-25088,-28160,-27136,
         -11008,-10496,-12032,-11520, -8960, -8448, -9984, -9472,
         -15104,-14592,-16128,-15616,-13056,-12544,-14080,-13568,
           -344,  -328,  -376,  -360,  -280,  -264,  -312,  -296,
           -472,  -456,  -504,  -488,  -408,  -392,  -440,  -424,
            -88,   -72,  -120,  -104,   -24,    -8,   -56,   -40,
           -216,  -200,  -248,  -232,  -152,  -136,  -184,  -168,
          -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
          -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696,
           -688,  -656,  -752,  -720,  -560,  -528,  -624,  -592,
           -944,  -912, -1008,  -976,  -816,  -784,  -880,  -848,
           5504,  5248,  6016,  5760,  4480,  4224,  4992,  4736,
           7552,  7296,  8064,  7808,  6528,  6272,  7040,  6784,
           2752,  2624,  3008,  2880,  2240,  2112,  2496,  2368,
           3776,  3648,  4032,  3904,  3264,  3136,  3520,  3392,
          22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944,
          30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136,
          11008, 10496, 12032, 11520,  8960,  8448,  9984,  9472,
          15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568,
            344,   328,   376,   360,   280,   264,   312,   296,
            472,   456,   504,   488,   408,   392,   440,   424,
             88,    72,   120,   104,    24,     8,    56,    40,
            216,   200,   248,   232,   152,   136,   184,   168,
           1376,  1312,  1504,  1440,  1120,  1056,  1248,  1184,
           1888,  1824,  2016,  1952,  1632,  1568,  1760,  1696,
            688,   656,   752,   720,   560,   528,   624,   592,
            944,   912,  1008,   976,   816,   784,   880,   848
    ])

    # Table lookup G.711 A -> PCM 16
    ulaw2linear = array.array('h', [
       -32124,-31100,-30076,-29052,-28028,-27004,-25980,-24956,
       -23932,-22908,-21884,-20860,-19836,-18812,-17788,-16764,
       -15996,-15484,-14972,-14460,-13948,-13436,-12924,-12412,
       -11900,-11388,-10876,-10364, -9852, -9340, -8828, -8316,
        -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
        -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
        -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
        -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
        -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
        -1372, -1308, -1244, -1180, -1116, -1052,  -988,  -924,
         -876,  -844,  -812,  -780,  -748,  -716,  -684,  -652,
         -620,  -588,  -556,  -524,  -492,  -460,  -428,  -396,
         -372,  -356,  -340,  -324,  -308,  -292,  -276,  -260,
         -244,  -228,  -212,  -196,  -180,  -164,  -148,  -132,
         -120,  -112,  -104,   -96,   -88,   -80,   -72,   -64,
          -56,   -48,   -40,   -32,   -24,   -16,    -8,     0,
        32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
        23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
        15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
        11900, 11388, 10876, 10364,  9852,  9340,  8828,  8316,
         7932,  7676,  7420,  7164,  6908,  6652,  6396,  6140,
         5884,  5628,  5372,  5116,  4860,  4604,  4348,  4092,
         3900,  3772,  3644,  3516,  3388,  3260,  3132,  3004,
         2876,  2748,  2620,  2492,  2364,  2236,  2108,  1980,
         1884,  1820,  1756,  1692,  1628,  1564,  1500,  1436,
         1372,  1308,  1244,  1180,  1116,  1052,   988,   924,
          876,   844,   812,   780,   748,   716,   684,   652,
          620,   588,   556,   524,   492,   460,   428,   396,
          372,   356,   340,   324,   308,   292,   276,   260,
          244,   228,   212,   196,   180,   164,   148,   132,
          120,   112,   104,    96,    88,    80,    72,    64,
           56,    48,    40,    32,    24,    16,     8,     0
    ])


    ''' Constructor '''
    def __init__(self, capfile, mix=1, linearize=1):
        self.mix = mix
        self.file = capfile.split('.')[0]
        self.linearize = linearize

        # Stream descriptor array
        self.sda = []

        self.logger = Log().getLogger()


    ''' Write RIFF header '''
    def write_RIFF_header(self, sd):
        sd['fo'].seek(0,0)
        # Write RIFF header
        sd['fo'].write(struct.pack("<BBBBLBBBBBBBBBBBBHHLLHHBBBBBBBBBBLBBBBL",
                0x52, 0x49, 0x46, 0x46,                                 # 'RIFF'
                (sd['blockalign'] * sd['nr_samples']) + 50,             # total file size (data + sizeof(waveheader) - 8)
                0x57, 0x41, 0x56, 0x45, 0x66, 0x6d, 0x74, 0x20,         # 'WAVEfmt '
                0x12, 0x00, 0x00, 0x00,                                 # chunk data size
                sd['format'],                                           # format tag
                sd['channels'],                                         # number of channels
                sd['samplerate'],                                       # sample rate in Hz = 8000
                sd['samplerate'] * sd['blockalign'],                    # avg bytes per second equals to sample rate for 8 bit, twice sample rate for 16 bit
                sd['blockalign'],                                       # blockalign
                sd['bitspersample'],                                    # significant bits per sample
                0x00, 0x00,                                             # extra format bytes
                0x66, 0x61, 0x63, 0x74,                                 # 'fact'
                0x04, 0x00, 0x00, 0x00,                                 # chunk data size
                sd['nr_samples'],                                       # fact chunk, unsigned long #samples, offset 46
                0x64, 0x61, 0x74, 0x61,                                 # 'data'
                sd['blockalign'] * sd['nr_samples'],                    # data chunk, unsigned long #samples in byte, offset 54
                )
        )


    ''' Find the SSI in our stream descriptor array. If not found, allocate a new entry '''
    def find_sd_slot(self, ssi):
        # Search SSI. Slot already allocated?
        for i in range(len(self.sda)):
            if self.sda[i]['ssi'] == ssi:
                return self.sda[i]
        # Not found, allocate a new slot
        i = len(self.sda)
        self.sda.append({
                         'ssi' : ssi,
                         'index' : i,
                         'errors' : 0,
                         'nr_samples': 0,
                         })
        return self.sda[i]

    ''' Decoder, capable of extracting and mixing G.711 audio streams from a packet capture file '''
    def decode(self, time_sec, time_usec, packet, len):
        # This is a simple parser. The payload is not fully decoded. Instead some assumptions based upon the
        # length of the captured package are checked
        for candidate in self.lenmap:
            if len == candidate['len']:
                # Read 12 byte RTP header data in front of the audio payload and analyze it
                # Important: SSI (Synchronization Source Identifier), sequence number, payload type and timestamp
                (streamsetup, payloadtype, seqnr, timestamp, ssi) = struct.unpack('>BBHLL', packet[candidate['offs']-12 : candidate['offs']])

                # Probably we need some more assertions here, but up to now it worked well
                if payloadtype not in [8, 0, 13]:
                    self.logger.debug('Unsupported payload type %s' % payloadtype)
                    return

                # Find the SSI of current stream in stream descriptor array. If not contained, allocate a slot and add it
                sd = self.find_sd_slot(ssi)
                # Set time of first appearance of this particular stream
                if not sd.has_key('first_seen_at'):
                    sd['first_seen_at'] =  datetime.datetime.fromtimestamp(time_sec) + datetime.timedelta(microseconds = time_usec)
                    # Take over ip source/destination information
                    (src_ip, dst_ip) = struct.unpack('>LL', packet[candidate['offs']-28 : candidate['offs']-20])
                    (src_port, dst_port) = struct.unpack('>HH', packet[candidate['offs']-20 : candidate['offs']-16])
                    sd['source'] = str(src_ip) + str(src_port)
                    sd['destination'] = str(dst_ip) + str(dst_port)
                    sd['payloadtype'] = payloadtype
                    sd['chunksize'] = candidate['chunk']

                    sd['channels'] = 1                  # Mono in any case
                    sd['samplerate'] = 8000             # 8kHz

                    if self.linearize:
                        sd['format'] = 1                # PCM
                        sd['bitspersample'] = 16        # 16 bit
                    else:
                        sd['format'] = 6                # CCITT G.711 A default
                        if sd['payloadtype'] == 0:
                            sd['format'] = 7            # CCITT G.711 u
                        sd['bitspersample'] = 8         # 8 bit

                    sd['blockalign'] = sd['bitspersample'] / 8 * sd['channels']

                    # Open target file for stream
                    sd['fo'] = open("%s_%d_.wav" % (self.file, sd['index']), 'wb+')

                    # Reserve place for RIFF header
                    self.write_RIFF_header(sd)

                # Do we already have received a sequence number? If yes, check whether we are in sequence
                if sd.has_key('expected') and seqnr != sd['expected']:
                    sd['errors'] += 1
                    lost = abs(sd['expected']-seqnr)
                else:
                    lost = 0

                # Advance sequence number
                sd['expected'] = (seqnr + 1) & 0xFFFF

                # Comfort Noise?
                if payloadtype == 13:
                    if not sd.has_key('ts_cn'):
                        sd['ts_cn'] = timestamp # Indicates the number of samples
                        return                  # Just react on the first seen CN packet
                else:
                    # Was there a CN sequence before?
                    if sd.has_key('ts_cn'):
                        pad = array.array('B', (0 for i in range(sd['blockalign']*(timestamp - sd['ts_cn'])))) # Silence
                        sd['fo'].write(pad)
                        sd['nr_samples'] += timestamp - sd['ts_cn']
                        del sd['ts_cn']

                # Something lost? Pad with silence
                while lost > 0:
                    pad = array.array('B', (0 for i in range(sd['blockalign']*candidate['chunk'])))
                    sd['fo'].write(pad)
                    sd['nr_samples'] += candidate['chunk']
                    lost -= 1

                # Write the audio out off the packet, this is LAME!!!
                start = candidate['offs']
                end = candidate['offs']+candidate['chunk']

                # This takes a lot of time...
                if payloadtype == 8:
                    if self.linearize:
                        audio = array.array('h', (self.alaw2linear[ord(packet[i])] for i in range(start,end)))
                    else:
                        audio = array.array('B', (ord(packet[i]) for i in range(start,end)))
                else:
                    if self.linearize:
                        audio = array.array('h', (self.ulaw2linear[ord(packet[i])] for i in range(start,end)))
                    else:
                        audio = array.array('B', (ord(packet[i]) for i in range(start,end)))

                sd['fo'].write(audio)
                sd['nr_samples'] += candidate['chunk']
                return

    ''' Finalize the extracted audio wav files '''
    def finalize(self):
        sdfound = []
        # Finalize wave file, patch header
        for sd in self.sda:
            # Finalize RIFF header
            self.write_RIFF_header(sd)

            if self.mix:
                # Find associated streams to mix
                for sdother in self.sda:
                    if sd['source'] == sdother['destination'] and sdother['source'] == sd['destination']:
                        if sd['index'] not in sdfound and sdother['index'] not in sdfound:

                            # Prevent second find
                            sdfound.append(sd['index'])
                            sdfound.append(sdother['index'])

                            # Check: Input linearized already?
                            if not self.linearize:
                                self.logger.error("Can't mix streams that are not linearized")
                                break

                            self.logger.debug("Streams %d (ssi=%d) and %d (ssi=%d) are belonging together" % (sd["index"], sd['ssi'], sdother['index'], sdother['ssi']))

                            # Calculate deltaT between both streams
                            timediff = abs(sd['first_seen_at']-sdother['first_seen_at'])
                            if sd['first_seen_at'] <= sdother['first_seen_at']:
                                leader = sd
                                follower = sdother
                            else:
                                leader = sdother
                                follower = sd

                            # Calculate missing samples for follower and resulting total sample count for the mix (125 usec per sample at 8000 Hz)
                            follower_samples_behind = int((timediff.seconds*1000000.0 + timediff.microseconds)  / 125)

                            total_samples = follower_samples_behind + max(leader['nr_samples'] - follower_samples_behind, follower['nr_samples'])

                            self.logger.debug("Stream %d is %s h behind stream %d (delta=%d samples). Total samples: %d" % (follower['index'], timediff, leader['index'], follower_samples_behind, total_samples))

                            # Open mix file
                            sdmix = {'channels':1, 'samplerate':8000, 'format':1, 'bitspersample':16, 'blockalign':2, 'nr_samples':total_samples}
                            sdmix['fo'] = open("%s_mix_%d_%d.wav" % (self.file, leader['index'], follower['index']), 'wb+')
                            self.write_RIFF_header(sdmix)

                            # Seek both files to start of audio data (skip RIFF header)
                            leader['fo'].seek(58, 0)
                            follower['fo'].seek(58, 0)

                            self.logger.debug("leader: %d, follower: %d, total: %d, follower_behind: %d" % (leader['nr_samples'], follower['nr_samples'], total_samples, follower_samples_behind))

                            # Write trailing overhead from leader first
                            sdmix['fo'].write(leader['fo'].read(leader['blockalign']*follower_samples_behind))

                            total_samples_written = follower_samples_behind

                            # Calculate the count of samples which have to be mixed from both sources
                            mixed_cnt = min(leader['nr_samples'] - follower_samples_behind, follower['nr_samples'])

                            self.logger.debug("Mixed samples count: %d" % mixed_cnt)

                            # Mix it, save it
                            for sample in range(0, mixed_cnt):
                                # Read sample, -3 db
                                leader_sample = float(struct.unpack("<h", leader['fo'].read(leader['blockalign']))[0]) * 0.707
                                follower_sample = float(struct.unpack("<h", follower['fo'].read(follower['blockalign']))[0]) * 0.707
                                # Add both samples
                                sum = leader_sample + follower_sample
                                # Clamp to prevent integer overflow
                                if sum > 32767:
                                    sum = 32767
                                elif sum < - 32768:
                                    sum = -32768
                                # Write the sum. Would be faster to write it into an array here and flush that to disk afterwards
                                # But the array could blow the memory, hence we write it as we have it
                                sdmix['fo'].write(struct.pack("<h", sum))

                            total_samples_written += mixed_cnt

                            # Handle the remaining rest, wherever a rest is
                            leader_rest = leader['nr_samples'] - follower_samples_behind - mixed_cnt
                            follower_rest = follower['nr_samples'] - mixed_cnt

                            if leader_rest:
                                tmp = leader['fo'].read(leader['blockalign']*leader_rest)
                                sdmix['fo'].write(tmp)
                                total_samples_written += leader_rest
                                self.logger.debug("Rest taken from leader: %d" % leader_rest)
                            else:
                                if follower_rest:
                                    tmp = follower['fo'].read(follower['blockalign']*follower_rest)
                                    sdmix['fo'].write(tmp)
                                    total_samples_written += follower_rest
                                    self.logger.debug("Rest taken from follower: %d" % follower_rest)
                            sdmix['fo'].close()
                            duration_in_seconds = int((total_samples_written * 125) / 1000000.0)
                            self.logger.debug("Total mixed samples written: %d (duration %s h)" % (total_samples_written,  str(datetime.time(duration_in_seconds // 3600, (duration_in_seconds % 3600) // 60, duration_in_seconds % 60))))
            # Close
            sd['fo'].close()
            os.remove("%s_%d_.wav" % (self.file, sd['index']))
        sdmixWav = "%s_mix_%d_%d.wav" % (self.file, leader['index'], follower['index'])
        cmd = 'lame --quiet --preset insane %s' % sdmixWav
        subprocess.call(cmd, shell=True)
        os.remove(sdmixWav)
