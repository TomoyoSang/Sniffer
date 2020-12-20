from winpcapy import WinPcapUtils, WinPcap, WinPcapDevices
import threading
import time
import ctypes
import inspect
import dpkt.ethernet
import dpkt.tcp
import dpkt.udp
import dpkt.icmp
import dpkt.ip
import collections
import time
from PyQt5.QtWidgets import QMainWindow, QApplication, QTableWidget, QWidget, QTableWidgetItem
from PyQt5.QtCore import pyqtSignal


class Captor_Thread(threading.Thread):
    def __init__(self, threadID, name, ui, cur_filter, device_index):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.ui = ui
        self.cur_filter = cur_filter
        self.capture = None
        self.device_index = device_index
        self.contents = collections.OrderedDict()
        self.contents_hex = collections.OrderedDict()
        self.counter = 0
        self.cur_lineno = 0

        self.ui.tableWidget.clearContents()

        if len(self.cur_filter.SrcIp) == 0:
            self.FilterSrcIp = []
        else:
            self.FilterSrcIp = self.cur_filter.SrcIp.split('.')

        if len(self.cur_filter.DstIp) == 0:
            self.FilterDstIp = []
        else:
            self.FilterDstIp = self.cur_filter.DstIp.split('.')

        if len(self.cur_filter.SrcPort) == 0:
            self.FilterSrcPort = "F"
        else:
            self.FilterSrcPort = self.cur_filter.SrcPort

        if len(self.cur_filter.SrcIp) == 0:
            self.FilterDstPort = "F"
        else:
            self.FilterDstPort = self.cur_filter.DstPort

        self.FilterProtocol = self.cur_filter.Protocol


    def run(self):
        with WinPcap(device_names[self.device_index]) as capture:
            self.capture = capture
            self.capture.run(callback=self.capture_callback)

    def capture_callback(self, win_pcap, param, header, pkt_data):

        # dpkt_data = dpkt.ethernet.Ethernet(pkt_data)
        # if not isinstance(dpkt_data.data, dpkt.ip.IP):
        #     #print('Not IP')
        #     return

        ##获取时间戳
        local_tv_sec = header.contents.ts.tv_sec
        ltime = time.localtime(local_tv_sec)
        strTime = "%d:%d:%d" % (ltime.tm_hour, ltime.tm_min, ltime.tm_sec)
        ##MAC帧的长度
        cur_len = header.contents.caplen
        #print("len : %d  time : %d:%d:%d" % (cur_len, ltime.tm_hour, ltime.tm_min, ltime.tm_sec))

        # self.contents[ltime] = str(transf_data.data)
        # if self.counter == 0:
        #     self.ui.Text_Edit.append(str(transf_data.data))
        #     self.counter += 1

        ## MAC帧
        ## 前14字节 = 6源地址+6目的地址+2类型
        DstMac = str(pkt_data[0:6])
        SrcMac = str(pkt_data[6:12])
        MacType = pkt_data[12]*256 + pkt_data[13]

        ### IP报文
        if MacType == 0x0800:
            if self.FilterProtocol == 5:
                return
            ##  IP头
            ip_frame = pkt_data[14:]
            ## 4位版本+4位首部长度 + 8位服务类型 + 16位总长度
            IpVersion = (ip_frame[0] & 0b11110000)
            IpHeaderLen = (ip_frame[0] & 0xf) * 4
            IpTOS = ip_frame[1]
            IpTotalLen = (ip_frame[2] * 256 + ip_frame[3])
            IpIdentification = ip_frame[4]*256+ip_frame[5]
            Ip3bitNote = (ip_frame[6] & 0b11100000)
            IpFragmentOffset = ((ip_frame[6] * 256 + ip_frame[7]) & 0b0001111111111111)
            IpTTL = ip_frame[8]
            IpProtocol = ip_frame[9]
            IpHeaderChecksum = ip_frame[10] * 256 + ip_frame[11]
            # Parse ips
            src_ip = ".".join([str(b) for b in ip_frame[0xc:0x10]])
            dst_ip = ".".join([str(b) for b in ip_frame[0x10:0x14]])

            dotsrc = src_ip.split(".")
            dotdst = dst_ip.split(".")

            if len(self.FilterSrcIp) == 4:
                for i in range(4):
                    if int(self.FilterSrcIp[i]) != int(dotsrc[i]):
                        return
            if len(self.FilterDstIp) == 4:
                for i in range(4):
                    if int(self.FilterDstIp[i]) != int(dotdst[i]):
                        return

            header_info = ''
            header_info += "IpVersion: %d\t" % IpVersion
            header_info += "IpHeaderLen: %d\t" % IpHeaderLen
            header_info += "IpTOS: %d\t" % IpTOS
            header_info += "IpTotalLen: %d\t" % IpTotalLen
            header_info += "IpIdentification: %d\t" % IpIdentification
            header_info += "Ip3bitNote: %d\t" % Ip3bitNote
            header_info += "IpFragmentOffset: %d\t" % IpFragmentOffset
            header_info += "IpTTL: %d\t" % IpTTL
            header_info += "IpProtocol: %d\t" % IpProtocol
            header_info += "IpHeaderChecksum: %d\t" % IpHeaderChecksum


            ip_class = ''
            if IpProtocol == 1:
                ip_class = 'ICMP'
            elif IpProtocol == 6:
                ip_class = 'TCP'
            elif IpProtocol == 17:
                ip_class = 'UDP'
            # elif IpProtocol == 2:
            #     ip_class = 'IGMP'
            else:
                return
            str_to_show = "%s : %s -> %s" % (ip_class, src_ip, dst_ip)
            # self.ui.packet_text.append(str_to_show)

            ##内部协议头
            if IpTotalLen <= IpHeaderLen:
                return

            newItemTime = QTableWidgetItem(strTime)
            newItemSrc = QTableWidgetItem(str(src_ip))
            newItemDst = QTableWidgetItem(str(dst_ip))
            newItemProtocol = QTableWidgetItem(ip_class)

            ###UDP头部
            if ip_class == 'UDP':
                if self.FilterProtocol >= 3:
                    return
                udpfile = pkt_data[IpHeaderLen:]
                UdpSrcPort = udpfile[0] * 256 + udpfile[1]
                UdpDstPort = udpfile[2] * 256 + udpfile[3]
                UdpLen = udpfile[4] * 256 + udpfile[5]
                UdpChecksum = udpfile[6] * 256 + udpfile[7]
                if UdpLen == 8:
                    return
                if self.FilterSrcPort != "F":
                    if UdpSrcPort != int(self.FilterSrcPort):
                        return
                if self.FilterDstPort != "F":
                    if UdpDstPort != int(self.FilterDstPort):
                        return

                self.contents[ltime] = udpfile[8:]

                header_info += "UdpSrcPort: %d\t" % UdpSrcPort
                header_info += "UdpDstPort :%d\t" % UdpDstPort
                header_info += "UdpLen: %d\t" % UdpLen
                header_info += "UdpChecksum: %d\t" % UdpChecksum

                newItemDetails = QTableWidgetItem(str(udpfile[8:]))

                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)

                self.cur_lineno += 1
                #print(self.cur_lineno)


            ## TCP头部
            elif ip_class == 'TCP':
                if self.FilterProtocol == 2 or self.FilterProtocol == 4 or self.FilterProtocol == 5:
                    return

                tcpfile = pkt_data[IpHeaderLen:]
                TcpSrcPort = tcpfile[0] * 256 + tcpfile[1]
                TcpDstPort = tcpfile[2] * 256 + tcpfile[3]
                TcpSeqNum = ((tcpfile[4] * 256 + tcpfile[5]) * 256 + tcpfile[6]) * 256 + tcpfile[7]
                TcpAckNum = ((tcpfile[8] * 256 + tcpfile[9]) * 256 + tcpfile[10]) * 256 + tcpfile[11]
                TcpHeaderLen = tcpfile[12] & 0b11110000
                TcpURG = tcpfile[13] & 0b00100000
                TcpAck = tcpfile[13] & 0b00010000
                TcpPSH = tcpfile[13] & 0b00001000
                TcpRST = tcpfile[13] & 0b00000100
                TcpSYN = tcpfile[13] & 0b00000010
                TcpFIN = tcpfile[13] & 0b00000001
                TcpWinSize = tcpfile[14] * 256 + tcpfile[15]
                TcpChecksum = tcpfile[16] * 256 + tcpfile[17]
                TcpUrgentPointer = tcpfile[18] * 256 + tcpfile[19]
                if TcpHeaderLen == IpTotalLen - IpHeaderLen:
                    return
                if self.FilterSrcPort != "F":
                    if TcpSrcPort != int(self.FilterSrcPort):
                        return
                if self.FilterDstPort != "F":
                    if TcpDstPort != int(self.FilterDstPort):
                        return

                self.contents[ltime] = tcpfile[TcpHeaderLen:]

                header_info += "TcpSrcPort: %d\t" % TcpSrcPort
                header_info += "TcpDstPort: %d\t" % TcpDstPort
                header_info += "TcpSeqNum: %d\t" % TcpSeqNum
                header_info += "TcpAckNum: %d\t" % TcpAckNum
                header_info += "TcpHeaderLen: %d\t" % TcpHeaderLen
                header_info += "TcpURG: %d\t" % TcpURG
                header_info += "TcpAck: %d\t" % TcpAck
                header_info += "TcpPSH: %d\t" % TcpPSH
                header_info += "TcpRST： %d\t" % TcpRST
                header_info += "TcpSYN: %d\t" % TcpSYN
                header_info += "TcpFIN: %d\t" % TcpFIN
                header_info += "TcpWinSize: %d\t" % TcpWinSize
                header_info += "TcpChecksum: %d\t" % TcpChecksum
                header_info += "TcpUrgentPointer: %d\t" % TcpUrgentPointer

                newItemDetails = QTableWidgetItem(str(tcpfile[TcpHeaderLen:]))

                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)

                self.cur_lineno += 1



            ## ICMP内容：
            elif ip_class == 'ICMP':
                if self.FilterProtocol != 0 and self.FilterProtocol != 1 and self.FilterProtocol != 4:
                    return
                icmpfile = pkt_data[IpHeaderLen:]
                IcmpType = icmpfile[0]
                IcmpCode = icmpfile[1]
                IcmpChecksum = icmpfile[2] * 256 + icmpfile[3]
                header_info += "IcmpType: %d\t" % IcmpType
                header_info += "IcmpCode: %d\t" % IcmpCode
                header_info += "IcmpChecksum: %d\t" % IcmpChecksum

                newItemDetails = QTableWidgetItem(str(icmpfile[4:]))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)

                self.cur_lineno += 1


            # ## IGMP内容：
            # elif ip_class == 'IGMP':
            #     igmpfile = pkt_data[IpHeaderLen:]
            #     IgmpType = igmpfile[0] * 256 + igmpfile[1]
            #     IgmpMaxTimeout = igmpfile[2]
            #     IgmpChecksum = igmpfile[3]
            #     IgmpGroupAddress = igmpfile[4:8]
            #
            #     header_info += "IgmpType: %d\t" % IgmpType
            #     header_info += "IgmpMaxTimeout: %d\t" % IgmpMaxTimeout
            #     header_info += "IgmpChecksum: %d\t" % IgmpChecksum
            #     header_info += "IgmpGroupAddress: %d\t" % IgmpGroupAddress
            #
            #     newItemDetails = QTableWidgetItem(str(igmpfile[8:]))
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)
            #
            #     self.cur_lineno += 1

        ### ARP报文
        elif MacType == 0x0806:
            if self.FilterProtocol != 5 and self.FilterProtocol != 0:
                return
            arpfile = pkt_data[14:]
            ArpHardcoreType = arpfile[0]*256 + arpfile[1]
            ArpUpperlayerProtocol = arpfile[2]*256 + arpfile[3]
            ArpMacLen = arpfile[4]
            ArpIpLen = arpfile[5]
            ArpOprType = arpfile[6]*256 + arpfile[7]
            ArpSrcMac = ((((arpfile[8]*256 + arpfile[9])*256+arpfile[10])*256+ arpfile[11])*256+ arpfile[12])*256+arpfile[13]
            #ArpSrcIp = arpfile[14:18]
            ArpDstMac = ((((arpfile[18]*256 + arpfile[19])*256+arpfile[20])*256+ arpfile[21])*256+ arpfile[22])*256+arpfile[23]
            #ArpDstIp = arpfile[24:28]

            # src_ip = ".".join([str(b) for b in ip_frame[0xc:0x10]])
            # dst_ip = ".".join([str(b) for b in ip_frame[0x10:0x14]])
            ArpSrcIp = ".".join([str(b) for b in arpfile[14:18]])
            ArpDstIp = ".".join([str(b) for b in arpfile[24:28]])

            dotsrc = ArpSrcIp.split(".")
            dotdst = ArpDstIp.split(".")

            if len(self.FilterSrcIp) == 4:
                for i in range(4):
                    if int(dotsrc[i]) != int(self.FilterSrcIp[i]):
                        return
            if len(self.FilterDstIp) == 4:
                for i in range(4):
                    if int(dotdst[i]) != int(self.FilterDstIp[i]):
                        return


            header_info = ''
            header_info += "ArpHardcoreType: %d\t" % ArpHardcoreType
            header_info += "ArpUpperlayerProtocol: %d\t" % ArpUpperlayerProtocol
            header_info += "ArpMacLen: %d\t" % ArpMacLen
            header_info += "ArpIpLen: %d\t" % ArpIpLen
            header_info += "ArpOprType: %d\t" % ArpOprType
            header_info += "ArpSrcMac: %d\t" % hex(ArpSrcMac)
            header_info += "ArpDstMac: %d\t" % hex(ArpDstMac)

            arp_srcip = "%d.%d.%d.%d" % (arpfile[14], arpfile[15], arpfile[16], arpfile[17])
            arp_dstip = "%d.%d.%d.%d" % (arpfile[24], arpfile[25], arpfile[26], arpfile[27])
            self.ui.tableWidget.setItem(self.cur_lineno, 0, QTableWidgetItem(strTime))
            self.ui.tableWidget.setItem(self.cur_lineno, 1, QTableWidgetItem(arp_srcip))
            self.ui.tableWidget.setItem(self.cur_lineno, 2, QTableWidgetItem(arp_dstip))
            self.ui.tableWidget.setItem(self.cur_lineno, 3, QTableWidgetItem('ARP'))
            self.ui.tableWidget.setItem(self.cur_lineno, 4, QTableWidgetItem(header_info))
            self.ui.tableWidget.setItem(self.cur_lineno, 5, QTableWidgetItem())
            self.cur_lineno += 1


        ### IPv6报文
        elif MacType == 0x86dd:
            if self.FilterProtocol == 5:
                return
            ipv6file = pkt_data[14:]
            Ipv6Version = ipv6file[0] & 0b11110000
            Ipv6StreamPriority = (ipv6file[0] & 0b00001111) * 16 + ipv6file[1] & 0b11110000
            Ipv6StreamTag = ((ipv6file[1] & 0b00001111)*256 + ipv6file[2])*256 + ipv6file[3]
            Ipv6BurdenLen = ipv6file[4]*256 + ipv6file[5]
            Ipv6NextHeader = ipv6file[6]
            Ipv6TTL = ipv6file[7]
            #Ipv6SrcIp = ((int(ipv6file[8:12])*(2**32)+int(ipv6file[12:16]))*(2**32)+int(ipv6file[16:20]))*(2**32)+int(ipv6file[20:24])
            #Ipv6DstIp = ((int(ipv6file[24:28]) * (2 ** 32) + int(ipv6file[28:32])) * (2 ** 32) + int(ipv6file[32:36])) * (2 ** 32) + int(ipv6file[36:40])
            srcip = "%d: %d: %d: %d: %d: %d: %d: %d" % (ipv6file[8]*256+ipv6file[9], ipv6file[10]*256+ipv6file[11], ipv6file[12]*256+ipv6file[13], ipv6file[14]*256+ipv6file[15],
                                                        ipv6file[16]*256+ipv6file[17], ipv6file[18]*256+ipv6file[19], ipv6file[20]*256+ipv6file[21], ipv6file[22]*256+ipv6file[23])
            dstip = "%d: %d: %d: %d: %d: %d: %d: %d" % (
ipv6file[24] * 256 + ipv6file[25], ipv6file[26] * 256 + ipv6file[27], ipv6file[28] * 256 + ipv6file[29],
            ipv6file[30] * 256 + ipv6file[31],
            ipv6file[32] * 256 + ipv6file[33], ipv6file[34] * 256 + ipv6file[35], ipv6file[36] * 256 + ipv6file[37],
            ipv6file[38] * 256 + ipv6file[39])

            ipv6_class = ''

            header_info = ''
            header_info += "Ipv6Version: %d\t" % Ipv6Version
            header_info += "Ipv6StreamPriority: %d\t" % Ipv6StreamPriority
            header_info += "Ipv6StreamTag: %d\t" % Ipv6StreamTag
            header_info += "Ipv6BurdenLen: %d\t" % Ipv6BurdenLen
            header_info += "Ipv6NextHeader: %d\t" % Ipv6NextHeader
            header_info += "Ipv6TTL: %d\t" % Ipv6TTL

            if Ipv6NextHeader == 1:
                ipv6_class = 'ICMP'
            elif Ipv6NextHeader == 6:
                ipv6_class = 'TCP'
            elif Ipv6NextHeader == 17:
                ipv6_class = 'UDP'
            elif Ipv6NextHeader == 2:
                ipv6_class = 'IGMP'
            else:
                return

            if Ipv6BurdenLen <= 40:
                return

            newItemTime = QTableWidgetItem(strTime)
            newItemSrc = QTableWidgetItem(srcip)
            newItemDst = QTableWidgetItem(dstip)
            newItemProtocol = QTableWidgetItem(ipv6_class)


            ###UDP头部
            if ipv6_class == 'UDP':
                if self.FilterProtocol >= 3:
                    return
                udpfile_v6 = pkt_data[40:]
                UdpSrcPort_v6 = udpfile_v6[0] * 256 + udpfile_v6[1]
                UdpDstPort_v6 = udpfile_v6[2] * 256 + udpfile_v6[3]
                UdpLen_v6 = udpfile_v6[4] * 256 + udpfile_v6[5]
                UdpChecksum_v6 = udpfile_v6[6] * 256 + udpfile_v6[7]
                if UdpLen_v6 == 8:
                    return
                if self.FilterSrcPort != "F":
                    if UdpSrcPort_v6 != int(self.FilterSrcPort):
                        return
                if self.FilterDstPort != "F":
                    if UdpDstPort_v6 != int(self.FilterDstPort):
                        return
                self.contents[ltime] = udpfile_v6[8:]
                # if self.counter == 0:
                #     self.counter += 1
                #     self.ui.Text_Edit.append(str(str(udpfile[8:]).encode('windows-1252')))
                header_info += "UdpSrcPort: %d\t" % UdpSrcPort_v6
                header_info += "UdpDstPort :%d\t" % UdpDstPort_v6
                header_info += "UdpLen: %d\t" % UdpLen_v6
                header_info += "UdpChecksum: %d\t" % UdpLen_v6

                newItemDetails = QTableWidgetItem(str(udpfile_v6[8:]))

                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)

                self.cur_lineno += 1

            ## TCP头部
            elif ipv6_class == 'TCP':
                if self.FilterProtocol == 2 or self.FilterProtocol == 4 or self.FilterProtocol == 5:
                    return
                tcpfile_v6 = pkt_data[40:]
                TcpSrcPort_v6 = tcpfile_v6[0] * 256 + tcpfile_v6[1]
                TcpDstPort_v6 = tcpfile_v6[2] * 256 + tcpfile_v6[3]
                TcpSeqNum_v6 = ((tcpfile_v6[4] * 256 + tcpfile_v6[5]) * 256 + tcpfile_v6[6]) * 256 + tcpfile_v6[7]
                TcpAckNum_v6 = ((tcpfile_v6[8] * 256 + tcpfile_v6[9]) * 256 + tcpfile_v6[10]) * 256 + tcpfile_v6[11]
                TcpHeaderLen_v6 = tcpfile_v6[12] & 0b11110000
                TcpURG_v6 = tcpfile_v6[13] & 0b00100000
                TcpAck_v6 = tcpfile_v6[13] & 0b00010000
                TcpPSH_v6 = tcpfile_v6[13] & 0b00001000
                TcpRST_v6 = tcpfile_v6[13] & 0b00000100
                TcpSYN_v6 = tcpfile_v6[13] & 0b00000010
                TcpFIN_v6 = tcpfile_v6[13] & 0b00000001
                TcpWinSize_v6 = tcpfile_v6[14] * 256 + tcpfile_v6[15]
                TcpChecksum_v6 = tcpfile_v6[16] * 256 + tcpfile_v6[17]
                TcpUrgentPointer_v6 = tcpfile_v6[18] * 256 + tcpfile_v6[19]
                if TcpHeaderLen_v6 == Ipv6BurdenLen - 40:
                    return
                if self.FilterSrcPort != "F":
                    if TcpSrcPort_v6 != int(self.FilterSrcPort):
                        return
                if self.FilterDstPort != "F":
                    if TcpDstPort_v6 != int(self.FilterDstPort):
                        return
                self.contents[ltime] = tcpfile_v6[TcpHeaderLen_v6:]

                header_info += "TcpSrcPort: %d\t" % TcpSrcPort_v6
                header_info += "TcpDstPort: %d\t" % TcpDstPort_v6
                header_info += "TcpSeqNum: %d\t" % TcpSeqNum_v6
                header_info += "TcpAckNum: %d\t" % TcpAckNum_v6
                header_info += "TcpHeaderLen: %d\t" % TcpHeaderLen_v6
                header_info += "TcpURG: %d\t" % TcpURG_v6
                header_info += "TcpAck: %d\t" % TcpAck_v6
                header_info += "TcpPSH: %d\t" % TcpPSH_v6
                header_info += "TcpRST： %d\t" % TcpRST_v6
                header_info += "TcpSYN: %d\t" % TcpSYN_v6
                header_info += "TcpFIN: %d\t" % TcpFIN_v6
                header_info += "TcpWinSize: %d\t" % TcpWinSize_v6
                header_info += "TcpChecksum: %d\t" % TcpChecksum_v6
                header_info += "TcpUrgentPointer: %d\t" % TcpUrgentPointer_v6

                newItemDetails = QTableWidgetItem(str(tcpfile_v6[TcpHeaderLen_v6:]))

                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)

                self.cur_lineno += 1



            ## ICMP内容：
            elif ipv6_class == 'ICMP':
                if self.FilterProtocol != 0 and self.FilterProtocol != 1 and self.FilterProtocol != 4:
                    return
                icmpfile_v6 = pkt_data[40:]
                IcmpType_v6 = icmpfile_v6[0]
                IcmpCode_v6 = icmpfile_v6[1]
                IcmpChecksum_v6 = icmpfile_v6[2] * 256 + icmpfile_v6[3]

                header_info += "IcmpType: %d\t" % IcmpType_v6
                header_info += "IcmpCode: %d\t" % IcmpCode_v6
                header_info += "IcmpChecksum: %d\t" % IcmpChecksum_v6

                newItemDetails = QTableWidgetItem(str(icmpfile_v6[4:]))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
                self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)

                self.cur_lineno += 1

            ## IGMP内容：
            # elif ipv6_class == 'IGMP':
            #     igmpfile_v6 = pkt_data[40:]
            #     IgmpType_v6 = igmpfile_v6[0] * 256 + igmpfile_v6[1]
            #     IgmpMaxTimeout_v6 = igmpfile_v6[2]
            #     IgmpChecksum_v6 = igmpfile_v6[3]
            #     IgmpGroupAddress_v6 = igmpfile_v6[4:8]
            #
            #     header_info += "IgmpType: %d\t" % IgmpType_v6
            #     header_info += "IgmpMaxTimeout: %d\t" % IgmpMaxTimeout_v6
            #     header_info += "IgmpChecksum: %d\t" % IgmpChecksum_v6
            #     header_info += "IgmpGroupAddress: %d\t" % IgmpGroupAddress_v6
            #
            #     newItemDetails = QTableWidgetItem(str(igmpfile_v6[8:]))
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 0, newItemTime)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 1, newItemSrc)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 2, newItemDst)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 3, newItemProtocol)
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 4, QTableWidgetItem(header_info))
            #     self.ui.tableWidget.setItem(self.cur_lineno % 100000, 5, newItemDetails)
            #
            #     self.cur_lineno += 1




thread = None


def start_thread(ui, cur_filter, device_index):
    global thread
    thread = Captor_Thread(1, "mythread", ui, cur_filter, device_index)
    thread.start()
    return thread


list_devices = None
device_names = None


##获取设备列表
def GetDevices():
    global list_devices, device_names
    list_devices = WinPcapDevices.list_devices()
    device_names = list(list_devices.keys())
    return device_names
