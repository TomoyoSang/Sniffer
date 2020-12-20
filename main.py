import sys
from PyQt5.QtWidgets import QMainWindow, QApplication

import mainwindow
import captor_thread
import time


class UserFilter:
    def __init__(self, SrcIp = "", DstIp = "", SrcPort = "", DstPort = "", Protocol = 0):
        ###过滤条件
        self.SrcIp = SrcIp
        self.DstIp = DstIp

        self.SrcPort = SrcPort
        self.DstPort = DstPort
        ##  0:ALL
        ##  1:IP
        ##  2:UDP
        ##  3:TCP
        ##  4:ICMP
        ##  5:ARP
        self.Protocol = Protocol


userfilter = UserFilter()


cur_thread = None


def StartCaptor():
    current_index = ui.comboBox.currentIndex()
    global cur_thread
    cur_thread = captor_thread.start_thread(ui, userfilter, current_index)


def StopCaptor():
    # cur_thread.stop_pcap = True
    if cur_thread is None or cur_thread.capture is None:
        return
    cur_thread.capture.stop()
    # cur_thread.join()

def FilterRule():

    global userfilter

    if len(userfilter.SrcIp) != 0:
        ui.srcip.setText(userfilter.SrcIp)
    if len(userfilter.DstIp) != 0:
        ui.dstip.setText(userfilter.DstIp)
    if len(userfilter.SrcPort) != 0:
        ui.srcport.setText(userfilter.SrcPort)
    if len(userfilter.DstPort) != 0:
        ui.dstport.setText(userfilter.DstPort)
    ui.protocol.setCurrentIndex(userfilter.Protocol)



    ui.FilterWidget.setVisible(True)

def FilterOK():
    global userfilter
    userfilter.Protocol = ui.protocol.currentIndex()
    userfilter.SrcIp = ui.srcip.text()
    userfilter.DstIp = ui.dstip.text()
    userfilter.SrcPort = ui.srcport.text()
    userfilter.DstPort = ui.dstport.text()

    ui.FilterWidget.setVisible(False)

def FilterCancel():
    ui.FilterWidget.setVisible(False)

def CloseWidget():
    if cur_thread is None or cur_thread.capture is None:
        MainWindow.close()
        return
    cur_thread.capture.stop()
    MainWindow.close()

def ShowText(Item):
    if Item is None:
        return
    ui.Text_Edit.setText(str(Item.text()))
    ui.Hex_Edit.setText(' '.join([hex(ord(i))[2:] for i in str(Item.text())]))

def SaveAsFile():
    Itemlist = ui.tableWidget.selectedItems()

    for Item in Itemlist:
        cur_time = time.time()
        with open(str(cur_time), 'w') as file:
            for line in str(Item.text()):
                file.write(line)
            file.close()

##获取设备列表

device_names = captor_thread.GetDevices()

##应用窗口运行
app = QApplication(sys.argv)
MainWindow = QMainWindow()
ui = mainwindow.Ui_MainWindow()
ui.setupUi(MainWindow)

##在下拉框展示设备列表
for device in device_names:
    ui.comboBox.addItem(device)


MainWindow.show()

##开始抓包：：
##开启一个thread
ui.btn_start.clicked.connect(StartCaptor)

ui.btn_stop.clicked.connect(StopCaptor)

ui.btn_filter.clicked.connect(FilterRule)

ui.btn_ok.clicked.connect(FilterOK)

ui.btn_cancel.clicked.connect(FilterCancel)

ui.btn_quit.clicked.connect(CloseWidget)

ui.tableWidget.itemClicked.connect(ShowText)

ui.btn_save.clicked.connect(SaveAsFile)

print(userfilter.SrcIp)

sys.exit(app.exec_())



