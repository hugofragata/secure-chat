import sys
from loginDialog import *
from ConnectionManager import ConnectionManager, ConnectionManagerError
import t
try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s


class AppChat(QtGui.QMainWindow, t.Ui_MainWindow):
    def __init__(self, parent=None):
        super(AppChat, self).__init__(parent)
        self.comm = None
        self.setupUi(self)
        self.login_dialog = QtGui.QDialog()
        self.diag_ui = Ui_Dialog()
        self.diag_ui.setupUi(self.login_dialog)
        self.diag_ui.pushButton.clicked.connect(self.login)
        self.sendButton.clicked.connect(self.sendMsg)
        self.msgBox.installEventFilter(self)
        accept = self.login_dialog.exec_()
        if accept == 0:
            quit()

    def login(self):
        QtGui.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        address = str(self.diag_ui.address.text())
        port = str(self.diag_ui.port.text())
        username = str(self.diag_ui.userName.text())
        if address and port and username:
            if not ConnectionManager.is_ip_address(address):
                QtGui.QApplication.restoreOverrideCursor()
                return
            if not self.valid_port(port):
                QtGui.QApplication.restoreOverrideCursor()
                return
            try:
                self.comm = ConnectionManager(address, port, self)
            except ConnectionManagerError:
                QtGui.QApplication.restoreOverrideCursor()
                errorDiag = QtGui.QMessageBox()
                errorDiag.setIcon(QtGui.QMessageBox.Critical)
                errorDiag.setText("Connection ERROR")
                errorDiag.setWindowTitle("Error")
                errorDiag.setStandardButtons(QtGui.QMessageBox.Ok)
                errorDiag.exec_()
                return
            else:
                QtGui.QApplication.restoreOverrideCursor()
                return self.login_dialog.accept()
        else:
            QtGui.QApplication.restoreOverrideCursor()
            return

    def sendMsg(self):
        text = self.msgBox.toPlainText()
        if not text or text == "\n":
            return
        self.textBrowser.append(text)
        self.comm.send_message(text)
        self.msgBox.clear()

    def updateChat(self, text):
        self.textBrowser.append("<span>" + _fromUtf8(text) + "</span>")
        print self.textBrowser.toPlainText()
        #TODO: append das verificacoes
        pass

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress and obj == self.msgBox:
            if event.key() == QtCore.Qt.Key_Return:
                self.sendMsg()
                return True
        return QtGui.QMainWindow.eventFilter(self, obj, event)

    @staticmethod
    def valid_port(s):
        try:
            p = int(s)
            if 0 < p <= 65535:
                return True
            else:
                return False
        except ValueError:
            return False


def main():
    app = QtGui.QApplication(sys.argv)
    form = AppChat()
    form.show()
    app.exec_()


if __name__ == '__main__':
    main()
