from PyQt4 import QtCore, QtGui


class UserListItem(QtGui.QListWidgetItem):
    def __init__(self, text, uid):
        self.user_id = uid
        self.user_name = text
        self.num = 0
        super(UserListItem, self).__init__(text)
