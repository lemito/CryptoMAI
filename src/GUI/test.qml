import QtQuick 2.15

Rectangle {
    id: window

    width: 400
    height: 200
    color: "#f8fafc"

    Text {
        id: name
        text: qsTr("🐾 MeowChat")
        font.pixelSize: 16 * 1.33
        font.weight: Font.DemiBold
        anchors.centerIn: parent
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }
}
