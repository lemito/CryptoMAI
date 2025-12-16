import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Qt.labs.lottieqt

Item {
    id: window
    width: 500
    height: 400

    Rectangle {
        anchors.fill: parent
        color: "#f0f0f0"

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 20
            spacing: 20

            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "MeowChat"
                font.pixelSize: 24
                font.bold: true
                color: "#2c3e50"
            }

            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.maximumHeight: 200

                Text {
                    id: descriptionText
                    width: parent.width - 20
                    text: "Бла бла бла"
                    font.pixelSize: 14
                    color: "#34495e"
                    wrapMode: Text.WordWrap
                    lineHeight: 1.4
                }
            }

            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "Версия 1.0.0"
                font.pixelSize: 12
                color: "#7f8c8d"
            }

            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: 150

                LottieAnimation {
                    id: qtlottie
                    anchors.fill: parent
                    // anchors.margins: 10
                    scale: 1
                    source: "qrc:/cats/Le Petit Chat _Cat_ Noir.json"
                    quality: LottieAnimation.HighQuality
                    loops: LottieAnimation.Infinite
                    // fillColor: "#F0F0F0"
                    // clip: true

                    onStatusChanged: {
                        if (status == LottieAnimation.Ready) {
                            console.log("Анимация загружена, размер:", width, "x", height)
                        }
                    }
                }
            }
        }
    }
}
