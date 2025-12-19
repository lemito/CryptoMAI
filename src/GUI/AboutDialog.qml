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
                z: 1
                font.bold: true
                color: "#2c3e50"
            }

            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.maximumHeight: 200

                Text {
                    id: descriptionText
                    x: 19
                    y: 0
                    width: parent.width - 20
                    font.pixelSize: 10
                    color: "#34495e"
                    text: "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\np, li { white-space: pre-wrap; }\nhr { height: 1px; border-width: 0; }\nli.unchecked::marker { content: \"\\2610\"; }\nli.checked::marker { content: \"\\2612\"; }\n</style></head><body style=\" font-family:'Ubuntu Sans'; font-size:11pt; font-weight:400; font-style:normal;\">\n<p align=\"justify\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:'Times New Roman'; font-size:12pt;\">Бла бла бла</span></p>\n<p align=\"justify\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:'Times New Roman'; font-size:12pt;\">Все права принадлежат только мне и никому другому</span></p>\n<p align=\"justify\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:'Times New Roman'; font-size:12pt;\">Картинки взяты из Google</span></p>\n<p align=\"justify\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:'Times New Roman'; font-size:12pt;\">Анимации - бесплатные из https://lottiefiles.com/</span></p></body></html>"
                    wrapMode: Text.WordWrap
                    z: 1
                    font.family: "Arial"
                    textFormat: Text.RichText
                    lineHeight: 1.4
                }
            }

            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "Версия 0.0.1"
                font.pixelSize: 12
                z: 1
                color: "#7f8c8d"
            }

            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: 150

                LottieAnimation {
                    id: qtlottie
                    anchors.fill: parent
                    anchors.leftMargin: 0
                    anchors.rightMargin: 0
                    anchors.topMargin: 22
                    anchors.bottomMargin: -22
                    // anchors.margins: 10
                    scale: 1
                    source: "qrc:/cats/Le Petit Chat _Cat_ Noir.json"
                    z: 1
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
