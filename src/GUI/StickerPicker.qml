import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Item {
    id: root
    width: 400
    height: 300

    property var stickerMap: ({
                                  ":meow:": "qrc:/stickers/meow_sticker.jpg",
                                  ":UwU:": "qrc:/stickers/meow_stickers.jpg",
                                  ":clown2:": "qrc:/stickers/hamster_clown_2.jpg",
                                  ":clown1:": "qrc:/stickers/hamster_clown.jpg",
                                  ":coffee:": "qrc:/stickers/hamster_coffee-ezgif.com-webp-to-gif-converter.gif",
                                  ":sad:": "qrc:/stickers/sad_sticker.gif",
                                  ":sad2:": "qrc:/stickers/sad2_sticker.gif",
                                  ":catcoffe:": "qrc:/stickers/cat_coffee-ezgif.com-webp-to-gif-converter.gif",
                                  ":kitty:": "qrc:/stickers/cat_sticker.gif"
                              })

    signal stickerSelected(string stickerCode)
    Popup {
        id: stickerPopup
        anchors.centerIn: parent
        modal: true
        focus: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        padding: 10

        width: 380
        height: 280

        background: Rectangle {
            color: "#ffffff"
            border.color: "#cccccc"
            border.width: 1
            radius: 10

            layer.enabled: true
        }

        ColumnLayout {
            anchors.fill: parent

            Text {
                text: "Выберите стикер"
                font.pixelSize: 16
                font.bold: true
                color: "#333333"
                Layout.alignment: Qt.AlignHCenter
            }

            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true

                Grid {
                    id: stickerGrid
                    columns: 4
                    spacing: 10

                    Repeater {
                        model: Object.keys(stickerMap)

                        Rectangle {
                            width: 80
                            height: 80
                            color: mouseArea.containsMouse ? "#f0f0f0" : "transparent"
                            radius: 8

                            Image {
                                anchors.centerIn: parent
                                width: 60
                                height: 60
                                source: stickerMap[modelData]
                                fillMode: Image.PreserveAspectFit
                                smooth: true

                                MouseArea {
                                    id: mouseArea
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor

                                    onClicked: {
                                        clickAnimation.start()
                                        stickerPopup.stickerSelected(modelData)
                                        stickerPopup.close()
                                    }
                                }
                            }

                            SequentialAnimation {
                                id: clickAnimation
                                NumberAnimation {
                                    target: parent
                                    property: "scale"
                                    from: 1.0
                                    to: 0.9
                                    duration: 50
                                }
                                NumberAnimation {
                                    target: parent
                                    property: "scale"
                                    from: 0.9
                                    to: 1.0
                                    duration: 50
                                }
                            }

                            ToolTip {
                                text: modelData
                                delay: 500
                                visible: mouseArea.containsMouse
                            }
                        }
                    }
                }
            }
        }
    }

    function open() {
        stickerPopup.open()
    }

    function close() {
        stickerPopup.close()
    }
}
