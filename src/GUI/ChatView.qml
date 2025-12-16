import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import Qt.labs.lottieqt

Item {
    id: root

    property bool hasSelectedChat: chatState ? chatState.hasSelectedChat : false
    property int messageCount: chatState ? chatState.messageCount : 0
    property var messageList: chatState ? chatState.messageList : []

    property int previousMessageCount: 0

    signal fileDownloadRequested(string fileId)

    LottieAnimation {
        id: lottieBackground
        anchors.fill: parent
        source: "qrc:/backgrounds/Background sparkles.json"
        loops: LottieAnimation.Infinite
        opacity: 0.2
        scale: 1
        z: -1
    }

    Rectangle {
        anchors.fill: parent
        color: "#f8f9fa"
        opacity: hasSelectedChat && messageCount > 0 ? 1 : 0.3
        z: 0
    }

    // ============================= ПУСТОЙ ЧАТ =============================
    Column {
        id: emptyState
        anchors.centerIn: parent
        spacing: 20
        visible: !hasSelectedChat || messageCount === 0
        z: 2

        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: "Пока тут пусто :("
            font.pixelSize: 16
            color: "#666"
            z: 3
        }

        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: "Создай чат или вступи в существующий"
            font.pixelSize: 14
            color: "#999"
            z: 3
        }

        LottieAnimation {
            id: emptyStateAnimation
            anchors.horizontalCenter: parent.horizontalCenter
            source: "qrc:/loaders/Loading 40 _ Paperplane.json"
            width: 150
            height: 150
            loops: LottieAnimation.Infinite
            visible: !hasSelectedChat || messageCount === 0
            z: 1
        }
    }

    // ============================ НЕ ПУСТОЙ ЧАТ ===========================
    ScrollView {
        id: messagesView
        anchors.fill: parent
        visible: hasSelectedChat && messageCount > 0
        padding: 10
        z: 3

        LottieAnimation {
            id: lottieBackground2
            anchors.fill: parent
            source: "qrc:/backgrounds/Background sparkles.json"
            loops: LottieAnimation.Infinite
            opacity: 0.2
            scale: 1
            z: -1
        }
        LottieAnimation {
            id: lottieBackground3
            anchors.fill: parent
            source: "qrc:/backgrounds/Background sparkles.json"
            loops: LottieAnimation.Infinite
            opacity: 0.2
            scale: 1
            transform: [
                Matrix4x4 {
                    matrix: Qt.matrix4x4(-1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1)
                },
                Translate {
                    x: parent.width
                }
            ]
            z: -1
        }


        ListView {
            id: listView
            model: messageList
            spacing: 10
            anchors.fill: parent

            property var newItemsIndices: []

            onCountChanged: {
                positionViewAtEnd()

                if (count > previousMessageCount) {
                    for (var i = previousMessageCount; i < count; i++) {
                        newItemsIndices.push(i)
                    }
                }
                previousMessageCount = count
            }

            onModelChanged: {
                newItemsIndices = []
                previousMessageCount = 0
            }

            delegate: Rectangle {
                id: messageDelegate
                width: Math.min(messageText.implicitWidth + 20, ListView.view.width * 0.7)
                height: messageColumn.implicitHeight + 20
                color: modelData.isOwn ? "#007bff" : "#e9ecef"
                radius: 15

                anchors.right: modelData.isOwn ? parent.right : undefined
                anchors.left: modelData.isOwn ? undefined : parent.left
                anchors.rightMargin: modelData.isOwn ? 10 : undefined
                anchors.leftMargin: modelData.isOwn ? undefined : 10

                scale: 0
                opacity: 0

                function animateAppearance() {
                    if (appearAnimation.running) return;

                    var delay = Math.min(index * 50, 300)

                    appearTimer.interval = delay
                    appearTimer.restart()
                }

                Timer {
                    id: appearTimer
                    onTriggered: {
                        appearAnimation.start()
                    }
                }

                ParallelAnimation {
                    id: appearAnimation
                    NumberAnimation {
                        target: messageDelegate
                        property: "scale"
                        from: 0
                        to: 1
                        duration: 300
                        easing.type: Easing.OutBack
                    }
                    NumberAnimation {
                        target: messageDelegate
                        property: "opacity"
                        from: 0
                        to: 1
                        duration: 200
                    }
                }

                Component.onCompleted: {
                    if (listView.newItemsIndices.indexOf(index) !== -1) {
                        animateAppearance()
                    } else {
                        scale = 1
                        opacity = 1
                    }
                }

                Column {
                    id: messageColumn
                    anchors {
                        verticalCenter: parent.verticalCenter
                        left: parent.left
                        right: parent.right
                        margins: 10
                    }
                    spacing: 5

                    Text {
                        visible: !modelData.isOwn
                        text: modelData.sender
                        font.bold: true
                        font.pixelSize: 12
                        color: "#6c757d"
                        width: parent.width
                    }

                    // ------------ файл --------------------
                    Column {
                        width: parent.width
                        visible: modelData.isFile
                        spacing: 10

                        function isImageFile(fileName) {
                            if (!fileName) return false
                            var ext = fileName.toLowerCase().split('.').pop()
                            return ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].indexOf(ext) !== -1
                        }

                        Image {
                            id: imagePreview
                            visible: parent.isImageFile(modelData.fileName) && modelData.content && modelData.content !== ""
                            source: visible && modelData.content ? "file://" + modelData.content : ""
                            width: Math.min(sourceSize.width > 0 ? sourceSize.width : parent.width, parent.width)
                            height: visible ? Math.min(sourceSize.height, 300) : 0
                            fillMode: Image.PreserveAspectFit
                            asynchronous: true
                            cache: false
                        }

                        RowLayout {
                            width: parent.width
                            spacing: 10

                            Image {
                                id: fileIcon
                                source: "qrc:/icons/file-icon.png"
                                width: 32
                                height: 32
                                Layout.preferredWidth: 32
                                Layout.preferredHeight: 32
                                Layout.alignment: Qt.AlignVCenter
                            }

                            Column {
                                Layout.fillWidth: true
                                Layout.alignment: Qt.AlignVCenter
                                spacing: 2

                                Text {
                                    width: parent.width
                                    font.pixelSize: 14
                                    color: modelData.isOwn ? "white" : "#007bff"
                                    text: modelData.fileName + (modelData.fileSize ? " ("+ modelData.fileSize +" байт)" : "")
                                    elide: Text.ElideRight
                                }

                                Text {
                                    visible: modelData.mimeType && modelData.mimeType !== "mime"
                                    width: parent.width
                                    font.pixelSize: 11
                                    color: modelData.isOwn ? "#cce5ff" : "#6c757d"
                                    text: modelData.mimeType
                                    elide: Text.ElideRight
                                }

                                ProgressBar {
                                    id: downloadProgress
                                    width: parent.width
                                    visible: modelData.downloadProgress !== undefined && modelData.downloadProgress >= 0 && modelData.downloadProgress < 100
                                    value: modelData.downloadProgress || 0
                                    from: 0
                                    to: 100
                                }
                            }

                            Button {
                                text: modelData.content && modelData.content !== "" ? "Открыть" : "Скачать"
                                Layout.alignment: Qt.AlignVCenter
                                Layout.preferredWidth: 100
                                Layout.minimumWidth: 80
                                enabled: !downloadProgress.visible
                                onClicked: {
                                    fileDownloadRequested(modelData.fileId)
                                }
                            }
                        }
                    }
                    // ------------ текстовое ----------------
                    Text {
                        id: messageText
                        visible: !modelData.isFile && modelData.content
                        text: modelData.content || "[ERROR]"
                        width: parent.width
                        wrapMode: Text.Wrap
                        font.pixelSize: 14
                        color: modelData.isOwn ? "white" : "black"
                    }

                    Text {
                        text: modelData.timestamp
                        font.pixelSize: 10
                        color: modelData.isOwn ? "#cce5ff" : "#6c757d"
                        anchors.right: parent.right
                    }
                }
            }
        }
    }
}
