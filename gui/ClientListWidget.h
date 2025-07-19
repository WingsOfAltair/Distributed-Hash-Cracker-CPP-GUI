#include <QListWidget>
#include <QMenu>
#include <QAction>
#include <QMessageBox>

class ClientListWidget : public QListWidget {
    Q_OBJECT
public:
    ClientListWidget(QWidget *parent = nullptr) : QListWidget(parent) {
        setContextMenuPolicy(Qt::CustomContextMenu);
        connect(this, &QListWidget::customContextMenuRequested,
                this, &ClientListWidget::showContextMenu);
    }

public slots:
    void showContextMenu(const QPoint &pos) {
    }
};
