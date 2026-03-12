"""
NeoNetwork Analyzer - Advanced Network Security & Monitoring Tool
By @concole_hack
"""

import sys
import os
import subprocess
import importlib
import platform
from datetime import datetime
import socket
import threading
import time
import json
import warnings
warnings.filterwarnings('ignore')

# Проверка и установка зависимостей
def install_package(package):
    """Установка одного пакета"""
    try:
        importlib.import_module(package.split('==')[0])
        print(f"✓ {package} уже установлен")
        return True
    except ImportError:
        print(f"📦 Устанавливаю {package}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--quiet"])
            print(f"✓ {package} успешно установлен")
            return True
        except:
            print(f"✗ Ошибка установки {package}")
            return False

def setup_environment():
    """Настройка окружения"""
    print("=" * 50)
    print("NeoNetwork Analyzer - Установка зависимостей")
    print("=" * 50)
    
    packages = [
        'PyQt5',
        'psutil',
        'pyqtgraph',
        'qdarkstyle',
        'netifaces'
    ]
    
    success = True
    for package in packages:
        if not install_package(package):
            success = False
    
    print("=" * 50)
    if success:
        print("✅ Все зависимости успешно установлены!")
    else:
        print("⚠️ Некоторые зависимости не установились, работаем с тем что есть")
    print("=" * 50)
    
    return success

# Запускаем установку
setup_environment()

# Теперь импортируем всё
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QRect, QSize, QThread, pyqtSignal
    from PyQt5.QtGui import QPainter, QBrush, QLinearGradient, QColor, QPen, QFont, QPainterPath, QPalette
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QLabel, QPushButton, QFrame, QTabWidget,
                                 QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
                                 QProgressBar, QSplitter, QGraphicsDropShadowEffect,
                                 QComboBox, QLineEdit, QMessageBox, QSystemTrayIcon,
                                 QMenu, QStyle, QCheckBox, QGroupBox, QGridLayout,
                                 QInputDialog)
    
    import pyqtgraph as pg
    import psutil
    import qdarkstyle
    HAS_DEPS = True
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    HAS_DEPS = False

if not HAS_DEPS:
    input("Нажмите Enter для выхода...")
    sys.exit(1)

class GradientWidget(QWidget):
    """Виджет с градиентным фоном"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, QColor(25, 25, 30))
        gradient.setColorAt(0.5, QColor(20, 20, 25))
        gradient.setColorAt(1, QColor(15, 15, 20))
        
        painter.fillRect(self.rect(), gradient)

class ModernButton(QPushButton):
    """Современная кнопка с эффектами"""
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(40)
        self.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 50, 60, 200);
                border: 2px solid rgba(80, 80, 90, 200);
                border-radius: 8px;
                padding: 10px 20px;
                color: white;
                font-weight: bold;
                font-size: 12px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: rgba(70, 70, 80, 200);
                border-color: rgba(100, 100, 110, 200);
            }
            QPushButton:pressed {
                background-color: rgba(90, 90, 100, 200);
                border-color: rgba(120, 120, 130, 200);
            }
        """)

class NetworkScanner(QThread):
    """Поток для сканирования сети"""
    network_scan = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.running = True
        
    def run(self):
        while self.running:
            try:
                connections = []
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        if conn.laddr and conn.status == 'ESTABLISHED':
                            proc_name = "System"
                            if conn.pid:
                                try:
                                    proc = psutil.Process(conn.pid)
                                    proc_name = proc.name()
                                except:
                                    pass
                            
                            raddr_str = "N/A"
                            if conn.raddr:
                                raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
                            
                            connections.append({
                                'pid': conn.pid or 0,
                                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'raddr': raddr_str,
                                'status': conn.status,
                                'process': proc_name
                            })
                    except:
                        continue
                
                self.network_scan.emit(connections)
                time.sleep(2)
            except Exception as e:
                print(f"Ошибка сканирования: {e}")
                time.sleep(5)
    
    def stop(self):
        self.running = False

class DashboardWidget(QWidget):
    """Виджет дашборда с метриками"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.metric_labels = {}
        self.plot_data = []
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Заголовок
        title = QLabel("📊 СЕТЕВОЙ АНАЛИЗАТОР")
        title.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                color: #FFFFFF;
                padding: 12px;
                background: rgba(40, 40, 50, 0.8);
                border-radius: 10px;
                border-left: 4px solid #5D6AFB;
            }
        """)
        title.setAlignment(Qt.AlignCenter)
        
        # Сетка метрик
        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(15)
        
        metrics = [
            ("🌐 Активные соединения", "0", "#5D6AFB"),
            ("⚠️ Подозрительные", "0", "#FF6B6B"),
            ("📤 Отправлено", "0 MB", "#4ECDC4"),
            ("📥 Получено", "0 MB", "#45B7D1"),
            ("🖥️ Процессы", "0", "#96CEB4"),
            ("🔒 Блокировок", "0", "#FECA57"),
        ]
        
        for i, (title_text, value, color) in enumerate(metrics):
            metric_widget = self.create_metric_widget(title_text, value, color)
            row = i // 3
            col = i % 3
            metrics_grid.addWidget(metric_widget, row, col)
            self.metric_labels[title_text] = metric_widget.findChild(QLabel, "value")
        
        # График сетевой активности
        graph_widget = self.create_network_graph()
        
        layout.addWidget(title)
        layout.addLayout(metrics_grid)
        layout.addWidget(graph_widget, 1)
        
    def create_metric_widget(self, title, value, color):
        widget = QFrame()
        widget.setStyleSheet(f"""
            QFrame {{
                background: rgba(40, 40, 50, 0.8);
                border-radius: 10px;
                border-left: 4px solid {color};
                padding: 12px;
            }}
        """)
        
        layout = QVBoxLayout(widget)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 11px;
                color: #AAAAAA;
                font-weight: bold;
            }
        """)
        
        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setStyleSheet(f"""
            QLabel {{
                font-size: 22px;
                font-weight: bold;
                color: {color};
            }}
        """)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        
        return widget
        
    def create_network_graph(self):
        widget = QFrame()
        widget.setStyleSheet("""
            QFrame {
                background: rgba(40, 40, 50, 0.8);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QVBoxLayout(widget)
        
        title = QLabel("📈 СЕТЕВАЯ АКТИВНОСТЬ")
        title.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #FFFFFF;
                margin-bottom: 10px;
            }
        """)
        
        # График
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground((30, 30, 35, 255))
        self.plot_widget.showGrid(x=True, y=True, alpha=0.2)
        self.plot_widget.setLabel('left', 'КБ/с')
        self.plot_widget.setLabel('bottom', 'Время')
        self.plot_widget.setYRange(0, 100)
        
        # Настройка осей
        self.plot_widget.getAxis('left').setPen(pg.mkPen(color=(200, 200, 200), width=1))
        self.plot_widget.getAxis('bottom').setPen(pg.mkPen(color=(200, 200, 200), width=1))
        
        self.curve = self.plot_widget.plot(pen=pg.mkPen(color=(93, 106, 251), width=2))
        
        layout.addWidget(title)
        layout.addWidget(self.plot_widget)
        
        return widget
        
    def update_metrics(self, stats):
        """Обновление метрик"""
        try:
            if 'connections' in stats:
                self.metric_labels["🌐 Активные соединения"].setText(str(len(stats['connections'])))
            
            if 'sent' in stats:
                sent_mb = stats['sent'] / (1024 * 1024)
                self.metric_labels["📤 Отправлено"].setText(f"{sent_mb:.1f} MB")
                
            if 'received' in stats:
                recv_mb = stats['received'] / (1024 * 1024)
                self.metric_labels["📥 Получено"].setText(f"{recv_mb:.1f} MB")
                
            # Обновляем график
            if 'network_speed' in stats:
                speed_kb = stats['network_speed'] / 1024
                self.plot_data.append(speed_kb)
                if len(self.plot_data) > 30:
                    self.plot_data.pop(0)
                
                if len(self.plot_data) > 1:
                    self.curve.setData(self.plot_data)
                    
                    # Автомасштабирование по Y
                    max_val = max(self.plot_data) if self.plot_data else 100
                    self.plot_widget.setYRange(0, max_val * 1.1)
        except Exception as e:
            print(f"Ошибка обновления метрик: {e}")

class ConnectionsTable(QTableWidget):
    """Таблица сетевых подключений"""
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        self.setColumnCount(5)
        headers = ["🆔 PID", "🏠 Локальный адрес", "🌍 Удаленный адрес", "📊 Статус", "⚙️ Процесс"]
        self.setHorizontalHeaderLabels(headers)
        
        # Настраиваем стиль
        self.setStyleSheet("""
            QTableWidget {
                background: rgba(40, 40, 50, 0.8);
                border-radius: 10px;
                gridline-color: rgba(100, 100, 110, 100);
                font-size: 11px;
                color: #E0E0E0;
            }
            
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid rgba(100, 100, 110, 50);
            }
            
            QHeaderView::section {
                background-color: rgba(50, 50, 60, 200);
                color: #FFFFFF;
                font-weight: bold;
                padding: 8px;
                border: none;
                border-right: 1px solid rgba(100, 100, 110, 100);
            }
        """)
        
        # Настройка заголовков
        header = self.horizontalHeader()
        for i in range(5):
            if i == 0:
                header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
            else:
                header.setSectionResizeMode(i, QHeaderView.Stretch)
        
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        
    def update_connections(self, connections):
        try:
            self.setRowCount(len(connections))
            
            for row, conn in enumerate(connections):
                # PID
                pid_item = QTableWidgetItem(str(conn['pid']))
                pid_item.setTextAlignment(Qt.AlignCenter)
                
                # Локальный адрес
                laddr_item = QTableWidgetItem(conn['laddr'])
                
                # Удаленный адрес
                raddr_item = QTableWidgetItem(conn['raddr'])
                
                # Статус
                status_item = QTableWidgetItem(conn['status'])
                status_item.setTextAlignment(Qt.AlignCenter)
                
                # Цвет статуса
                status_color = QColor(244, 67, 54)  # По умолчанию красный
                if conn['status'] == 'ESTABLISHED':
                    status_color = QColor(76, 175, 80)
                elif conn['status'] == 'LISTEN':
                    status_color = QColor(255, 193, 7)
                
                status_item.setForeground(status_color)
                
                # Процесс
                process_item = QTableWidgetItem(conn['process'][:30])
                
                # Устанавливаем элементы
                self.setItem(row, 0, pid_item)
                self.setItem(row, 1, laddr_item)
                self.setItem(row, 2, raddr_item)
                self.setItem(row, 3, status_item)
                self.setItem(row, 4, process_item)
                
        except Exception as e:
            print(f"Ошибка обновления таблицы: {e}")

class SecurityPanel(QWidget):
    """Панель безопасности"""
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Заголовок
        title = QLabel("🛡️ ЦЕНТР БЕЗОПАСНОСТИ")
        title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #FFFFFF;
                padding: 10px;
                background: rgba(40, 40, 50, 0.8);
                border-radius: 10px;
                border-left: 4px solid #FF6B6B;
            }
        """)
        
        # Сканер портов
        scan_group = QGroupBox("🔍 Сканирование портов")
        scan_group.setStyleSheet("""
            QGroupBox {
                color: #FFFFFF;
                font-weight: bold;
                border: 2px solid rgba(100, 100, 110, 150);
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 15px;
                background: rgba(40, 40, 50, 0.6);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
        """)
        
        scan_layout = QVBoxLayout()
        
        # Панель ввода
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Цель:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("127.0.0.1 или localhost")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: rgba(60, 60, 70, 200);
                border: 2px solid rgba(100, 100, 110, 150);
                border-radius: 5px;
                padding: 8px;
                color: #FFFFFF;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 2px solid #5D6AFB;
            }
        """)
        
        self.scan_button = ModernButton("Начать сканирование")
        self.scan_button.clicked.connect(self.start_scan)
        
        input_layout.addWidget(self.target_input)
        input_layout.addWidget(self.scan_button)
        
        # Лог сканирования
        self.port_list = QTextEdit()
        self.port_list.setStyleSheet("""
            QTextEdit {
                background: rgba(40, 40, 50, 0.8);
                border-radius: 5px;
                border: 1px solid rgba(100, 100, 110, 150);
                color: #E0E0E0;
                font-family: 'Consolas', monospace;
                font-size: 10px;
                padding: 10px;
            }
        """)
        self.port_list.setReadOnly(True)
        
        scan_layout.addLayout(input_layout)
        scan_layout.addWidget(self.port_list)
        scan_group.setLayout(scan_layout)
        
        # Настройки безопасности
        sec_group = QGroupBox("⚙️ Настройки защиты")
        sec_group.setStyleSheet(scan_group.styleSheet())
        
        sec_layout = QVBoxLayout()
        
        self.auto_block = QCheckBox("Автоматическая блокировка подозрительных соединений")
        self.notify_threats = QCheckBox("Уведомлять об угрозах")
        self.notify_threats.setChecked(True)
        self.log_all = QCheckBox("Логировать всю сетевую активность")
        
        # Стиль чекбоксов
        checkbox_style = """
            QCheckBox {
                color: #E0E0E0;
                font-size: 12px;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 2px solid rgba(100, 100, 110, 150);
            }
            QCheckBox::indicator:checked {
                background-color: #5D6AFB;
                border-color: #5D6AFB;
            }
        """
        
        for checkbox in [self.auto_block, self.notify_threats, self.log_all]:
            checkbox.setStyleSheet(checkbox_style)
        
        sec_layout.addWidget(self.auto_block)
        sec_layout.addWidget(self.notify_threats)
        sec_layout.addWidget(self.log_all)
        sec_group.setLayout(sec_layout)
        
        # Кнопки действий
        action_layout = QHBoxLayout()
        
        self.block_button = ModernButton("🚫 Блокировать IP")
        self.block_button.clicked.connect(self.block_ip)
        
        self.export_button = ModernButton("💾 Экспорт логов")
        self.export_button.clicked.connect(self.export_logs)
        
        action_layout.addWidget(self.block_button)
        action_layout.addWidget(self.export_button)
        
        layout.addWidget(title)
        layout.addWidget(scan_group)
        layout.addWidget(sec_group)
        layout.addLayout(action_layout)
        layout.addStretch()
        
    def start_scan(self):
        """Сканирование портов"""
        target = self.target_input.text().strip()
        if not target:
            target = "127.0.0.1"
            
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Сканирование...")
        
        self.port_list.append(f"[{datetime.now().strftime('%H:%M:%S')}] Сканирование {target}...")
        
        # Запускаем в отдельном потоке
        scan_thread = threading.Thread(target=self.scan_ports, args=(target,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def scan_ports(self, target):
        """Сканирование портов в отдельном потоке"""
        try:
            # Разрешаем hostname в IP
            ip = socket.gethostbyname(target)
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443, 3306, 5432]
            
            for port in common_ports:
                QtCore.QMetaObject.invokeMethod(self, "update_scan_log", 
                    QtCore.Qt.QueuedConnection,
                    QtCore.Q_ARG(str, f"  Проверка порта {port}..."))
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        QtCore.QMetaObject.invokeMethod(self, "update_scan_log",
                            QtCore.Qt.QueuedConnection,
                            QtCore.Q_ARG(str, f"  ✅ Порт {port}: OPEN"))
                    else:
                        QtCore.QMetaObject.invokeMethod(self, "update_scan_log",
                            QtCore.Qt.QueuedConnection,
                            QtCore.Q_ARG(str, f"  ❌ Порт {port}: CLOSED"))
                except:
                    QtCore.QMetaObject.invokeMethod(self, "update_scan_log",
                        QtCore.Qt.QueuedConnection,
                        QtCore.Q_ARG(str, f"  ⚠️ Порт {port}: ERROR"))
                finally:
                    sock.close()
                
                time.sleep(0.1)
            
            QtCore.QMetaObject.invokeMethod(self, "update_scan_log",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"\n[{datetime.now().strftime('%H:%M:%S')}] Сканирование завершено!"))
            
        except Exception as e:
            QtCore.QMetaObject.invokeMethod(self, "update_scan_log",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, f"  Ошибка: {str(e)}"))
        
        finally:
            QtCore.QMetaObject.invokeMethod(self.scan_button, "setEnabled",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(bool, True))
            QtCore.QMetaObject.invokeMethod(self.scan_button, "setText",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, "Начать сканирование"))
    
    @QtCore.pyqtSlot(str)
    def update_scan_log(self, message):
        """Обновление лога сканирования (для вызова из основного потока)"""
        self.port_list.append(message)
        
    def block_ip(self):
        """Блокировка IP"""
        ip, ok = QInputDialog.getText(
            self, "Блокировка IP", "Введите IP для блокировки:"
        )
        if ok and ip:
            # Здесь должна быть реальная логика блокировки
            QMessageBox.information(
                self, 
                "IP заблокирован", 
                f"IP адрес {ip} был добавлен в черный список!\n\n"
                f"В реальной системе здесь будет:\n"
                f"• Блокировка через iptables/firewall\n"
                f"• Добавление в hosts файл\n"
                f"• Уведомление системы безопасности"
            )
            
    def export_logs(self):
        """Экспорт логов"""
        try:
            log_data = {
                "timestamp": datetime.now().isoformat(),
                "scan_results": self.port_list.toPlainText(),
                "settings": {
                    "auto_block": self.auto_block.isChecked(),
                    "notify_threats": self.notify_threats.isChecked(),
                    "log_all": self.log_all.isChecked()
                }
            }
            
            with open("network_logs.json", "w", encoding="utf-8") as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)
            
            QMessageBox.information(
                self,
                "Экспорт логов",
                "Логи успешно экспортированы в файл network_logs.json"
            )
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось экспортировать логи: {str(e)}")

class NeoNetworkAnalyzer(QMainWindow):
    """Главное окно NeoNetwork Analyzer"""
    def __init__(self):
        super().__init__()
        self.network_stats = {
            'connections': [],
            'sent': 0,
            'received': 0,
            'network_speed': 0,
            'last_bytes_recv': 0,
            'last_bytes_sent': 0
        }
        
        self.setup_ui()
        self.setup_tray()
        self.start_monitoring()
        
    def setup_ui(self):
        # Основные настройки окна
        self.setWindowTitle("NeoNetwork Analyzer v1.0 - By @concole_hack")
        self.setGeometry(100, 100, 1400, 850)
        
        # Центральный виджет с градиентным фоном
        central_widget = GradientWidget()
        self.setCentralWidget(central_widget)
        
        # Основной layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(1, 1, 1, 1)
        main_layout.setSpacing(0)
        
        # Панель заголовка
        title_bar = self.create_title_bar()
        main_layout.addWidget(title_bar)
        
        # Основное содержание
        content_widget = QWidget()
        content_layout = QHBoxLayout(content_widget)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(10)
        
        # Левая панель (дашборд)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        
        self.dashboard = DashboardWidget()
        left_layout.addWidget(self.dashboard)
        
        # Правая панель (таблица и безопасность)
        right_panel = QTabWidget()
        right_panel.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: rgba(50, 50, 60, 200);
                color: #AAAAAA;
                padding: 10px 20px;
                margin-right: 2px;
                font-weight: bold;
                font-size: 12px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background: rgba(93, 106, 251, 200);
                color: #FFFFFF;
            }
            QTabBar::tab:hover:!selected {
                background: rgba(70, 70, 80, 200);
            }
        """)
        
        # Вкладка соединений
        connections_tab = QWidget()
        connections_layout = QVBoxLayout(connections_tab)
        connections_layout.setContentsMargins(0, 0, 0, 0)
        
        # Панель управления для таблицы
        table_control = QHBoxLayout()
        table_control.addWidget(QLabel("🌐 Активные сетевые подключения"))
        table_control.addStretch()
        
        refresh_btn = ModernButton("🔄 Обновить")
        refresh_btn.setFixedWidth(100)
        table_control.addWidget(refresh_btn)
        
        self.connections_table = ConnectionsTable()
        
        connections_layout.addLayout(table_control)
        connections_layout.addWidget(self.connections_table)
        
        # Вкладка безопасности
        security_tab = SecurityPanel()
        
        right_panel.addTab(connections_tab, "🌐 ПОДКЛЮЧЕНИЯ")
        right_panel.addTab(security_tab, "🛡️ БЕЗОПАСНОСТЬ")
        
        # Разделитель
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 1000])
        splitter.setHandleWidth(3)
        
        content_layout.addWidget(splitter)
        main_layout.addWidget(content_widget)
        
        # Статус бар
        self.setup_status_bar()
        
        # Анимация появления
        self.setWindowOpacity(0)
        self.fade_in()
        
    def create_title_bar(self):
        """Создание кастомной панели заголовка"""
        title_bar = QWidget()
        title_bar.setFixedHeight(45)
        title_bar.setStyleSheet("""
            QWidget {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(30, 30, 40, 255),
                    stop:1 rgba(20, 20, 30, 255)
                );
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
        """)
        
        layout = QHBoxLayout(title_bar)
        layout.setContentsMargins(15, 0, 15, 0)
        
        # Логотип и заголовок
        logo_label = QLabel("🌀 NEO NETWORK ANALYZER")
        logo_label.setStyleSheet("""
            QLabel {
                color: #FFFFFF;
                font-size: 16px;
                font-weight: bold;
                letter-spacing: 0.5px;
            }
        """)
        
        subtitle_label = QLabel("Advanced Security Scanner | By @concole_hack")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: #5D6AFB;
                font-size: 10px;
                font-weight: bold;
            }
        """)
        
        # Кнопки управления окном
        btn_minimize = QPushButton("—")
        btn_minimize.setFixedSize(25, 25)
        btn_minimize.setStyleSheet("""
            QPushButton {
                background: rgba(80, 80, 90, 200);
                border: none;
                border-radius: 3px;
                color: white;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: rgba(100, 100, 110, 200);
            }
        """)
        btn_minimize.clicked.connect(self.showMinimized)
        
        btn_maximize = QPushButton("□")
        btn_maximize.setFixedSize(25, 25)
        btn_maximize.setStyleSheet(btn_minimize.styleSheet())
        btn_maximize.clicked.connect(self.toggle_maximize)
        
        btn_close = QPushButton("✕")
        btn_close.setFixedSize(25, 25)
        btn_close.setStyleSheet("""
            QPushButton {
                background: #FF6B6B;
                border: none;
                border-radius: 3px;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #FF5252;
            }
        """)
        btn_close.clicked.connect(self.close)
        
        layout.addWidget(logo_label)
        layout.addStretch()
        layout.addWidget(subtitle_label)
        layout.addStretch()
        layout.addWidget(btn_minimize)
        layout.addWidget(btn_maximize)
        layout.addWidget(btn_close)
        
        return title_bar
        
    def setup_status_bar(self):
        """Настройка статус бара"""
        self.status_bar = self.statusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background: rgba(25, 25, 30, 255);
                color: #AAAAAA;
                font-size: 10px;
                padding: 5px;
                border-top: 1px solid rgba(50, 50, 60, 200);
            }
        """)
        
        # Виджеты статус бара
        self.status_label = QLabel("🟢 Система активна | Инициализация...")
        self.status_bar.addWidget(self.status_label)
        
        self.connection_count = QLabel("Подключения: 0")
        self.status_bar.addPermanentWidget(self.connection_count)
        
        self.cpu_label = QLabel("CPU: 0%")
        self.status_bar.addPermanentWidget(self.cpu_label)
        
        self.ram_label = QLabel("RAM: 0%")
        self.status_bar.addPermanentWidget(self.ram_label)
        
        self.time_label = QLabel("Время: --:--:--")
        self.status_bar.addPermanentWidget(self.time_label)
        
        # Таймер для обновления статуса
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)
        
    def setup_tray(self):
        """Настройка системного трея"""
        try:
            self.tray_icon = QSystemTrayIcon(self)
            self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
            
            tray_menu = QMenu()
            
            show_action = tray_menu.addAction("Показать")
            show_action.triggered.connect(self.show_normal)
            
            hide_action = tray_menu.addAction("Скрыть")
            hide_action.triggered.connect(self.hide)
            
            tray_menu.addSeparator()
            
            exit_action = tray_menu.addAction("Выход")
            exit_action.triggered.connect(self.quit_app)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
            self.tray_icon.activated.connect(self.tray_icon_activated)
        except:
            print("Системный трей не доступен")
        
    def start_monitoring(self):
        """Запуск мониторинга сети"""
        try:
            # Инициализация начальных значений
            io_counters = psutil.net_io_counters()
            self.network_stats['last_bytes_recv'] = io_counters.bytes_recv
            self.network_stats['last_bytes_sent'] = io_counters.bytes_sent
            
            self.scanner = NetworkScanner()
            self.scanner.network_scan.connect(self.update_network_data)
            self.scanner.start()
            
            self.status_label.setText("🟢 Система активна | Мониторинг запущен")
        except Exception as e:
            print(f"Ошибка запуска мониторинга: {e}")
            self.status_label.setText("🔴 Ошибка мониторинга")
        
    def update_network_data(self, connections):
        """Обновление данных сети"""
        try:
            self.network_stats['connections'] = connections
            
            # Обновляем статистику сети
            io_counters = psutil.net_io_counters()
            
            current_recv = io_counters.bytes_recv
            current_sent = io_counters.bytes_sent
            
            # Рассчитываем скорость (байт/сек)
            recv_diff = current_recv - self.network_stats['last_bytes_recv']
            sent_diff = current_sent - self.network_stats['last_bytes_sent']
            
            self.network_stats['received'] = current_recv
            self.network_stats['sent'] = current_sent
            self.network_stats['network_speed'] = recv_diff + sent_diff
            
            # Сохраняем для следующего расчета
            self.network_stats['last_bytes_recv'] = current_recv
            self.network_stats['last_bytes_sent'] = current_sent
            
            # Обновляем UI
            self.connections_table.update_connections(connections)
            self.dashboard.update_metrics(self.network_stats)
            self.connection_count.setText(f"Подключения: {len(connections)}")
            
        except Exception as e:
            print(f"Ошибка обновления данных сети: {e}")
        
    def update_status(self):
        """Обновление статуса системы"""
        try:
            # CPU и RAM
            cpu_percent = psutil.cpu_percent(interval=None)
            ram_percent = psutil.virtual_memory().percent
            
            self.cpu_label.setText(f"CPU: {cpu_percent:.1f}%")
            self.ram_label.setText(f"RAM: {ram_percent:.1f}%")
            
            # Время
            current_time = datetime.now().strftime("%H:%M:%S")
            self.time_label.setText(f"Время: {current_time}")
            
        except Exception as e:
            print(f"Ошибка обновления статуса: {e}")
            
    def fade_in(self):
        """Анимация появления окна"""
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(300)
        self.animation.setStartValue(0)
        self.animation.setEndValue(1)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)
        self.animation.start()
        
    def toggle_maximize(self):
        """Переключение максимизации окна"""
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
            
    def show_normal(self):
        """Показать окно нормально"""
        self.showNormal()
        self.activateWindow()
        self.raise_()
        
    def tray_icon_activated(self, reason):
        """Обработка кликов по иконке в трее"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_normal()
            
    def closeEvent(self, event):
        """Обработка закрытия окна"""
        reply = QMessageBox.question(
            self, 'Подтверждение',
            'Вы уверены, что хотите закрыть NeoNetwork Analyzer?\n\n'
            'Приложение продолжит работу в системном трее.\n'
            'Для полного выхода выберите "Выход" в меню трея.',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.hide()
            event.ignore()
        else:
            event.ignore()
            
    def quit_app(self):
        """Полный выход из приложения"""
        try:
            if hasattr(self, 'scanner'):
                self.scanner.stop()
                self.scanner.wait(2000)
        except:
            pass
        
        QApplication.quit()

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NeoNetwork Analyzer")
    app.setApplicationVersion("1.0")
    
    # Устанавливаем иконку приложения
    try:
        app.setWindowIcon(QtGui.QIcon('icon.png'))
    except:
        pass
    
    # Устанавливаем темную тему
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5() + """
        * {
            font-family: 'Segoe UI', Arial, sans-serif;
            outline: none;
        }
        
        QMainWindow {
            background: transparent;
        }
        
        QScrollBar:vertical {
            background: rgba(60, 60, 70, 100);
            width: 10px;
            border-radius: 5px;
        }
        
        QScrollBar::handle:vertical {
            background: rgba(93, 106, 251, 150);
            border-radius: 5px;
            min-height: 20px;
        }
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
    """)
    
    # Создаем и показываем главное окно
    window = NeoNetworkAnalyzer()
    
    # Центрируем окно
    screen_geometry = app.primaryScreen().availableGeometry()
    window_geometry = window.frameGeometry()
    window_geometry.moveCenter(screen_geometry.center())
    window.move(window_geometry.topLeft())
    
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
