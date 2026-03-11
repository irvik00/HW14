import pytest
import json
import os
import tempfile
import gzip
from datetime import datetime
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_parser import (
    parse_suricata_logs,
    stream_suricata_logs,
    get_log_statistics,
    validate_log_format,
    SuricataParseError,
    FileAccessError,
    SuricataAlert
)


class TestSuricataAlert:
    """Тесты для dataclass SuricataAlert"""
    
    def test_alert_creation(self):
        """Тест создания объекта alert"""
        alert = SuricataAlert(
            timestamp='2023-01-01T00:00:00',
            src_ip='192.168.1.1',
            alert_severity=1,
            alert_signature='Test Signature'
        )
        
        assert alert.timestamp == '2023-01-01T00:00:00'
        assert alert.src_ip == '192.168.1.1'
        assert alert.alert_severity == 1
        assert alert.alert_signature == 'Test Signature'
        assert alert.dest_ip is None
    
    def test_to_dict(self):
        """Тест конвертации в словарь"""
        alert = SuricataAlert(
            timestamp='2023-01-01T00:00:00',
            src_ip='192.168.1.1',
            alert_severity=1,
            alert_signature='Test',
            dest_ip='8.8.8.8'
        )
        
        d = alert.to_dict()
        assert d['timestamp'] == '2023-01-01T00:00:00'
        assert d['src_ip'] == '192.168.1.1'
        assert d['dest_ip'] == '8.8.8.8'
        assert 'proto' not in d  # None поля не должны быть в словаре
    
    def test_severity_level(self):
        """Тест текстового уровня серьёзности"""
        alert = SuricataAlert(
            timestamp='',
            src_ip='',
            alert_severity=1,
            alert_signature=''
        )
        assert alert.severity_level == 'HIGH'
        
        alert.alert_severity = 2
        assert alert.severity_level == 'MEDIUM'
        
        alert.alert_severity = 3
        assert alert.severity_level == 'LOW'
        
        alert.alert_severity = 999
        assert alert.severity_level == 'UNKNOWN'


class TestParseSuricataLogs:
    """Тесты для функции parse_suricata_logs"""
    
    @pytest.fixture
    def sample_log_lines(self):
        """Создаёт пример логов для тестов"""
        return [
            json.dumps({
                "timestamp": "2023-01-01T00:00:01",
                "event_type": "alert",
                "src_ip": "192.168.1.10",
                "dest_ip": "8.8.8.8",
                "proto": "TCP",
                "src_port": 12345,
                "dest_port": 80,
                "alert": {
                    "severity": 1,
                    "signature": "ET MALWARE Test"
                }
            }),
            json.dumps({
                "timestamp": "2023-01-01T00:00:02",
                "event_type": "alert",
                "src_ip": "192.168.1.20",
                "alert": {
                    "severity": 2,
                    "signature": "ET POLICY Test"
                }
            }),
            json.dumps({
                "timestamp": "2023-01-01T00:00:03",
                "event_type": "http",  # не alert
                "src_ip": "192.168.1.30"
            }),
            "not json",  # битая строка
            json.dumps({
                "timestamp": "2023-01-01T00:00:04",
                "event_type": "alert",
                "src_ip": "192.168.1.40",
                "alert": {
                    "severity": "3",  # строка, но должна сконвертироваться
                    "signature": "ET SCAN Test"
                }
            }),
        ]
    
    @pytest.fixture
    def temp_log_file(self, sample_log_lines):
        """Создаёт временный файл с логами"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            for line in sample_log_lines:
                f.write(line + '\n')
            temp_path = f.name
        
        yield temp_path
        
        # Очистка
        os.unlink(temp_path)
    
    @pytest.fixture
    def temp_gz_log_file(self, sample_log_lines):
        """Создаёт сжатый gzip файл с логами"""
        temp_path = tempfile.mktemp(suffix='.gz')
        with gzip.open(temp_path, 'wt', encoding='utf-8') as f:
            for line in sample_log_lines:
                f.write(line + '\n')
        
        yield temp_path
        
        # Очистка
        os.unlink(temp_path)
    
    def test_basic_parsing(self, temp_log_file):
        """Тест базового парсинга"""
        alerts = parse_suricata_logs(temp_log_file)
        
        # Должны быть найдены 3 alert'а (первый, второй и пятый)
        assert len(alerts) == 3
        
        # Проверяем первый alert
        assert alerts[0]['src_ip'] == '192.168.1.10'
        assert alerts[0]['alert_severity'] == 1
        assert alerts[0]['alert_signature'] == 'ET MALWARE Test'
        assert alerts[0]['dest_ip'] == '8.8.8.8'
        assert alerts[0]['proto'] == 'TCP'
        
        # Проверяем второй alert
        assert alerts[1]['src_ip'] == '192.168.1.20'
        assert alerts[1]['alert_severity'] == 2
        
        # Проверяем пятый (severity как строка)
        assert alerts[2]['src_ip'] == '192.168.1.40'
        assert alerts[2]['alert_severity'] == 3
    
    def test_max_alerts_limit(self, temp_log_file):
        """Тест ограничения количества событий"""
        alerts = parse_suricata_logs(temp_log_file, max_alerts=2)
        assert len(alerts) == 2
    
    def test_severity_filter(self, temp_log_file):
        """Тест фильтрации по severity"""
        alerts = parse_suricata_logs(temp_log_file, severity_filter=[1])
        assert len(alerts) == 1
        assert alerts[0]['alert_severity'] == 1
        
        alerts = parse_suricata_logs(temp_log_file, severity_filter=[2, 3])
        assert len(alerts) == 2
        assert all(a['alert_severity'] in [2, 3] for a in alerts)
    
    def test_gz_file_parsing(self, temp_gz_log_file):
        """Тест парсинга сжатого gz файла"""
        alerts = parse_suricata_logs(temp_gz_log_file)
        assert len(alerts) == 3
    
    def test_file_not_found(self):
        """Тест обработки отсутствующего файла"""
        with pytest.raises(FileAccessError, match="Файл не найден"):
            parse_suricata_logs("nonexistent_file.json")
    
    def test_empty_file(self):
        """Тест с пустым файлом"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            temp_path = f.name
        
        try:
            alerts = parse_suricata_logs(temp_path)
            assert alerts == []
        finally:
            os.unlink(temp_path)
    
    def test_malformed_json_handling(self, caplog):
        """Тест обработки битых JSON строк"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            f.write('{"valid": "json"}\n')
            f.write('not json\n')
            f.write('also not json\n')
            f.write('{"another": "valid"}\n')
            temp_path = f.name
        
        try:
            with caplog.at_level('WARNING'):
                alerts = parse_suricata_logs(temp_path)
                assert len(alerts) == 0  # нет alert событий
                assert "не является валидным JSON" in caplog.text
        finally:
            os.unlink(temp_path)


class TestStreamSuricataLogs:
    """Тесты для функции stream_suricata_logs"""
    
    def test_streaming(self):
        """Тест потокового чтения"""
        # Создаём файл с 150 alert'ами
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            for i in range(150):
                event = {
                    "timestamp": f"2023-01-01T00:00:{i:02d}",
                    "event_type": "alert",
                    "src_ip": f"192.168.1.{i % 255}",
                    "alert": {"severity": 1, "signature": f"Test {i}"}
                }
                f.write(json.dumps(event) + '\n')
            temp_path = f.name
        
        try:
            chunks = list(stream_suricata_logs(temp_path, chunk_size=50))
            assert len(chunks) == 3  # 150 / 50 = 3 чанка
            assert len(chunks[0]) == 50
            assert len(chunks[1]) == 50
            assert len(chunks[2]) == 50
        finally:
            os.unlink(temp_path)


class TestLogStatistics:
    """Тесты для функции get_log_statistics"""
    
    def test_empty_statistics(self):
        """Тест статистики для пустого списка"""
        stats = get_log_statistics([])
        assert stats['total_alerts'] == 0
        assert stats['unique_ips'] == 0
    
    def test_basic_statistics(self):
        """Тест базовой статистики"""
        alerts = [
            {'src_ip': '1.1.1.1', 'alert_severity': 1, 'alert_signature': 'Sig1'},
            {'src_ip': '1.1.1.1', 'alert_severity': 1, 'alert_signature': 'Sig1'},
            {'src_ip': '2.2.2.2', 'alert_severity': 2, 'alert_signature': 'Sig2'},
            {'src_ip': '3.3.3.3', 'alert_severity': 3, 'alert_signature': 'Sig3'},
        ]
        
        stats = get_log_statistics(alerts)
        
        assert stats['total_alerts'] == 4
        assert stats['unique_ips'] == 3
        assert stats['severity_distribution'][1] == 2
        assert stats['severity_distribution'][2] == 1
        assert stats['severity_distribution'][3] == 1
        assert 'Sig1' in stats['top_signatures']


class TestValidateLogFormat:
    """Тесты для функции validate_log_format"""
    
    def test_valid_format(self):
        """Тест валидного формата"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            f.write(json.dumps({"timestamp": "2023", "event_type": "alert"}) + '\n')
            f.write(json.dumps({"timestamp": "2023", "event_type": "http"}) + '\n')
            temp_path = f.name
        
        try:
            assert validate_log_format(temp_path) is True
        finally:
            os.unlink(temp_path)
    
    def test_invalid_format(self):
        """Тест невалидного формата"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            f.write("not json\n")
            f.write("also not json\n")
            temp_path = f.name
        
        try:
            assert validate_log_format(temp_path) is False
        finally:
            os.unlink(temp_path)
    
    def test_empty_file(self):
        """Тест пустого файла"""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            temp_path = f.name
        
        try:
            # Пустой файл считается валидным? Зависит от требований
            assert validate_log_format(temp_path) is True
        finally:
            os.unlink(temp_path)
    
    def test_nonexistent_file(self):
        """Тест несуществующего файла"""
        assert validate_log_format("nonexistent.json") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])