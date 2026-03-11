import pytest
import pandas as pd
import os
import tempfile
from datetime import datetime, timedelta
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from responder import (
    simulate_blocking,
    notify_critical_cves,
    notify_suspicious_ips,
    generate_threat_report,
    validate_ip_list,
    validate_cve_dataframe,
    ensure_log_file,
    ResponderError,
    DataValidationError,
    FileWriteError
)


class TestValidation:
    """Тесты для функций валидации"""
    
    def test_validate_ip_list_valid(self):
        """Тест валидации корректного списка IP"""
        ip_list = ['192.168.1.1', '10.0.0.1', '8.8.8.8']
        assert validate_ip_list(ip_list) is True
    
    def test_validate_ip_list_empty(self):
        """Тест валидации пустого списка"""
        assert validate_ip_list([]) is True
    
    def test_validate_ip_list_none(self):
        """Тест с None вместо списка"""
        with pytest.raises(DataValidationError, match="не может быть None"):
            validate_ip_list(None)
    
    def test_validate_ip_list_invalid_type(self):
        """Тест с некорректным типом"""
        with pytest.raises(DataValidationError, match="Ожидался список"):
            validate_ip_list("not a list")
    
    def test_validate_ip_list_invalid_ip_type(self):
        """Тест с IP не строкой"""
        with pytest.raises(DataValidationError, match="должен быть строкой"):
            validate_ip_list(['192.168.1.1', 123])
    
    def test_validate_ip_list_empty_string(self):
        """Тест с пустой строкой IP"""
        with pytest.raises(DataValidationError, match="не может быть пустым"):
            validate_ip_list(['192.168.1.1', ''])
    
    def test_validate_cve_dataframe_valid(self):
        """Тест валидации корректного DataFrame"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2023-1234'],
            'cvss': [9.8],
            'description': ['Test']
        })
        assert validate_cve_dataframe(df) is True
    
    def test_validate_cve_dataframe_none(self):
        """Тест с None вместо DataFrame"""
        with pytest.raises(DataValidationError, match="не может быть None"):
            validate_cve_dataframe(None)
    
    def test_validate_cve_dataframe_missing_columns(self):
        """Тест с отсутствующими колонками"""
        df = pd.DataFrame({'wrong_col': [1, 2]})
        with pytest.raises(DataValidationError, match="отсутствуют колонки"):
            validate_cve_dataframe(df)
    
    def test_ensure_log_file_valid(self, tmp_path):
        """Тест проверки доступности файла"""
        log_file = tmp_path / "test.log"
        path = ensure_log_file(str(log_file))
        assert path.exists() is False  # файл ещё не создан
        assert path.parent.exists()


class TestSimulateBlocking:
    """Тесты для функции simulate_blocking"""
    
    def test_basic_blocking(self, tmp_path):
        """Тест базовой блокировки"""
        log_file = tmp_path / "blocked.log"
        ip_list = ['192.168.1.10', '10.0.0.1']
        
        result = simulate_blocking(ip_list, "Test reason", str(log_file))
        
        assert result == 2
        assert log_file.exists()
        
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            assert '192.168.1.10' in content
            assert '10.0.0.1' in content
            assert 'Test reason' in content
    
    def test_empty_ip_list(self, tmp_path, capsys):
        """Тест с пустым списком IP"""
        log_file = tmp_path / "blocked.log"
        
        result = simulate_blocking([], "Test", str(log_file))
        
        assert result == 0
        assert not log_file.exists()  # файл не должен создаваться
        
        captured = capsys.readouterr()
        assert "Нет IP-адресов для блокировки" not in captured.out  # сообщение в консоль не выводится
    
    def test_no_console_output(self, tmp_path, capsys):
        """Тест без вывода в консоль"""
        log_file = tmp_path / "blocked.log"
        ip_list = ['192.168.1.10']
        
        result = simulate_blocking(ip_list, "Test", str(log_file), console_output=False)
        
        assert result == 1
        captured = capsys.readouterr()
        assert captured.out == ''  # ничего не выведено в консоль
    
    def test_invalid_ip_in_list(self, tmp_path, caplog):
        """Тест с некорректными IP в списке"""
        log_file = tmp_path / "blocked.log"
        ip_list = ['192.168.1.10', None, '', 123]
        
        with pytest.raises(DataValidationError):
            simulate_blocking(ip_list, "Test", str(log_file))
    
    def test_permission_error(self, monkeypatch):
        """Тест ошибки прав доступа"""
        import os
        
        # Создаём файл только для чтения
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            readonly_file = f.name
        
        # Делаем файл только для чтения (на Windows это сложнее)
        try:
            os.chmod(readonly_file, 0o444)  # read-only
            
            with pytest.raises(FileWriteError):
                simulate_blocking(['192.168.1.10'], "Test", readonly_file)
        finally:
            # Удаляем файл (на read-only файл может не дать удалить)
            os.chmod(readonly_file, 0o666)  # даём права на запись для удаления
            os.unlink(readonly_file)


class TestNotifyCriticalCVEs:
    """Тесты для функции notify_critical_cves"""
    
    @pytest.fixture
    def sample_cve_df(self):
        """Создаёт пример DataFrame с CVE"""
        return pd.DataFrame({
            'cve_id': ['CVE-2023-1234', 'CVE-2023-5678', 'CVE-2023-9012'],
            'cvss': [9.8, 7.2, 4.5],
            'description': [
                'Critical remote code execution vulnerability',
                'High severity cross-site scripting',
                'Medium information disclosure'
            ]
        })
    
    def test_basic_notification(self, sample_cve_df, capsys):
        """Тест базового уведомления"""
        stats = notify_critical_cves(sample_cve_df, threshold=7.0)
        
        assert stats['total_cves'] == 3
        assert stats['critical_cves'] == 2
        assert stats['max_cvss'] == 9.8
        
        captured = capsys.readouterr()
        assert 'CVE-2023-1234' in captured.out
        assert 'CVE-2023-5678' in captured.out
        assert 'CVE-2023-9012' not in captured.out  # некритичная
    
    def test_no_critical_cves(self, capsys):
        """Тест без критических уязвимостей"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2023-1234'],
            'cvss': [4.5],
            'description': ['Test']
        })
        
        stats = notify_critical_cves(df, threshold=7.0)
        
        assert stats['critical_cves'] == 0
        
        captured = capsys.readouterr()
        assert 'Критических уязвимостей' in captured.out
    
    def test_empty_dataframe(self, capsys):
        """Тест с пустым DataFrame"""
        df = pd.DataFrame(columns=['cve_id', 'cvss', 'description'])
        
        stats = notify_critical_cves(df)
        
        assert stats['critical_cves'] == 0
        assert stats['total_cves'] == 0
    
    def test_missing_description(self, capsys):
        """Тест с отсутствующим описанием"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2023-1234'],
            'cvss': [9.8]
            # нет колонки description
        })
        
        stats = notify_critical_cves(df)
        
        assert stats['critical_cves'] == 1
        
        captured = capsys.readouterr()
        assert 'No description' in captured.out
    
    def test_invalid_dataframe(self):
        """Тест с некорректным DataFrame"""
        with pytest.raises(DataValidationError):
            notify_critical_cves("not a dataframe")


class TestNotifySuspiciousIPs:
    """Тесты для функции notify_suspicious_ips"""
    
    @pytest.fixture
    def sample_ip_df(self):
        """Создаёт пример DataFrame с IP"""
        return pd.DataFrame({
            'src_ip': ['192.168.1.10', '192.168.1.20', '192.168.1.30', '192.168.1.40'],
            'count': [15, 8, 3, 1],
            'avg_severity': [1.2, 2.0, 2.5, 3.0]
        })
    
    def test_basic_notification(self, sample_ip_df, capsys):
        """Тест базового уведомления"""
        stats = notify_suspicious_ips(sample_ip_df, threshold=5)
        
        assert stats['total_ips'] == 4
        assert stats['suspicious_ips'] == 2
        assert stats['max_count'] == 15
        
        captured = capsys.readouterr()
        assert '192.168.1.10' in captured.out
        assert '192.168.1.20' in captured.out
        assert '192.168.1.30' not in captured.out
    
    def test_no_suspicious_ips(self, capsys):
        """Тест без подозрительных IP"""
        df = pd.DataFrame({
            'src_ip': ['192.168.1.10'],
            'count': [1]
        })
        
        stats = notify_suspicious_ips(df, threshold=5)
        
        assert stats['suspicious_ips'] == 0
        
        captured = capsys.readouterr()
        assert 'не обнаружено' in captured.out
    
    def test_empty_dataframe(self, capsys):
        """Тест с пустым DataFrame"""
        df = pd.DataFrame(columns=['src_ip', 'count'])
        
        stats = notify_suspicious_ips(df)
        
        assert stats['total_ips'] == 0
    
    def test_missing_severity_column(self, capsys):
        """Тест с отсутствующей колонкой severity"""
        df = pd.DataFrame({
            'src_ip': ['192.168.1.10'],
            'count': [10]
        })
        
        stats = notify_suspicious_ips(df, threshold=5)
        
        assert stats['suspicious_ips'] == 1
        
        captured = capsys.readouterr()
        assert 'событий: 10' in captured.out
        assert 'средний severity' not in captured.out
    
    def test_invalid_dataframe(self):
        """Тест с некорректным DataFrame"""
        result = notify_suspicious_ips("not a dataframe")
        assert 'error' in result


class TestGenerateThreatReport:
    """Тесты для функции generate_threat_report"""
    
    def test_basic_report(self):
        """Тест базовой генерации отчёта"""
        cve_stats = {
            'total_cves': 10,
            'critical_cves': 3,
            'threshold': 7.0,
            'max_cvss': 9.8,
            'avg_cvss': 8.2
        }
        
        ip_stats = {
            'total_ips': 20,
            'suspicious_ips': 5,
            'threshold': 5,
            'max_count': 15
        }
        
        block_count = 3
        
        report = generate_threat_report(cve_stats, ip_stats, block_count)
        
        assert 'ОТЧЁТ ОБ УГРОЗАХ' in report
        assert 'КРИТИЧЕСКИЕ УЯЗВИМОСТИ' in report
        assert 'ПОДОЗРИТЕЛЬНЫЕ IP' in report
        assert 'БЛОКИРОВКИ' in report
        assert 'Всего уязвимостей: 10' in report
        assert 'Всего уникальных IP: 20' in report
        assert 'Заблокировано IP: 3' in report
    
    def test_empty_stats(self):
        """Тест с пустой статистикой"""
        cve_stats = {'total_cves': 0, 'critical_cves': 0}
        ip_stats = {'total_ips': 0, 'suspicious_ips': 0}
        
        report = generate_threat_report(cve_stats, ip_stats, 0)
        
        assert 'Всего уязвимостей: 0' in report
        assert 'Всего уникальных IP: 0' in report
        assert 'Заблокировано IP: 0' in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])