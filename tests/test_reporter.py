import pytest
import pandas as pd
import json
import os
import tempfile
import shutil
from datetime import datetime, timedelta
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reporter import (
    ensure_reports_dir,
    save_cves,
    save_top_ips,
    save_summary,
    save_all_reports,
    cleanup_old_reports,
    ReportError,
    DirectoryCreationError,
    FileWriteError,
    DataValidationError,
    validate_dataframe,
    validate_dict
)


class TestDirectoryManagement:
    """Тесты для управления директориями"""
    
    def test_ensure_reports_dir_creation(self, tmp_path):
        """Тест создания директории"""
        test_dir = tmp_path / "test_reports"
        assert not test_dir.exists()
        
        result = ensure_reports_dir(str(test_dir))
        assert test_dir.exists()
        assert result == test_dir
    
    def test_ensure_reports_dir_existing(self, tmp_path):
        """Тест с уже существующей директорией"""
        test_dir = tmp_path / "existing"
        test_dir.mkdir()
        
        result = ensure_reports_dir(str(test_dir))
        assert test_dir.exists()
        assert result == test_dir


class TestDataValidation:
    """Тесты для функций валидации"""
    
    def test_validate_dataframe_valid(self):
        """Тест валидации корректного DataFrame"""
        df = pd.DataFrame({'a': [1, 2], 'b': [3, 4]})
        assert validate_dataframe(df, ['a', 'b']) is True
    
    def test_validate_dataframe_none(self):
        """Тест с None вместо DataFrame"""
        with pytest.raises(DataValidationError, match="не может быть None"):
            validate_dataframe(None)
    
    def test_validate_dataframe_invalid_type(self):
        """Тест с некорректным типом"""
        with pytest.raises(DataValidationError, match="Ожидался DataFrame"):
            validate_dataframe("not a dataframe")
    
    def test_validate_dataframe_missing_columns(self):
        """Тест с отсутствующими колонками"""
        df = pd.DataFrame({'a': [1, 2]})
        with pytest.raises(DataValidationError, match="отсутствуют колонки"):
            validate_dataframe(df, ['a', 'b'])
    
    def test_validate_dict_valid(self):
        """Тест валидации корректного словаря"""
        data = {'a': 1, 'b': 2}
        assert validate_dict(data, ['a', 'b']) is True
    
    def test_validate_dict_none(self):
        """Тест с None вместо словаря"""
        with pytest.raises(DataValidationError, match="не может быть None"):
            validate_dict(None)
    
    def test_validate_dict_invalid_type(self):
        """Тест с некорректным типом"""
        with pytest.raises(DataValidationError, match="Ожидался словарь"):
            validate_dict([1, 2, 3])
    
    def test_validate_dict_missing_keys(self):
        """Тест с отсутствующими ключами"""
        data = {'a': 1}
        with pytest.raises(DataValidationError, match="отсутствуют ключи"):
            validate_dict(data, ['a', 'b'])


class TestSaveCVEs:
    """Тесты для функции save_cves"""
    
    @pytest.fixture
    def sample_cve_df(self):
        """Создаёт пример DataFrame с CVE"""
        return pd.DataFrame({
            'cve_id': ['CVE-2023-1234', 'CVE-2023-5678'],
            'cvss': [9.8, 7.5],
            'description': ['Critical RCE', 'High XSS']
        })
    
    def test_save_cves_basic(self, sample_cve_df, tmp_path):
        """Тест базового сохранения CVE"""
        filepath = save_cves(sample_cve_df, "test_cves.csv", str(tmp_path))
        
        assert os.path.exists(filepath)
        
        # Проверяем содержимое
        loaded_df = pd.read_csv(filepath)
        assert len(loaded_df) == 2
        assert 'cve_id' in loaded_df.columns
        assert loaded_df.iloc[0]['cve_id'] == 'CVE-2023-1234'
    
    def test_save_cves_empty(self, tmp_path):
        """Тест сохранения пустого DataFrame"""
        empty_df = pd.DataFrame(columns=['cve_id', 'cvss'])
        
        filepath = save_cves(empty_df, "empty_cves.csv", str(tmp_path))
        assert os.path.exists(filepath)
        
        loaded_df = pd.read_csv(filepath)
        assert loaded_df.empty
    
    def test_save_cves_invalid_data(self):
        """Тест с некорректными данными"""
        from reporter import DataValidationError
        
        with pytest.raises(DataValidationError):
            save_cves("not a dataframe")
    
    def test_save_cves_with_index(self, sample_cve_df, tmp_path):
        """Тест сохранения с индексом"""
        filepath = save_cves(sample_cve_df, "with_index.csv", str(tmp_path), include_index=True)
        
        loaded_df = pd.read_csv(filepath)
        assert 'Unnamed: 0' in loaded_df.columns or 'index' in loaded_df.columns
    
    def test_save_cves_permission_error(self, sample_cve_df, tmp_path, monkeypatch):
        """Тест ошибки прав доступа"""
        from reporter import FileWriteError
        
        # Мокаем open чтобы он кидал исключение
        def mock_open(*args, **kwargs):
            raise PermissionError("Permission denied")
        
        monkeypatch.setattr("builtins.open", mock_open)
        
        with pytest.raises(FileWriteError):
            save_cves(sample_cve_df, "test.csv", str(tmp_path))


class TestSaveTopIPs:
    """Тесты для функции save_top_ips"""
    
    @pytest.fixture
    def sample_ip_df(self):
        """Создаёт пример DataFrame с IP"""
        return pd.DataFrame({
            'src_ip': ['192.168.1.10', '192.168.1.20', '192.168.1.30'],
            'count': [15, 8, 3],
            'avg_severity': [1.2, 2.0, 2.7]
        })
    
    def test_save_ips_basic(self, sample_ip_df, tmp_path):
        """Тест базового сохранения IP"""
        filepath = save_top_ips(sample_ip_df, "test_ips.csv", str(tmp_path))
        
        assert os.path.exists(filepath)
        
        loaded_df = pd.read_csv(filepath)
        assert len(loaded_df) == 3
        assert 'src_ip' in loaded_df.columns
        assert loaded_df.iloc[0]['src_ip'] == '192.168.1.10'
    
    def test_save_ips_empty(self, tmp_path):
        """Тест сохранения пустого DataFrame"""
        empty_df = pd.DataFrame(columns=['src_ip', 'count'])
        
        filepath = save_top_ips(empty_df, "empty_ips.csv", str(tmp_path))
        assert os.path.exists(filepath)
        assert pd.read_csv(filepath).empty


class TestSaveSummary:
    """Тесты для функции save_summary"""
    
    @pytest.fixture
    def sample_stats(self):
        """Создаёт пример статистики"""
        return {
            'total_alerts': 100,
            'unique_ips': 25,
            'severity_distribution': {1: 50, 2: 30, 3: 20},
            'scan_time': datetime.now().isoformat(),
            'threat_level': 'HIGH'
        }
    
    def test_save_summary_basic(self, sample_stats, tmp_path):
        """Тест базового сохранения JSON"""
        filepath = save_summary(sample_stats, "test_stats.json", str(tmp_path))
        
        assert os.path.exists(filepath)
        
        with open(filepath, 'r', encoding='utf-8') as f:
            loaded_stats = json.load(f)
        
        assert loaded_stats['total_alerts'] == 100
        assert loaded_stats['unique_ips'] == 25
        assert loaded_stats['threat_level'] == 'HIGH'
    
    def test_save_summary_with_numpy_types(self, tmp_path):
        """Тест сохранения с numpy типами"""
        import numpy as np
        
        stats = {
            'int_value': np.int64(42),
            'float_value': np.float64(3.14),
            'array_value': np.array([1, 2, 3])
        }
        
        filepath = save_summary(stats, "numpy_stats.json", str(tmp_path))
        
        with open(filepath, 'r', encoding='utf-8') as f:
            loaded = json.load(f)
        
        assert loaded['int_value'] == 42
        assert loaded['float_value'] == 3.14
        assert loaded['array_value'] == [1, 2, 3]
    
    def test_save_summary_empty(self, tmp_path):
        """Тест сохранения пустого словаря"""
        filepath = save_summary({}, "empty.json", str(tmp_path))
        
        with open(filepath, 'r', encoding='utf-8') as f:
            loaded = json.load(f)
        
        assert loaded == {}


class TestSaveAllReports:
    """Тесты для функции save_all_reports"""
    
    @pytest.fixture
    def test_data(self):
        """Создаёт тестовые данные"""
        cves = pd.DataFrame({
            'cve_id': ['CVE-2023-1234'],
            'cvss': [9.8]
        })
        
        ips = pd.DataFrame({
            'src_ip': ['192.168.1.10'],
            'count': [10]
        })
        
        stats = {'total_alerts': 10}
        
        return cves, ips, stats
    
    def test_save_all_basic(self, test_data, tmp_path):
        """Тест сохранения всех отчётов"""
        cves, ips, stats = test_data
        
        results = save_all_reports(cves, ips, stats, str(tmp_path))
        
        assert 'cve_file' in results
        assert 'ip_file' in results
        assert 'json_file' in results
        
        assert results['cve_file'] is not None
        assert results['ip_file'] is not None
        assert results['json_file'] is not None
        
        assert os.path.exists(results['cve_file'])
        assert os.path.exists(results['ip_file'])
        assert os.path.exists(results['json_file'])
    
    def test_save_all_with_prefix(self, test_data, tmp_path):
        """Тест сохранения с префиксом"""
        cves, ips, stats = test_data
        
        results = save_all_reports(cves, ips, stats, str(tmp_path), prefix="test_")
        
        assert "test_" in results['cve_file']
        assert "test_" in results['ip_file']
        assert "test_" in results['json_file']
    
    def test_save_all_partial_failure(self, test_data, tmp_path):
        """Тест с частичными ошибками"""
        cves, ips, stats = test_data
        
        # Портим один DataFrame
        bad_cves = "not a dataframe"
        
        results = save_all_reports(bad_cves, ips, stats, str(tmp_path))
        
        assert results['cve_file'] is None
        assert results['ip_file'] is not None
        assert results['json_file'] is not None


class TestCleanupOldReports:
    """Тесты для функции cleanup_old_reports"""
    
    def test_cleanup_old_files(self, tmp_path):
        """Тест удаления старых файлов"""
        # Создаём старые файлы
        for i in range(5):
            file_path = tmp_path / f"old_file_{i}.csv"
            file_path.touch()
            # Устанавливаем время модификации на 10 дней назад
            old_time = (datetime.now() - timedelta(days=10)).timestamp()
            os.utime(file_path, (old_time, old_time))
        
        # Создаём новые файлы
        for i in range(3):
            file_path = tmp_path / f"new_file_{i}.csv"
            file_path.touch()
        
        deleted = cleanup_old_reports(str(tmp_path), days_to_keep=7)
        
        assert deleted == 5
        assert len(list(tmp_path.glob("*.csv"))) == 3
    
    def test_cleanup_nonexistent_dir(self):
        """Тест с несуществующей директорией"""
        deleted = cleanup_old_reports("/nonexistent/path")
        assert deleted == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])