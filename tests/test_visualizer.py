import pytest
import pandas as pd
import numpy as np
import os
from pathlib import Path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from visualizer import (
    ensure_reports_dir,
    plot_top_ips,
    plot_cvss_distribution,
    _create_empty_plot,
    VisualizationError
)


class TestDirectoryManagement:
    """Тесты для управления директориями"""
    
    def test_ensure_reports_dir_creation(self, tmp_path):
        """Тест создания директории"""
        test_dir = tmp_path / "test_plots"
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


class TestPlotTopIPs:
    """Тесты для функции plot_top_ips"""
    
    @pytest.fixture
    def sample_ip_df(self):
        """Создаёт пример DataFrame с IP"""
        return pd.DataFrame({
            'src_ip': ['192.168.1.10', '192.168.1.20', '192.168.1.30', 
                       '192.168.1.40', '192.168.1.50'],
            'count': [25, 18, 12, 7, 3]
        })
    
    def test_basic_plot(self, sample_ip_df, tmp_path):
        """Тест базового построения графика"""
        filepath = plot_top_ips(
            sample_ip_df, 
            filename="test.png", 
            reports_dir=str(tmp_path),
            top_n=5
        )
        
        assert os.path.exists(filepath)
        assert filepath.endswith("test.png")
        assert Path(filepath).stat().st_size > 0
    
    def test_empty_dataframe(self, tmp_path):
        """Тест с пустым DataFrame"""
        empty_df = pd.DataFrame(columns=['src_ip', 'count'])
        
        filepath = plot_top_ips(empty_df, "empty.png", str(tmp_path))
        
        assert os.path.exists(filepath)
    
    def test_custom_top_n(self, sample_ip_df, tmp_path):
        """Тест с пользовательским количеством IP"""
        filepath = plot_top_ips(
            sample_ip_df,
            filename="top3.png",
            reports_dir=str(tmp_path),
            top_n=3
        )
        
        assert os.path.exists(filepath)
    
    def test_custom_title(self, sample_ip_df, tmp_path):
        """Тест с пользовательским заголовком"""
        custom_title = "Custom Title Test"
        filepath = plot_top_ips(
            sample_ip_df,
            filename="custom_title.png",
            reports_dir=str(tmp_path),
            title=custom_title,
            top_n=5
        )
        
        assert os.path.exists(filepath)
    
    def test_custom_figsize(self, sample_ip_df, tmp_path):
        """Тест с пользовательским размером фигуры"""
        filepath = plot_top_ips(
            sample_ip_df,
            filename="custom_size.png",
            reports_dir=str(tmp_path),
            figsize=(10, 6),
            top_n=5
        )
        
        assert os.path.exists(filepath)


class TestPlotCVSSDistribution:
    """Тесты для функции plot_cvss_distribution"""
    
    @pytest.fixture
    def sample_cvss_series(self):
        """Создаёт пример Series с CVSS"""
        return pd.Series([9.8, 8.5, 7.2, 6.5, 5.8, 4.2, 3.1, 2.0, 1.5, 9.2, 7.8, 6.7])
    
    def test_basic_histogram(self, sample_cvss_series, tmp_path):
        """Тест базового построения гистограммы"""
        filepath = plot_cvss_distribution(
            sample_cvss_series, 
            "test.png", 
            str(tmp_path)
        )
        
        assert os.path.exists(filepath)
        assert filepath.endswith("test.png")
        assert Path(filepath).stat().st_size > 0
    
    def test_empty_series(self, tmp_path):
        """Тест с пустой Series"""
        empty_series = pd.Series(dtype=float)
        
        filepath = plot_cvss_distribution(empty_series, "empty.png", str(tmp_path))
        
        assert os.path.exists(filepath)
    
    def test_series_with_nan(self, tmp_path):
        """Тест с Series, содержащей NaN"""
        series_with_nan = pd.Series([9.8, np.nan, 7.2, None, 5.5])
        
        filepath = plot_cvss_distribution(series_with_nan, "with_nan.png", str(tmp_path))
        
        assert os.path.exists(filepath)
    
    def test_custom_bins(self, sample_cvss_series, tmp_path):
        """Тест с пользовательским количеством бинов"""
        filepath = plot_cvss_distribution(
            sample_cvss_series,
            filename="custom_bins.png",
            reports_dir=str(tmp_path),
            bins=10
        )
        
        assert os.path.exists(filepath)
    
    def test_custom_title(self, sample_cvss_series, tmp_path):
        """Тест с пользовательским заголовком"""
        custom_title = "Custom CVSS Distribution"
        filepath = plot_cvss_distribution(
            sample_cvss_series,
            filename="custom_title.png",
            reports_dir=str(tmp_path),
            title=custom_title
        )
        
        assert os.path.exists(filepath)
    
    def test_without_stats(self, sample_cvss_series, tmp_path):
        """Тест без отображения статистики"""
        filepath = plot_cvss_distribution(
            sample_cvss_series,
            filename="no_stats.png",
            reports_dir=str(tmp_path),
            show_stats=False
        )
        
        assert os.path.exists(filepath)


class TestEmptyPlot:
    """Тесты для функции _create_empty_plot"""
    
    def test_create_empty_plot(self, tmp_path):
        """Тест создания пустого графика"""
        filepath = tmp_path / "empty.png"
        result = _create_empty_plot(filepath, "Test message", (8, 4))
        
        assert os.path.exists(filepath)
        assert result == str(filepath)
    
    def test_empty_plot_with_different_messages(self, tmp_path):
        """Тест создания пустого графика с разными сообщениями"""
        messages = ["Нет данных", "Ошибка", "Пусто"]
        
        for msg in messages:
            filepath = tmp_path / f"empty_{msg}.png"
            result = _create_empty_plot(filepath, msg, (8, 4))
            
            assert os.path.exists(filepath)
            assert result == str(filepath)


class TestIntegration:
    """Интеграционные тесты для визуализации"""
    
    def test_full_pipeline(self, tmp_path):
        """Тест полного цикла визуализации с реальными данными"""
        # Подготовка данных
        ip_df = pd.DataFrame({
            'src_ip': ['192.168.1.10', '192.168.1.20', '192.168.1.30'],
            'count': [15, 8, 3]
        })
        
        cvss_series = pd.Series([9.8, 7.2, 5.5, 4.1, 2.3])
        
        # Создание графиков
        ip_path = plot_top_ips(
            ip_df, 
            "integration_ip.png", 
            str(tmp_path),
            top_n=3
        )
        
        cvss_path = plot_cvss_distribution(
            cvss_series, 
            "integration_cvss.png", 
            str(tmp_path)
        )
        
        # Проверки
        assert os.path.exists(ip_path)
        assert os.path.exists(cvss_path)
        assert Path(ip_path).stat().st_size > 0
        assert Path(cvss_path).stat().st_size > 0
    
    def test_with_minimal_data(self, tmp_path):
        """Тест с минимальными данными"""
        ip_df = pd.DataFrame({'src_ip': ['192.168.1.1'], 'count': [1]})
        cvss_series = pd.Series([5.0])
        
        ip_path = plot_top_ips(ip_df, "min_ip.png", str(tmp_path), top_n=1)
        cvss_path = plot_cvss_distribution(cvss_series, "min_cvss.png", str(tmp_path))
        
        assert os.path.exists(ip_path)
        assert os.path.exists(cvss_path)
    
    def test_with_large_numbers(self, tmp_path):
        """Тест с большими числами"""
        ip_df = pd.DataFrame({
            'src_ip': [f'192.168.1.{i}' for i in range(1, 11)],
            'count': [i * 100 for i in range(1, 11)]
        })
        
        cvss_series = pd.Series([x * 0.1 for x in range(0, 100)])
        
        ip_path = plot_top_ips(ip_df, "large_ip.png", str(tmp_path), top_n=10)
        cvss_path = plot_cvss_distribution(cvss_series, "large_cvss.png", str(tmp_path))
        
        assert os.path.exists(ip_path)
        assert os.path.exists(cvss_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])