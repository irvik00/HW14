import pytest
import sys
import os
import signal
from unittest.mock import patch, MagicMock, Mock, call
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import (
    parse_arguments,
    validate_configuration,
    collect_data,
    analyze_threats,
    respond_to_threats,
    generate_reports,
    create_visualizations,
    print_summary,
    signal_handler,
    main,
    ConfigurationError,
    DataCollectionError,
    AnalysisError,
    ThreatAnalyzerError
)


# Фикстура для мока config
@pytest.fixture
def mock_config():
    """Создаёт мок-конфиг для тестов"""
    config = MagicMock()
    config.log_file = "logs/test.json"
    config.vuln_limit = 30
    config.cvss_threshold = 7.0
    config.block_threshold = 3
    config.top_n = 5
    config.skip_vulns = False
    config.skip_logs = False
    config.test_mode = False
    config.email_enabled = False
    config.sender_email = "test@test.com"
    config.sender_password = "password"
    config.recipient_email = "test@test.com"
    config.smtp_server = "smtp.test.com"
    config.smtp_port = 587
    config.verbose = False
    return config


class TestParseArguments:
    """Тесты для функции parse_arguments"""
    
    def test_default_arguments(self, monkeypatch):
        """Тест аргументов по умолчанию"""
        monkeypatch.setattr(sys, 'argv', ['main.py'])
        args = parse_arguments()
        
        # ИСПРАВЛЕНО: теперь проверяем None, а не константы
        assert args.log_file is None
        assert args.vuln_limit is None
        assert args.threshold is None
        assert args.block_threshold is None
        assert args.top_n is None
        assert args.no_block is False
        assert args.skip_vulns is False
        assert args.skip_logs is False
        assert args.test_mode is False
        assert args.verbose is False
    
    def test_custom_arguments(self, monkeypatch):
        """Тест пользовательских аргументов"""
        monkeypatch.setattr(sys, 'argv', [
            'main.py',
            '--log-file', 'custom.log',
            '--vuln-limit', '50',
            '--threshold', '8.5',
            '--block-threshold', '5',
            '--top-n', '10',
            '--no-block',
            '--skip-vulns',
            '--skip-logs',
            '--test-mode',
            '--verbose'
        ])
        
        args = parse_arguments()
        
        assert args.log_file == "custom.log"
        assert args.vuln_limit == 50
        assert args.threshold == 8.5
        assert args.block_threshold == 5
        assert args.top_n == 10
        assert args.no_block is True
        assert args.skip_vulns is True
        assert args.skip_logs is True
        assert args.test_mode is True
        assert args.verbose is True


class TestValidateConfiguration:
    """Тесты для функции validate_configuration"""
    
    def test_valid_configuration(self):
        """Тест корректной конфигурации"""
        args = MagicMock()
        args.skip_vulns = False
        args.skip_logs = False
        args.threshold = 7.0
        args.block_threshold = 3
        
        validate_configuration(args)
    
    def test_both_sources_skipped(self):
        """Тест с пропуском обоих источников"""
        args = MagicMock()
        args.skip_vulns = True
        args.skip_logs = True
        
        with pytest.raises(ConfigurationError, match="Нельзя пропустить оба"):
            validate_configuration(args)
    
    def test_invalid_threshold(self):
        """Тест с некорректным порогом"""
        args = MagicMock()
        args.skip_vulns = False
        args.skip_logs = False
        args.threshold = 11.0
        
        with pytest.raises(ConfigurationError, match="Порог CVSS должен быть от 0 до 10"):
            validate_configuration(args)
    
    def test_negative_block_threshold(self):
        """Тест с отрицательным порогом блокировки"""
        args = MagicMock()
        args.skip_vulns = False
        args.skip_logs = False
        args.threshold = 7.0
        args.block_threshold = -1
        
        with pytest.raises(ConfigurationError, match="не может быть отрицательным"):
            validate_configuration(args)


class TestCollectData:
    """Тесты для функции collect_data"""
    
    @patch('main.get_vulnerabilities')
    @patch('main.parse_suricata_logs')
    def test_collect_both_sources(self, mock_parse, mock_get, tmp_path):
        """Тест сбора из обоих источников"""
        args = MagicMock()
        args.skip_vulns = False
        args.skip_logs = False
        args.vuln_limit = 30
        args.log_file = str(tmp_path / "test.log")
        args.test_mode = False
        
        mock_get.return_value = [{'cve_id': 'CVE-1'}, {'cve_id': 'CVE-2'}]
        mock_parse.return_value = [{'src_ip': '1.1.1.1'}, {'src_ip': '2.2.2.2'}]
        
        vulns, alerts = collect_data(args)
        
        assert len(vulns) == 2
        assert len(alerts) == 2
        mock_get.assert_called_once_with(limit=30, min_cvss=None)
        mock_parse.assert_called_once()
    
    @patch('main.get_vulnerabilities')
    def test_skip_vulns(self, mock_get):
        """Тест с пропуском уязвимостей"""
        args = MagicMock()
        args.skip_vulns = True
        args.skip_logs = False
        
        with patch('main.parse_suricata_logs') as mock_parse:
            mock_parse.return_value = [{'src_ip': '1.1.1.1'}]
            vulns, alerts = collect_data(args)
        
        assert len(vulns) == 0
        assert len(alerts) == 1
        mock_get.assert_not_called()
    
    @patch('main.get_vulnerabilities')
    def test_api_error_with_test_mode(self, mock_get):
        """Тест ошибки API в тестовом режиме"""
        args = MagicMock()
        args.skip_vulns = False
        args.skip_logs = True
        args.test_mode = True
        
        from api_client import VulnersAPIError
        mock_get.side_effect = VulnersAPIError("API Error")
        
        vulns, alerts = collect_data(args)
        
        assert len(vulns) == 0
        assert len(alerts) == 0
    
    @patch('main.get_vulnerabilities')
    def test_api_error_without_test_mode(self, mock_get):
        """Тест ошибки API без тестового режима"""
        args = MagicMock()
        args.skip_vulns = False
        args.skip_logs = True
        args.test_mode = False
        
        from api_client import VulnersAPIError
        mock_get.side_effect = VulnersAPIError("API Error")
        
        with pytest.raises(DataCollectionError, match="Не удалось получить уязвимости"):
            collect_data(args)


class TestAnalyzeThreats:
    """Тесты для функции analyze_threats"""
    
    @patch('main.find_critical_cves')
    @patch('main.get_top_ips')
    @patch('main.cvss_distribution')
    @patch('main.get_cvss_summary_stats')
    def test_analysis_success(self, mock_stats, mock_cvss, mock_ips, mock_cves):
        """Тест успешного анализа"""
        mock_cves.return_value = pd.DataFrame({'cve_id': ['CVE-1']})
        mock_ips.return_value = pd.DataFrame({'src_ip': ['1.1.1.1'], 'count': [10]})
        mock_cvss.return_value = pd.Series([9.8, 7.2])
        mock_stats.return_value = {'mean': 8.5}
        
        vulns = [{'cve_id': 'CVE-1', 'cvss': 9.8}]
        alerts = [{'src_ip': '1.1.1.1', 'alert_severity': 1}]
        
        critical_df, top_df, cvss_series = analyze_threats(vulns, alerts, 7.0, 5)
        
        assert len(critical_df) == 1
        assert len(top_df) == 1
        assert len(cvss_series) == 2
        
        mock_cves.assert_called_once_with(vulns, threshold=7.0)
        mock_ips.assert_called_once_with(alerts, top_n=5)
        mock_cvss.assert_called_once_with(vulns)
    
    def test_analysis_with_empty_data(self):
        """Тест анализа с пустыми данными"""
        critical_df, top_df, cvss_series = analyze_threats([], [], 7.0, 5)
        
        assert critical_df.empty
        assert top_df.empty
        assert cvss_series.empty


class TestRespondToThreats:
    """Тесты для функции respond_to_threats"""
    
    @patch('main.simulate_blocking')
    def test_respond_with_blocking(self, mock_block):
        """Тест реагирования с блокировкой"""
        critical_df = pd.DataFrame({'cve_id': ['CVE-1']})
        top_df = pd.DataFrame({
            'src_ip': ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
            'count': [10, 5, 2]
        })

        suspicious = respond_to_threats(critical_df, top_df, 5, False)

        assert len(suspicious) == 2
        assert '1.1.1.1' in suspicious
        assert '2.2.2.2' in suspicious
        assert '3.3.3.3' not in suspicious

        mock_block.assert_called_once_with(suspicious, reason="Более 5 событий")
    
    @patch('main.simulate_blocking')
    def test_no_blocking_flag(self, mock_block):
        """Тест с отключённой блокировкой"""
        critical_df = pd.DataFrame({'cve_id': ['CVE-1']})
        top_df = pd.DataFrame({'src_ip': ['1.1.1.1'], 'count': [10]})

        suspicious = respond_to_threats(critical_df, top_df, 5, True)

        assert len(suspicious) == 0
        mock_block.assert_not_called()
    
    @patch('main.simulate_blocking')
    def test_no_suspicious_ips(self, mock_block):
        """Тест без подозрительных IP"""
        critical_df = pd.DataFrame({'cve_id': ['CVE-1']})
        top_df = pd.DataFrame({'src_ip': ['1.1.1.1'], 'count': [2]})

        suspicious = respond_to_threats(critical_df, top_df, 5, False)

        assert len(suspicious) == 0
        mock_block.assert_not_called()


class TestGenerateReports:
    """Тесты для функции generate_reports"""
    
    @patch('main.save_cves')
    @patch('main.save_top_ips')
    @patch('main.save_summary')
    def test_generate_all_reports(self, mock_summary, mock_ips, mock_cves):
        """Тест генерации всех отчётов"""
        mock_cves.return_value = "reports/critical_cves.csv"
        mock_ips.return_value = "reports/top_ips.csv"
        mock_summary.return_value = "reports/summary.json"
        
        critical_df = pd.DataFrame({'cve_id': ['CVE-1'], 'cvss': [9.8]})
        top_df = pd.DataFrame({'src_ip': ['1.1.1.1'], 'count': [10]})
        suspicious = ['1.1.1.1']
        
        files = generate_reports(
            [{'cve': 1}], [{'alert': 1}], critical_df, top_df, suspicious,
            skip_vulns=False, skip_logs=False
        )
        
        assert 'cve' in files
        assert 'ip' in files
        assert 'summary' in files
        assert files['cve'] == "reports/critical_cves.csv"
        
        mock_cves.assert_called_once()
        mock_ips.assert_called_once()
        mock_summary.assert_called_once()
    
    @patch('main.save_summary')
    def test_generate_with_empty_data(self, mock_summary):
        """Тест генерации с пустыми данными"""
        mock_summary.return_value = "reports/summary.json"
        
        critical_df = pd.DataFrame()
        top_df = pd.DataFrame()
        suspicious = []
        
        files = generate_reports(
            [], [], critical_df, top_df, suspicious,
            skip_vulns=True, skip_logs=True
        )
        
        assert 'summary' in files
        assert 'cve' not in files
        assert 'ip' not in files
        mock_summary.assert_called_once()


class TestCreateVisualizations:
    """Тесты для функции create_visualizations"""
    
    @patch('main.plot_top_ips')
    @patch('main.plot_cvss_distribution')
    def test_create_all_plots(self, mock_cvss_plot, mock_ips_plot):
        """Тест создания всех графиков"""
        mock_ips_plot.return_value = "reports/ips.png"
        mock_cvss_plot.return_value = "reports/cvss.png"
        
        top_df = pd.DataFrame({'src_ip': ['1.1.1.1'], 'count': [10]})
        cvss_series = pd.Series([9.8, 7.2])
        
        plots = create_visualizations(top_df, cvss_series)
        
        assert 'ips' in plots
        assert 'cvss' in plots
        assert plots['ips'] == "reports/ips.png"
        
        mock_ips_plot.assert_called_once_with(top_df, filename="threat_analysis.png")
        mock_cvss_plot.assert_called_once_with(cvss_series, filename="cvss_distribution.png")
    
    def test_create_with_empty_data(self):
        """Тест создания с пустыми данными"""
        top_df = pd.DataFrame()
        cvss_series = pd.Series()
        
        plots = create_visualizations(top_df, cvss_series)
        
        assert 'ips' not in plots
        assert 'cvss' not in plots


class TestSignalHandler:
    """Тесты для обработчика сигналов"""
    
    @patch('sys.exit')
    def test_signal_handler(self, mock_exit):
        """Тест обработчика сигналов"""
        signal_handler(None, None)
        mock_exit.assert_called_once_with(130)


@patch('main.signal.signal')
@patch('main.get_user_config')
@patch('main.parse_arguments')
def test_main_configuration_error(mock_parse_args, mock_get_user_config, mock_signal, mock_config):
    """Тест ошибки конфигурации"""
    # Настраиваем конфликтующие настройки
    mock_config.skip_vulns = True
    mock_config.skip_logs = True
    mock_get_user_config.return_value = mock_config
    
    mock_args = MagicMock()
    mock_args.log_file = None
    mock_args.vuln_limit = None
    mock_args.threshold = None
    mock_args.block_threshold = None
    mock_args.top_n = None
    mock_args.no_block = False
    mock_args.skip_vulns = False
    mock_args.skip_logs = False
    mock_args.test_mode = False
    mock_args.verbose = False
    mock_parse_args.return_value = mock_args
    
    result = main()
    assert result == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])