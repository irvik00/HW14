import pytest
import pandas as pd
import numpy as np
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import (
    find_critical_cves, 
    get_top_ips, 
    cvss_distribution,
    get_cvss_summary_stats,
    analyze_threat_correlation
)

class TestFindCriticalCVEs:
    """Тесты для функции поиска критических CVE"""
    
    def test_empty_list(self):
        """Тест с пустым списком"""
        result = find_critical_cves([])
        assert isinstance(result, pd.DataFrame)
        assert result.empty
        assert list(result.columns) == ['cve_id', 'cvss', 'description', 'severity_category']
    
    def test_invalid_input_type(self):
        """Тест с некорректным типом входных данных"""
        result = find_critical_cves("not a list")
        assert isinstance(result, pd.DataFrame)
        assert result.empty
    
    def test_basic_filtering(self):
        """Тест базовой фильтрации по порогу"""
        test_data = [
            {'cve_id': 'CVE-1', 'cvss': 9.8, 'description': 'Critical'},
            {'cve_id': 'CVE-2', 'cvss': 7.2, 'description': 'High'},
            {'cve_id': 'CVE-3', 'cvss': 5.5, 'description': 'Medium'},
        ]
        
        result = find_critical_cves(test_data, threshold=7.0)
        assert len(result) == 2
        assert result.iloc[0]['cve_id'] == 'CVE-1'  # Проверяем сортировку
        assert result.iloc[1]['cve_id'] == 'CVE-2'
        assert 'severity_category' in result.columns
    
    def test_severity_categories(self):
        """Тест категорий критичности"""
        test_data = [
            {'cve_id': 'CVE-1', 'cvss': 9.5},
            {'cve_id': 'CVE-2', 'cvss': 8.0},
            {'cve_id': 'CVE-3', 'cvss': 5.5},
            {'cve_id': 'CVE-4', 'cvss': 2.0},
        ]
        
        result = find_critical_cves(test_data, threshold=0)  # Без фильтрации
        
        categories = result.set_index('cve_id')['severity_category'].to_dict()
        assert categories['CVE-1'] == 'Критическая'
        assert categories['CVE-2'] == 'Высокая'
        assert categories['CVE-3'] == 'Средняя'
        assert categories['CVE-4'] == 'Низкая'
    
    def test_invalid_cvss_values(self):
        """Тест обработки некорректных CVSS значений"""
        test_data = [
            {'cve_id': 'CVE-1', 'cvss': '9.8'},  # строка, но должна конвертироваться
            {'cve_id': 'CVE-2', 'cvss': None},
            {'cve_id': 'CVE-3', 'cvss': 'invalid'},
            {'cve_id': 'CVE-4'},  # нет cvss
        ]
        
        result = find_critical_cves(test_data, threshold=7.0)
        assert len(result) == 1  # Только CVE-1 должен пройти
        assert result.iloc[0]['cve_id'] == 'CVE-1'


class TestGetTopIPs:
    """Тесты для функции получения топ IP"""
    
    def test_empty_list(self):
        """Тест с пустым списком"""
        result = get_top_ips([])
        assert isinstance(result, pd.DataFrame)
        assert result.empty
    
    def test_basic_grouping(self):
        """Тест базовой группировки по IP"""
        test_data = [
            {'src_ip': '192.168.1.10', 'alert_severity': 1},
            {'src_ip': '192.168.1.10', 'alert_severity': 1},
            {'src_ip': '192.168.1.20', 'alert_severity': 2},
            {'src_ip': '192.168.1.10', 'alert_severity': 1},
            {'src_ip': '192.168.1.30', 'alert_severity': 3},
        ]
        
        result = get_top_ips(test_data, top_n=2)
        assert len(result) == 2
        
        # Проверяем, что первый IP - самый активный
        assert result.iloc[0]['src_ip'] == '192.168.1.10'
        assert result.iloc[0]['count'] == 3
        assert result.iloc[0]['avg_severity'] == 1.0
        
        assert result.iloc[1]['src_ip'] in ['192.168.1.20', '192.168.1.30']
    
    def test_missing_columns(self):
        """Тест с отсутствующими обязательными колонками"""
        test_data = [
            {'ip': '192.168.1.10', 'severity': 1},  # неправильные имена колонок
        ]
        
        result = get_top_ips(test_data)
        assert result.empty
    
    def test_empty_ip_values(self):
        """Тест с пустыми значениями IP"""
        test_data = [
            {'src_ip': '192.168.1.10', 'alert_severity': 1},
            {'src_ip': None, 'alert_severity': 2},
            {'src_ip': '', 'alert_severity': 3},
        ]
        
        result = get_top_ips(test_data)
        assert len(result) == 1
        assert result.iloc[0]['src_ip'] == '192.168.1.10'
    
    def test_risk_score_calculation(self):
        """Тест расчета скорингового балла"""
        test_data = [
            {'src_ip': 'IP1', 'alert_severity': 1},
            {'src_ip': 'IP1', 'alert_severity': 1},
            {'src_ip': 'IP2', 'alert_severity': 3},
        ]
        
        result = get_top_ips(test_data, top_n=2)
        
        # IP1 должно быть выше по риску (больше событий)
        assert result.iloc[0]['src_ip'] == 'IP1'
        assert 'risk_score' in result.columns
        assert result.iloc[0]['risk_score'] > 0


class TestCVSSDistribution:
    """Тесты для функций работы с распределением CVSS"""
    
    def test_empty_list(self):
        """Тест с пустым списком"""
        result = cvss_distribution([])
        assert isinstance(result, pd.Series)
        assert result.empty
    
    def test_basic_distribution(self):
        """Тест базового распределения"""
        test_data = [
            {'cvss': 9.8},
            {'cvss': 7.5},
            {'cvss': 5.5},
            {'cvss': 2.1},
        ]
        
        result = cvss_distribution(test_data)
        assert len(result) == 4
        assert result.mean() == pytest.approx((9.8 + 7.5 + 5.5 + 2.1) / 4)
    
    def test_invalid_values(self):
        """Тест с некорректными значениями"""
        test_data = [
            {'cvss': 9.8},
            {'cvss': 'invalid'},
            {'cvss': None},
            {},  # пустой словарь
        ]
        
        result = cvss_distribution(test_data)
        assert len(result) == 1
        assert result.iloc[0] == 9.8
    
    def test_summary_stats(self):
        """Тест сводной статистики"""
        test_data = [
            {'cvss': 9.8},
            {'cvss': 7.5},
            {'cvss': 5.5},
            {'cvss': 2.1},
        ]

        stats = get_cvss_summary_stats(test_data)

        assert stats['count'] == 4
        assert stats['min'] == 2.1
        assert stats['max'] == 9.8
        
        
        assert stats['mean'] == pytest.approx(6.225, rel=1e-2)
        

class TestThreatCorrelation:
    """Тесты для анализа корреляции угроз"""
    
    def test_no_threats(self):
        """Тест с отсутствием угроз"""
        vulns_df = pd.DataFrame()
        ips_df = pd.DataFrame()
        
        result = analyze_threat_correlation(vulns_df, ips_df)
        assert result['has_critical_vulns'] is False
        assert result['has_suspicious_ips'] is False
        assert result['threat_level'] == 'Низкий'
    
    def test_medium_threat(self):
        """Тест со средним уровнем угрозы"""
        vulns_df = pd.DataFrame({'cve_id': ['CVE-1'], 'cvss': [8.5]})
        ips_df = pd.DataFrame({'src_ip': ['IP1'], 'count': [2]})
        
        result = analyze_threat_correlation(vulns_df, ips_df)
        assert result['has_critical_vulns'] is True
        assert result['has_suspicious_ips'] is True
        assert result['threat_level'] == 'Средний'
    
    def test_high_threat(self):
        """Тест с высоким уровнем угрозы"""
        vulns_df = pd.DataFrame({'cve_id': [f'CVE-{i}' for i in range(6)], 'cvss': [8.5]*6})
        ips_df = pd.DataFrame({'src_ip': [f'IP{i}' for i in range(4)], 'count': [5]*4})
        
        result = analyze_threat_correlation(vulns_df, ips_df)
        assert result['total_critical_vulns'] == 6
        assert result['total_suspicious_ips'] == 4
        assert result['threat_level'] == 'Высокий'
    
    def test_critical_threat(self):
        """Тест с критическим уровнем угрозы"""
        vulns_df = pd.DataFrame({'cve_id': [f'CVE-{i}' for i in range(15)], 'cvss': [9.5]*15})
        ips_df = pd.DataFrame({'src_ip': [f'IP{i}' for i in range(10)], 'count': [10]*10})
        
        result = analyze_threat_correlation(vulns_df, ips_df)
        assert result['threat_level'] == 'Критический'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])