import pytest
import os
import requests  # Добавлен недостающий импорт
from unittest.mock import Mock, patch, MagicMock
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_client import get_vulnerabilities, VulnersAuthError, VulnersRateLimitError

# Фикстура с тестовыми данными
@pytest.fixture
def mock_vulners_response():
    """Возвращает типичный ответ от Vulners API"""
    return {
        "result": "OK",
        "data": {
            "search": [
                {
                    "_source": {
                        "id": "CVE-2023-1234",
                        "cvss": {"score": 9.8},
                        "description": "Critical vulnerability in test software"
                    }
                },
                {
                    "_source": {
                        "id": "CVE-2023-5678",
                        "cvss": {"score": 7.5},
                        "description": "High severity issue"
                    }
                },
                {
                    "_source": {
                        "id": "CVE-2023-9012",
                        "cvss": {"score": 4.2},
                        "description": "Low severity issue"
                    }
                }
            ]
        }
    }

def test_get_vulnerabilities_success(mock_vulners_response):
    """Тест успешного получения уязвимостей"""
    with patch('api_client.requests.Session') as mock_session:
        # Настраиваем мок
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_vulners_response
        mock_session.return_value.post.return_value = mock_response
        
        # Тестируем без фильтра
        with patch.dict(os.environ, {'VULNERS_API_KEY': 'test_key'}):
            result = get_vulnerabilities(limit=10)
            
            assert len(result) == 3
            assert result[0]['cve_id'] == 'CVE-2023-1234'
            assert result[0]['cvss'] == 9.8
            assert result[1]['cve_id'] == 'CVE-2023-5678'
            assert result[2]['cve_id'] == 'CVE-2023-9012'

def test_get_vulnerabilities_with_min_cvss_filter(mock_vulners_response):
    """Тест фильтрации по минимальному CVSS"""
    with patch('api_client.requests.Session') as mock_session:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_vulners_response
        mock_session.return_value.post.return_value = mock_response
        
        with patch.dict(os.environ, {'VULNERS_API_KEY': 'test_key'}):
            result = get_vulnerabilities(limit=10, min_cvss=7.0)
            
            assert len(result) == 2
            assert all(v['cvss'] >= 7.0 for v in result)
            assert result[0]['cve_id'] == 'CVE-2023-1234'
            assert result[1]['cve_id'] == 'CVE-2023-5678'

def test_get_vulnerabilities_no_api_key():
    """Тест поведения без API ключа"""
    with patch.dict(os.environ, {}, clear=True):  # Убираем все переменные окружения
        result = get_vulnerabilities()
        assert result == []  # Должен вернуть пустой список, не упасть

def test_get_vulnerabilities_api_error():
    """Тест обработки ошибки API"""
    with patch('api_client.requests.Session') as mock_session:
        # Симулируем ошибку сети
        mock_session.return_value.post.side_effect = requests.exceptions.ConnectionError("Network error")
        
        with patch.dict(os.environ, {'VULNERS_API_KEY': 'test_key'}):
            result = get_vulnerabilities()
            assert result == []  # Должен вернуть пустой список при ошибке

def test_get_vulnerabilities_empty_response():
    """Тест пустого ответа от API"""
    with patch('api_client.requests.Session') as mock_session:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "OK", "data": {"search": []}}
        mock_session.return_value.post.return_value = mock_response
        
        with patch.dict(os.environ, {'VULNERS_API_KEY': 'test_key'}):
            result = get_vulnerabilities()
            assert result == []

def test_get_vulnerabilities_malformed_data():
    """Тест обработки битых данных от API"""
    with patch('api_client.requests.Session') as mock_session:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": "OK",
            "data": {
                "search": [
                    {"_source": {"id": "CVE-2023-1234"}},  # нет cvss
                    {"_source": {"cvss": {"score": 8.0}}},  # нет id
                    {"_source": {}}  # пусто
                ]
            }
        }
        mock_session.return_value.post.return_value = mock_response
        
        with patch.dict(os.environ, {'VULNERS_API_KEY': 'test_key'}):
            result = get_vulnerabilities()
            assert len(result) == 0  # Все записи должны быть пропущены

def test_get_vulnerabilities_rate_limit():
    """Тест превышения лимита запросов"""
    with patch('api_client.requests.Session') as mock_session:
        # Симулируем 429 ошибку
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("429 Rate Limit")
        mock_session.return_value.post.return_value = mock_response
        
        with patch.dict(os.environ, {'VULNERS_API_KEY': 'test_key'}):
            # Функция должна обработать исключение и вернуть пустой список
            result = get_vulnerabilities()
            assert result == []

# Добавим тест для проверки пользовательских исключений
def test_vulners_auth_error_handling():
    """Тест обработки ошибки аутентификации"""
    with patch('api_client.requests.Session') as mock_session:
        # Симулируем 401 ошибку (неверный ключ)
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized")
        mock_session.return_value.post.return_value = mock_response
        
        with patch.dict(os.environ, {'VULNERS_API_KEY': 'wrong_key'}):
            # Функция должна вернуть пустой список, но залогировать ошибку
            result = get_vulnerabilities()
            assert result == []