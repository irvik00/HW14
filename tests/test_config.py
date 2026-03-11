import pytest
import os
import sys
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config, ask_yes_no, ask_value, get_user_config, save_to_env


class TestConfig:
    """Тесты для класса Config"""
    
    def test_default_values(self, monkeypatch):
        """Тест значений по умолчанию"""
        # Список всех переменных окружения, которые могут влиять
        env_vars = [
            'LOG_FILE', 'VULN_LIMIT', 'CVSS_THRESHOLD', 'BLOCK_THRESHOLD',
            'TOP_IPS', 'EMAIL_ENABLED', 'SMTP_SERVER', 'SMTP_PORT',
            'SENDER_EMAIL', 'SENDER_PASSWORD', 'RECIPIENT_EMAIL'
        ]
        
        # Удаляем все
        for var in env_vars:
            monkeypatch.delenv(var, raising=False)
        
        config = Config()
        
        assert config.log_file == "logs/alerts-only.json"
        assert config.reports_dir == "reports"
        assert config.vuln_limit == 30
        assert config.cvss_threshold == 7.0
        assert config.block_threshold == 3
        assert config.top_n == 5
        assert config.email_enabled is False
        assert config.smtp_server == "smtp.gmail.com"
        assert config.smtp_port == 587
        assert config.sender_email == ""
        assert config.sender_password == ""
        assert config.recipient_email == ""
        assert config.skip_vulns is False
        assert config.skip_logs is False
        assert config.test_mode is False
        assert config.verbose is False
    
    def test_env_values(self, monkeypatch):
        """Тест загрузки из переменных окружения"""
        monkeypatch.setenv('LOG_FILE', 'custom.log')
        monkeypatch.setenv('VULN_LIMIT', '50')
        monkeypatch.setenv('CVSS_THRESHOLD', '8.5')
        monkeypatch.setenv('BLOCK_THRESHOLD', '5')
        monkeypatch.setenv('TOP_IPS', '10')
        monkeypatch.setenv('EMAIL_ENABLED', 'true')
        monkeypatch.setenv('SMTP_SERVER', 'smtp.custom.com')
        monkeypatch.setenv('SMTP_PORT', '465')
        monkeypatch.setenv('SENDER_EMAIL', 'sender@test.com')
        monkeypatch.setenv('SENDER_PASSWORD', 'pass123')
        monkeypatch.setenv('RECIPIENT_EMAIL', 'recipient@test.com')
        
        config = Config()
        
        assert config.log_file == "custom.log"
        assert config.vuln_limit == 50
        assert config.cvss_threshold == 8.5
        assert config.block_threshold == 5
        assert config.top_n == 10
        assert config.email_enabled is True
        assert config.smtp_server == "smtp.custom.com"
        assert config.smtp_port == 465
        assert config.sender_email == "sender@test.com"
        assert config.sender_password == "pass123"
        assert config.recipient_email == "recipient@test.com"
    
    def test_invalid_env_values(self, monkeypatch):
        """Тест обработки некорректных значений в .env"""
        monkeypatch.setenv('VULN_LIMIT', 'not_a_number')
        monkeypatch.setenv('CVSS_THRESHOLD', 'invalid')
        monkeypatch.setenv('SMTP_PORT', 'not_a_port')
        
        config = Config()
        
        # Должны использоваться значения по умолчанию
        assert config.vuln_limit == 30
        assert config.cvss_threshold == 7.0
        assert config.smtp_port == 587
    

class TestAskYesNo:
    """Тесты для функции ask_yes_no"""
    
    @patch('builtins.input')
    def test_default_no(self, mock_input):
        """Тест значения по умолчанию (False)"""
        mock_input.return_value = ''
        result = ask_yes_no("Test question", default=False)
        assert result is False
    
    @patch('builtins.input')
    def test_default_yes(self, mock_input):
        """Тест значения по умолчанию (True)"""
        mock_input.return_value = ''
        result = ask_yes_no("Test question", default=True)
        assert result is True
    
    @patch('builtins.input')
    def test_yes_answer(self, mock_input):
        """Тест ответа 'y'"""
        mock_input.return_value = 'y'
        result = ask_yes_no("Test question", default=False)
        assert result is True
    
    @patch('builtins.input')
    def test_no_answer(self, mock_input):
        """Тест ответа 'n'"""
        mock_input.return_value = 'n'
        result = ask_yes_no("Test question", default=True)
        assert result is False
    
    @patch('builtins.input')
    def test_yes_uppercase(self, mock_input):
        """Тест ответа 'Y' в верхнем регистре"""
        mock_input.return_value = 'Y'
        result = ask_yes_no("Test question", default=False)
        assert result is True


class TestAskValue:
    """Тесты для функции ask_value"""
    
    @patch('builtins.input')
    def test_default_value(self, mock_input):
        """Тест значения по умолчанию"""
        mock_input.return_value = ''
        result = ask_value("Test", "default")
        assert result == "default"
    
    @patch('builtins.input')
    def test_string_value(self, mock_input):
        """Тест ввода строки"""
        mock_input.return_value = 'custom'
        result = ask_value("Test", "default")
        assert result == "custom"
    
    @patch('builtins.input')
    def test_int_value(self, mock_input):
        """Тест ввода целого числа"""
        mock_input.return_value = '42'
        result = ask_value("Test", 0, int)
        assert result == 42
    
    @patch('builtins.input')
    def test_float_value(self, mock_input):
        """Тест ввода числа с плавающей точкой"""
        mock_input.return_value = '3.14'
        result = ask_value("Test", 0.0, float)
        assert result == 3.14
    
    @patch('builtins.input')
    def test_invalid_int(self, mock_input, capsys):
        """Тест обработки некорректного целого числа"""
        mock_input.return_value = 'not_a_number'
        result = ask_value("Test", 42, int)
        captured = capsys.readouterr()
        assert "Ошибка" in captured.out
        assert result == 42


class TestSaveToEnv:
    """Тесты для функции save_to_env"""
    
    def test_save_new_env(self, tmp_path, monkeypatch):
        """Тест сохранения в новый .env файл"""
        # Временная директория
        monkeypatch.chdir(tmp_path)
        
        config = Config()
        config.log_file = "test.log"
        config.vuln_limit = 50
        config.email_enabled = True
        config.sender_email = "test@test.com"
        config.sender_password = "password"
        
        save_to_env(config)
        
        env_path = tmp_path / '.env'
        assert env_path.exists()
        
        content = env_path.read_text(encoding='utf-8')
        assert "LOG_FILE=test.log" in content
        assert "VULN_LIMIT=50" in content
        assert "EMAIL_ENABLED=true" in content
        assert "SENDER_EMAIL=test@test.com" in content
        assert "SENDER_PASSWORD=password" in content
    
    def test_update_existing_env(self, tmp_path, monkeypatch):
        """Тест обновления существующего .env файла"""
        monkeypatch.chdir(tmp_path)
        
        # Создаём существующий .env
        env_path = tmp_path / '.env'
        env_path.write_text("EXISTING_VAR=value\nLOG_FILE=old.log\n")
        
        config = Config()
        config.log_file = "new.log"
        config.vuln_limit = 50
        
        save_to_env(config)
        
        content = env_path.read_text(encoding='utf-8')
        assert "EXISTING_VAR=value" in content
        assert "LOG_FILE=new.log" in content
        assert "VULN_LIMIT=50" in content
    
    def test_dont_save_placeholder_password(self, tmp_path, monkeypatch):
        """Тест: не сохранять пароль-заполнитель"""
        monkeypatch.chdir(tmp_path)
        
        config = Config()
        config.sender_password = "******"  # пароль-заполнитель
        
        save_to_env(config)
        
        env_path = tmp_path / '.env'
        content = env_path.read_text(encoding='utf-8')
        assert "SENDER_PASSWORD=******" not in content


class TestGetUserConfig:
    """Тесты для функции get_user_config"""
    
    @patch('config.ask_yes_no')
    def test_use_default_settings(self, mock_ask_yes_no):
        """Тест использования настроек по умолчанию"""
        mock_ask_yes_no.return_value = False  # пользователь не хочет менять
        
        config = get_user_config()
        
        assert isinstance(config, Config)
        mock_ask_yes_no.assert_called_once()
    
    @patch('config.ask_yes_no')
    @patch('config.ask_value')
    def test_change_settings(self, mock_ask_value, mock_ask_yes_no):
        """Тест изменения настроек"""
        # Первый вызов: хочет ли менять настройки? -> Да
        # Второй вызов: пропустить уязвимости? -> Нет
        # Третий вызов: пропустить логи? -> Нет
        # Четвёртый вызов: тестовый режим? -> Нет
        # Пятый вызов: изменить email? -> Нет (для включённого email)
        mock_ask_yes_no.side_effect = [True, False, False, False, False]
        
        # Мокаем ask_value для возврата значений по умолчанию
        mock_ask_value.side_effect = lambda q, d, t=None: d
        
        config = get_user_config()
        
        assert isinstance(config, Config)
        assert mock_ask_yes_no.call_count >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])