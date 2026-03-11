"""
Модуль для интерактивной настройки параметров программы.
Запрашивает данные у пользователя только если нужно изменить значения по умолчанию.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Загружаем .env при импорте
load_dotenv()

class Config:
    """Класс с настройками программы"""
    
    def __init__(self):
        # Пути к файлам (из .env или по умолчанию)
        self.log_file = os.getenv('LOG_FILE', "logs/alerts-only.json")
        self.reports_dir = os.getenv('REPORTS_DIR', "reports")
        
        # Настройки анализа (из .env или по умолчанию)
        try:
            self.vuln_limit = int(os.getenv('VULN_LIMIT', '30'))
        except ValueError:
            self.vuln_limit = 30
            
        try:
            self.cvss_threshold = float(os.getenv('CVSS_THRESHOLD', '7.0'))
        except ValueError:
            self.cvss_threshold = 7.0
            
        try:
            self.block_threshold = int(os.getenv('BLOCK_THRESHOLD', '3'))
        except ValueError:
            self.block_threshold = 3
            
        try:
            self.top_n = int(os.getenv('TOP_IPS', '5'))
        except ValueError:
            self.top_n = 5
        
        # Настройки email (из .env)
        self.email_enabled = os.getenv('EMAIL_ENABLED', '').lower() == 'true'
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        
        try:
            self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        except ValueError:
            self.smtp_port = 587
            
        self.sender_email = os.getenv('SENDER_EMAIL', '')
        self.sender_password = os.getenv('SENDER_PASSWORD', '')
        self.recipient_email = os.getenv('RECIPIENT_EMAIL', '')
        
        # Флаги (по умолчанию False)
        self.skip_vulns = False
        self.skip_logs = False
        self.test_mode = False
        self.verbose = False
        
        # Автоматически включаем email, если есть все данные
        if self.sender_email and self.recipient_email and self.sender_password:
            self.email_enabled = True


def ask_yes_no(question: str, default: bool = False) -> bool:
    """
    Спрашивает пользователя да/нет с значением по умолчанию.
    
    Args:
        question: Вопрос для пользователя
        default: Значение по умолчанию (True для y, False для n)
    
    Returns:
        bool: Ответ пользователя или значение по умолчанию
    """
    default_str = "Y/n" if default else "y/N"
    answer = input(f"{question} ({default_str}): ").strip().lower()
    
    if answer == '':
        return default
    return answer.startswith('y')


def ask_value(question: str, default: any, value_type: type = str) -> any:
    """
    Спрашивает пользователя значение с подстановкой по умолчанию.
    
    Args:
        question: Вопрос для пользователя
        default: Значение по умолчанию
        value_type: Тип значения (str, int, float)
    
    Returns:
        any: Введённое значение или значение по умолчанию
    """
    answer = input(f"{question} [{default}]: ").strip()
    
    if answer == '':
        return default
    
    try:
        if value_type == int:
            return int(answer)
        elif value_type == float:
            return float(answer)
        else:
            return answer
    except ValueError:
        print(f"   Ошибка, оставляем по умолчанию: {default}")
        return default


def get_user_config() -> Config:
    """
    Получает настройки от пользователя, но только если он хочет что-то изменить.
    
    Returns:
        Config: Объект с настройками
    """
    config = Config()
    
    print("\n" + "="*60)
    print("НАСТРОЙКА ПРОГРАММЫ")
    print("="*60)
    print("\nТЕКУЩИЕ НАСТРОЙКИ:")
    print(f"  • Лог-файл: {config.log_file}")
    print(f"  • Лимит уязвимостей: {config.vuln_limit}")
    print(f"  • Порог CVSS: {config.cvss_threshold}")
    print(f"  • Порог блокировки: {config.block_threshold}")
    
    if config.email_enabled:
        print(f"  • Email: включён (отправитель: {config.sender_email})")
    else:
        print(f"  • Email: отключён")
    
    # Спрашиваем, хочет ли пользователь изменить настройки
    if not ask_yes_no("\nХотите изменить настройки?", default=False):
        print("\nИспользуются настройки по умолчанию")
        return config
    
    print("\n" + "="*60)
    print("ИЗМЕНЕНИЕ НАСТРОЕК")
    print("="*60)
    
    # ФАЙЛЫ
    print("\nФАЙЛЫ:")
    config.log_file = ask_value("  Путь к лог-файлу", config.log_file)
    
    # АНАЛИЗ
    print("\nАНАЛИЗ:")
    config.vuln_limit = ask_value("  Лимит уязвимостей", config.vuln_limit, int)
    config.cvss_threshold = ask_value("  Порог CVSS для критичности", config.cvss_threshold, float)
    config.block_threshold = ask_value("  Порог событий для блокировки IP", config.block_threshold, int)
    
    # РЕЖИМЫ
    print("\nРЕЖИМЫ:")
    if ask_yes_no("  Пропустить загрузку уязвимостей?", default=False):
        config.skip_vulns = True
    
    if ask_yes_no("  Пропустить загрузку логов?", default=False):
        config.skip_logs = True
    
    if ask_yes_no("  Включить тестовый режим?", default=False):
        config.test_mode = True
    
    # EMAIL
    print("\nEMAIL-УВЕДОМЛЕНИЯ:")
    
    # Показываем текущие настройки email
    if config.email_enabled:
        print(f"  Текущие настройки (из .env):")
        print(f"    Отправитель: {config.sender_email}")
        print(f"    Получатель: {config.recipient_email}")
        
        if ask_yes_no("  Изменить настройки email?", default=False):
            config.sender_email = ask_value("    Email отправителя", config.sender_email)
            config.sender_password = ask_value("    Пароль приложения", "******")
            config.recipient_email = ask_value("    Email получателя", config.recipient_email)
            
            # Спрашиваем, сохранить ли в .env
            if ask_yes_no("\n  Сохранить новые настройки в .env?", default=True):
                save_to_env(config)
    else:
        print("  Email отключён (нет настроек в .env)")
        if ask_yes_no("  Включить email-уведомления?", default=False):
            print("\n  Введите данные для отправки:")
            config.sender_email = input("    Email отправителя: ").strip()
            config.sender_password = input("    Пароль приложения: ").strip()
            config.recipient_email = input("    Email получателя: ").strip()
            config.email_enabled = True
            
            # Спрашиваем, сохранить ли в .env
            if ask_yes_no("\n  Сохранить настройки в .env?", default=True):
                save_to_env(config)
    
    print("\n" + "="*60)
    print("Настройка завершена!")
    print("="*60 + "\n")
    
    return config


def save_to_env(config: Config) -> None:
    """
    Сохраняет настройки в .env файл.
    
    Args:
        config: Объект с настройками
    """
    env_path = Path('.env')
    
    # Читаем существующий .env
    env_vars = {}
    if env_path.exists():
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    
    # Обновляем настройки
    env_vars['LOG_FILE'] = config.log_file
    env_vars['VULN_LIMIT'] = str(config.vuln_limit)
    env_vars['CVSS_THRESHOLD'] = str(config.cvss_threshold)
    env_vars['BLOCK_THRESHOLD'] = str(config.block_threshold)
    env_vars['TOP_IPS'] = str(config.top_n)
    env_vars['EMAIL_ENABLED'] = str(config.email_enabled).lower()
    env_vars['SMTP_SERVER'] = config.smtp_server
    env_vars['SMTP_PORT'] = str(config.smtp_port)
    env_vars['SENDER_EMAIL'] = config.sender_email
    env_vars['RECIPIENT_EMAIL'] = config.recipient_email
    
    # Пароль сохраняем только если он не пустой
    if config.sender_password and config.sender_password != '******':
        env_vars['SENDER_PASSWORD'] = config.sender_password
    
    # Записываем обратно
    with open(env_path, 'w', encoding='utf-8') as f:
        f.write("# Настройки Threat Analyzer\n")
        f.write("# Автоматически создано при запуске\n\n")
        
        for key in sorted(env_vars.keys()):
            f.write(f"{key}={env_vars[key]}\n")
    
    print(f"  Настройки сохранены в {env_path}")