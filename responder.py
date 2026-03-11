"""
Модуль для имитации реагирования на обнаруженные угрозы.

Предоставляет функции для логирования блокировок IP-адресов
и уведомления о критических уязвимостях.
"""

import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
import pandas as pd
from pathlib import Path

logger = logging.getLogger(__name__)

# Константы
DEFAULT_BLOCK_LOG_FILE = "blocked_ips.log"
DEFAULT_SEVERITY_THRESHOLD = 7.0
MAX_DESCRIPTION_LENGTH = 100


class ResponderError(Exception):
    """Базовое исключение для ошибок реагирования"""
    pass


class FileWriteError(ResponderError):
    """Ошибка при записи в файл"""
    pass


class DataValidationError(ResponderError):
    """Ошибка валидации данных"""
    pass


def validate_ip_list(ip_list: List[str]) -> bool:
    """
    Проверяет список IP-адресов на корректность.
    
    Args:
        ip_list: Список IP-адресов для проверки
    
    Returns:
        bool: True если список корректен
    
    Raises:
        DataValidationError: Если данные некорректны
    """
    if ip_list is None:
        raise DataValidationError("Список IP не может быть None")
    
    if not isinstance(ip_list, list):
        raise DataValidationError(f"Ожидался список, получен {type(ip_list)}")
    
    # Проверяем каждый IP (опционально)
    for ip in ip_list:
        if not isinstance(ip, str):
            raise DataValidationError(f"IP-адрес должен быть строкой, получен {type(ip)}")
        if not ip.strip():
            raise DataValidationError("IP-адрес не может быть пустым")
    
    return True


def validate_cve_dataframe(cve_df: pd.DataFrame, required_columns: Optional[List[str]] = None) -> bool:
    """
    Проверяет DataFrame с CVE на корректность.
    
    Args:
        cve_df: DataFrame для проверки
        required_columns: Список обязательных колонок
    
    Returns:
        bool: True если данные корректны
    
    Raises:
        DataValidationError: Если данные некорректны
    """
    if cve_df is None:
        raise DataValidationError("DataFrame не может быть None")
    
    if not isinstance(cve_df, pd.DataFrame):
        raise DataValidationError(f"Ожидался DataFrame, получен {type(cve_df)}")
    
    required = required_columns or ['cve_id', 'cvss']
    missing_columns = [col for col in required if col not in cve_df.columns]
    if missing_columns:
        raise DataValidationError(f"В DataFrame отсутствуют колонки: {missing_columns}")
    
    return True


def ensure_log_file(log_file: str) -> Path:
    """
    Проверяет доступность файла для записи.
    
    Args:
        log_file: Путь к файлу лога
    
    Returns:
        Path: Объект Path файла
    
    Raises:
        FileWriteError: Если файл недоступен для записи
    """
    try:
        path = Path(log_file)
        
        # Создаём родительскую директорию, если нужно
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Проверяем возможность записи
        if path.exists() and not os.access(path, os.W_OK):
            raise FileWriteError(f"Нет прав на запись в файл {log_file}")
        
        return path
        
    except Exception as e:
        raise FileWriteError(f"Ошибка доступа к файлу {log_file}: {e}")


def simulate_blocking(
    ip_list: List[str], 
    reason: str = "Suspicious activity",
    log_file: str = DEFAULT_BLOCK_LOG_FILE,
    console_output: bool = True
) -> int:
    """
    Имитирует блокировку IP-адресов.
    
    Функция записывает информацию о блокировке в лог-файл
    и выводит сообщение в консоль.
    
    Args:
        ip_list: Список IP-адресов для блокировки
        reason: Причина блокировки
        log_file: Путь к файлу для записи логов
        console_output: Выводить ли сообщения в консоль
    
    Returns:
        int: Количество записанных записей
    
    Raises:
        DataValidationError: Если входные данные некорректны
        FileWriteError: Если не удалось записать в файл
    
    Examples:
        >>> simulate_blocking(['192.168.1.10', '10.0.0.1'], "High traffic")
        Записано 2 записей о блокировке в blocked_ips.log
        
        >>> simulate_blocking([], "No threats")
        Нет IP-адресов для блокировки.
    """
    # Валидация
    try:
        validate_ip_list(ip_list)
    except DataValidationError as e:
        logger.error(f"Ошибка валидации списка IP: {e}")
        raise
    
    if not ip_list:
        logger.info("Нет IP-адресов для блокировки.")
        return 0
    
    # Проверка файла
    try:
        log_path = ensure_log_file(log_file)
    except FileWriteError as e:
        logger.error(f"Ошибка доступа к файлу лога: {e}")
        raise
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    written_count = 0
    
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            for ip in ip_list:
                # Пропускаем пустые IP (хотя валидация уже должна была отсеять)
                if not ip or not isinstance(ip, str):
                    logger.warning(f"Пропущен некорректный IP: {ip}")
                    continue
                
                message = f"[{timestamp}] SIMULATED BLOCK: IP {ip} blocked. Reason: {reason}"
                
                # Вывод в консоль
                if console_output:
                    print(message)
                
                # Запись в файл
                f.write(message + "\n")
                written_count += 1
        
        logger.info(f"Записано {written_count} записей о блокировке в {log_file}")
        
        # Дополнительная информация
        if written_count < len(ip_list):
            logger.warning(f"Записано только {written_count} из {len(ip_list)} IP")
        
        return written_count
        
    except PermissionError:
        raise FileWriteError(f"Нет прав на запись в файл {log_file}")
    except OSError as e:
        raise FileWriteError(f"Ошибка ввода-вывода при записи в {log_file}: {e}")
    except Exception as e:
        raise FileWriteError(f"Неожиданная ошибка при записи в {log_file}: {e}")


def notify_critical_cves(
    cve_df: pd.DataFrame, 
    threshold: float = DEFAULT_SEVERITY_THRESHOLD,
    console_output: bool = True,
    max_description_length: int = MAX_DESCRIPTION_LENGTH
) -> Dict[str, Any]:
    """
    Выводит в консоль список критических уязвимостей.
    
    Функция анализирует DataFrame с CVE, фильтрует по порогу CVSS
    и выводит информацию в консоль.
    
    Args:
        cve_df: DataFrame с данными о CVE
        threshold: Пороговое значение CVSS для критичности
        console_output: Выводить ли информацию в консоль
        max_description_length: Максимальная длина описания
    
    Returns:
        Dict[str, Any]: Статистика по выведенным уязвимостям
    
    Raises:
        DataValidationError: Если входные данные некорректны
    
    Examples:
        >>> cve_data = pd.DataFrame({
        ...     'cve_id': ['CVE-2023-1234'],
        ...     'cvss': [9.8],
        ...     'description': ['Critical RCE']
        ... })
        >>> stats = notify_critical_cves(cve_data)
        === КРИТИЧЕСКИЕ УЯЗВИМОСТИ (CVSS >= 7.0) ===
        CVE-2023-1234 | CVSS: 9.8 | Critical RCE...
        =============================================
    """
    # Валидация
    try:
        validate_cve_dataframe(cve_df, ['cve_id', 'cvss'])
    except DataValidationError as e:
        logger.error(f"Ошибка валидации данных CVE: {e}")
        raise
    
    # Фильтруем по порогу, если нужно
    if threshold > 0:
        critical_df = cve_df[cve_df['cvss'] >= threshold].copy()
    else:
        critical_df = cve_df.copy()
    
    # Статистика
    stats = {
        'total_cves': len(cve_df),
        'critical_cves': len(critical_df),
        'threshold': threshold,
        'max_cvss': critical_df['cvss'].max() if not critical_df.empty else 0,
        'avg_cvss': critical_df['cvss'].mean() if not critical_df.empty else 0
    }
    
    if critical_df.empty:
        message = f"Критических уязвимостей (CVSS >= {threshold}) не обнаружено."
        if console_output:
            print(message)
        logger.info(message)
        return stats
    
    # Сортируем по убыванию CVSS
    critical_df = critical_df.sort_values('cvss', ascending=False)
    
    if console_output:
        print(f"\n=== КРИТИЧЕСКИЕ УЯЗВИМОСТИ (CVSS >= {threshold}) ===")
        
        for idx, row in critical_df.iterrows():
            cve = row['cve_id']
            cvss = row['cvss']
            
            # Обработка описания
            description = row.get('description', '')
            if description and isinstance(description, str):
                if len(description) > max_description_length:
                    desc = description[:max_description_length] + '...'
                else:
                    desc = description
            else:
                desc = 'No description'
            
            print(f"{cve} | CVSS: {cvss:.1f} | {desc}")
        
        # Добавляем статистику
        print(f"\nВсего критических уязвимостей: {len(critical_df)}")
        print(f"Средний CVSS: {critical_df['cvss'].mean():.2f}")
        print(f"Максимальный CVSS: {critical_df['cvss'].max():.1f}")
        print("=============================================\n")
    
    logger.info(f"Выведено {len(critical_df)} критических уязвимостей (CVSS >= {threshold})")
    
    return stats


def notify_suspicious_ips(
    ip_df: pd.DataFrame,
    threshold: int = 5,
    console_output: bool = True
) -> Dict[str, Any]:
    """
    Выводит в консоль список подозрительных IP-адресов.
    
    Args:
        ip_df: DataFrame с данными об IP
        threshold: Пороговое значение количества событий
        console_output: Выводить ли информацию в консоль
    
    Returns:
        Dict[str, Any]: Статистика по подозрительным IP
    
    Examples:
        >>> ip_data = pd.DataFrame({
        ...     'src_ip': ['192.168.1.10', '192.168.1.20'],
        ...     'count': [15, 3],
        ...     'avg_severity': [1.2, 2.0]
        ... })
        >>> stats = notify_suspicious_ips(ip_data, threshold=5)
    """
    # Проверка типа входных данных
    if not isinstance(ip_df, pd.DataFrame):
        logger.error(f"Ожидался DataFrame, получен {type(ip_df)}")
        return {
            'error': f"Invalid input type: {type(ip_df)}",
            'total_ips': 0,
            'suspicious_ips': 0,
            'threshold': threshold
        }
    
    if ip_df is None or ip_df.empty:
        logger.info("Нет данных об IP для анализа")
        return {'total_ips': 0, 'suspicious_ips': 0, 'threshold': threshold}
    
    # Проверяем наличие нужных колонок
    required_columns = ['src_ip', 'count']
    missing = [col for col in required_columns if col not in ip_df.columns]
    if missing:
        logger.error(f"В DataFrame отсутствуют колонки: {missing}")
        return {
            'error': f"Missing columns: {missing}",
            'total_ips': 0,
            'suspicious_ips': 0,
            'threshold': threshold
        }
    
    # Фильтруем IP с количеством событий выше порога
    suspicious_df = ip_df[ip_df['count'] >= threshold].copy()
    
    stats = {
        'total_ips': len(ip_df),
        'suspicious_ips': len(suspicious_df),
        'threshold': threshold,
        'max_count': suspicious_df['count'].max() if not suspicious_df.empty else 0
    }
    
    if suspicious_df.empty:
        message = f"Подозрительных IP (событий >= {threshold}) не обнаружено."
        if console_output:
            print(message)
        logger.info(message)
        return stats
    
    if console_output:
        print(f"\n=== ПОДОЗРИТЕЛЬНЫЕ IP (событий >= {threshold}) ===")
        
        # Сортируем по убыванию количества событий
        suspicious_df = suspicious_df.sort_values('count', ascending=False)
        
        for idx, row in suspicious_df.iterrows():
            ip = row['src_ip']
            count = row['count']
            
            # Если есть информация о severity
            if 'avg_severity' in row:
                severity = row['avg_severity']
                print(f"{ip} | событий: {count} | средний severity: {severity:.2f}")
            else:
                print(f"{ip} | событий: {count}")
        
        print("===========================================\n")
    
    logger.info(f"Найдено {len(suspicious_df)} подозрительных IP (событий >= {threshold})")
    
    return stats


def generate_threat_report(
    cve_stats: Dict[str, Any],
    ip_stats: Dict[str, Any],
    block_count: int
) -> str:
    """
    Генерирует текстовый отчёт об угрозах.
    
    Args:
        cve_stats: Статистика по CVE
        ip_stats: Статистика по IP
        block_count: Количество заблокированных IP
    
    Returns:
        str: Отформатированный текстовый отчёт
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = []
    report.append("=" * 50)
    report.append(f"ОТЧЁТ ОБ УГРОЗАХ - {timestamp}")
    report.append("=" * 50)
    report.append("")
    
    # CVE статистика
    report.append("📋 КРИТИЧЕСКИЕ УЯЗВИМОСТИ:")
    report.append(f"  Всего уязвимостей: {cve_stats.get('total_cves', 0)}")
    report.append(f"  Критических (CVSS >= {cve_stats.get('threshold', 7.0)}): {cve_stats.get('critical_cves', 0)}")
    if cve_stats.get('critical_cves', 0) > 0:
        report.append(f"  Макс. CVSS: {cve_stats.get('max_cvss', 0):.1f}")
        report.append(f"  Средний CVSS: {cve_stats.get('avg_cvss', 0):.2f}")
    report.append("")
    
    # IP статистика
    report.append("🌐 ПОДОЗРИТЕЛЬНЫЕ IP:")
    report.append(f"  Всего уникальных IP: {ip_stats.get('total_ips', 0)}")
    report.append(f"  Подозрительных (>= {ip_stats.get('threshold', 5)} событий): {ip_stats.get('suspicious_ips', 0)}")
    if ip_stats.get('suspicious_ips', 0) > 0:
        report.append(f"  Макс. событий: {ip_stats.get('max_count', 0)}")
    report.append("")
    
    # Блокировки
    report.append("🔒 БЛОКИРОВКИ:")
    report.append(f"  Заблокировано IP: {block_count}")
    report.append("")
    report.append("=" * 50)
    
    return "\n".join(report)


if __name__ == "__main__":
    # Пример использования
    logging.basicConfig(level=logging.INFO)
    
    print("Тестирование модуля responder.py")
    print("-" * 50)
    
    # Тест блокировки
    print("\n1. Тест блокировки IP:")
    test_ips = ['192.168.1.10', '10.0.0.1', '172.16.0.5']
    simulate_blocking(test_ips, reason="Тестовая блокировка")
    
    # Тест уведомлений о CVE
    print("\n2. Тест уведомлений о CVE:")
    test_cves = pd.DataFrame({
        'cve_id': ['CVE-2023-1234', 'CVE-2023-5678', 'CVE-2023-9012'],
        'cvss': [9.8, 7.2, 4.5],
        'description': [
            'Критическая уязвимость удалённого выполнения кода',
            'Межсайтовый скриптинг высокой степени риска',
            'Умеренная уязвимость раскрытия информации'
        ]
    })
    cve_stats = notify_critical_cves(test_cves)
    
    # Тест подозрительных IP
    print("\n3. Тест подозрительных IP:")
    test_ips_df = pd.DataFrame({
        'src_ip': ['192.168.1.10', '192.168.1.20', '192.168.1.30', '192.168.1.40'],
        'count': [15, 8, 3, 1],
        'avg_severity': [1.2, 2.0, 2.5, 3.0]
    })
    ip_stats = notify_suspicious_ips(test_ips_df, threshold=5)
    
    # Генерация отчёта
    print("\n4. Генерация отчёта:")
    report = generate_threat_report(cve_stats, ip_stats, len(test_ips))
    print(report)
    
    print("\n✅ Все тесты завершены")