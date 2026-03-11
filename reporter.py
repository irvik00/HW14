"""
Модуль для сохранения результатов анализа в файлы различных форматов.

Предоставляет функции для сохранения DataFrame в CSV и словарей в JSON,
с автоматическим созданием необходимых директорий и обработкой ошибок.
"""

import os
import json
import pandas as pd
import logging
from typing import Dict, Any, Optional, Union, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Константы
DEFAULT_REPORTS_DIR = "reports"
DEFAULT_CSV_ENCODING = 'utf-8-sig'  # utf-8-sig для корректного отображения в Excel
DEFAULT_JSON_INDENT = 2


class ReportError(Exception):
    """Базовое исключение для ошибок сохранения отчётов"""
    pass


class DirectoryCreationError(ReportError):
    """Ошибка при создании директории"""
    pass


class FileWriteError(ReportError):
    """Ошибка при записи файла"""
    pass


class DataValidationError(ReportError):
    """Ошибка валидации данных"""
    pass


def ensure_reports_dir(reports_dir: str = DEFAULT_REPORTS_DIR) -> Path:
    """
    Создаёт папку для отчётов, если её нет.
    
    Args:
        reports_dir: Путь к директории для отчётов
    
    Returns:
        Path: Объект Path созданной директории
    
    Raises:
        DirectoryCreationError: Если не удалось создать директорию
    
    Examples:
        >>> reports_path = ensure_reports_dir("my_reports")
        >>> print(reports_path)  # my_reports
    """
    try:
        path = Path(reports_dir)
        path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Директория {reports_dir} готова")
        return path
    except Exception as e:
        raise DirectoryCreationError(f"Не удалось создать директорию {reports_dir}: {e}")


def validate_dataframe(df: pd.DataFrame, required_columns: Optional[List[str]] = None) -> bool:
    """
    Проверяет DataFrame на корректность перед сохранением.
    
    Args:
        df: DataFrame для проверки
        required_columns: Список обязательных колонок
    
    Returns:
        bool: True если данные корректны
    
    Raises:
        DataValidationError: Если данные некорректны
    """
    if df is None:
        raise DataValidationError("DataFrame не может быть None")
    
    if not isinstance(df, pd.DataFrame):
        raise DataValidationError(f"Ожидался DataFrame, получен {type(df)}")
    
    if required_columns:
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise DataValidationError(f"В DataFrame отсутствуют колонки: {missing_columns}")
    
    return True


def validate_dict(data: Dict[str, Any], required_keys: Optional[List[str]] = None) -> bool:
    """
    Проверяет словарь на корректность перед сохранением.
    
    Args:
        data: Словарь для проверки
        required_keys: Список обязательных ключей
    
    Returns:
        bool: True если данные корректны
    
    Raises:
        DataValidationError: Если данные некорректны
    """
    if data is None:
        raise DataValidationError("Словарь не может быть None")
    
    if not isinstance(data, dict):
        raise DataValidationError(f"Ожидался словарь, получен {type(data)}")
    
    if required_keys:
        missing_keys = [key for key in required_keys if key not in data]
        if missing_keys:
            raise DataValidationError(f"В словаре отсутствуют ключи: {missing_keys}")
    
    return True


def save_cves(
    cve_df: pd.DataFrame, 
    filename: str = "critical_cves.csv",
    reports_dir: str = DEFAULT_REPORTS_DIR,
    include_index: bool = False,
    required_columns: Optional[List[str]] = None
) -> str:
    """
    Сохраняет DataFrame с критическими уязвимостями в CSV.
    
    Функция проверяет данные перед сохранением, создаёт директорию
    при необходимости и возвращает полный путь к сохранённому файлу.
    
    Args:
        cve_df: DataFrame с данными о CVE
        filename: Имя файла (по умолчанию "critical_cves.csv")
        reports_dir: Директория для сохранения
        include_index: Включать ли индекс DataFrame в файл
        required_columns: Список обязательных колонок
    
    Returns:
        str: Полный путь к сохранённому файлу
    
    Raises:
        DataValidationError: Если данные некорректны
        FileWriteError: Если не удалось записать файл
    
    Examples:
        >>> cve_data = pd.DataFrame({'cve_id': ['CVE-2023-1234'], 'cvss': [9.8]})
        >>> path = save_cves(cve_data)
        >>> print(f"Сохранено в {path}")
        
        >>> # С пользовательским именем и директорией
        >>> path = save_cves(cve_data, "critical.csv", "output")
    """
    # Валидация
    try:
        validate_dataframe(cve_df, required_columns or ['cve_id', 'cvss'])
    except DataValidationError as e:
        logger.error(f"Ошибка валидации данных CVE: {e}")
        raise
    
    # Проверка на пустой DataFrame
    if cve_df.empty:
        logger.warning("DataFrame с CVE пуст, будет сохранён пустой файл")
    
    # Создание директории
    try:
        reports_path = ensure_reports_dir(reports_dir)
    except DirectoryCreationError as e:
        logger.error(f"Ошибка создания директории: {e}")
        raise
    
    # Формирование полного пути
    filepath = reports_path / filename
    
    try:
        # Сохранение в CSV
        cve_df.to_csv(
            filepath, 
            index=include_index, 
            encoding=DEFAULT_CSV_ENCODING,
            errors='replace'  # Заменяем некорректные символы
        )
        
        # Проверяем, что файл создан и не пуст
        if not filepath.exists():
            raise FileWriteError(f"Файл {filepath} не был создан")
        
        file_size = filepath.stat().st_size
        logger.info(f"Сохранён отчёт с CVE: {filepath} (размер: {file_size} байт, записей: {len(cve_df)})")
        
        return str(filepath)
        
    except PermissionError:
        raise FileWriteError(f"Нет прав на запись в {filepath}")
    except OSError as e:
        raise FileWriteError(f"Ошибка ввода-вывода при сохранении {filepath}: {e}")
    except Exception as e:
        raise FileWriteError(f"Неожиданная ошибка при сохранении {filepath}: {e}")


def save_top_ips(
    ip_df: pd.DataFrame, 
    filename: str = "top_ips.csv",
    reports_dir: str = DEFAULT_REPORTS_DIR,
    include_index: bool = False,
    required_columns: Optional[List[str]] = None
) -> str:
    """
    Сохраняет топ IP-адресов в CSV.
    
    Args:
        ip_df: DataFrame с данными об IP
        filename: Имя файла (по умолчанию "top_ips.csv")
        reports_dir: Директория для сохранения
        include_index: Включать ли индекс DataFrame в файл
        required_columns: Список обязательных колонок
    
    Returns:
        str: Полный путь к сохранённому файлу
    
    Raises:
        DataValidationError: Если данные некорректны
        FileWriteError: Если не удалось записать файл
    
    Examples:
        >>> ip_data = pd.DataFrame({'src_ip': ['192.168.1.1'], 'count': [10]})
        >>> path = save_top_ips(ip_data)
    """
    # Валидация
    try:
        validate_dataframe(ip_df, required_columns or ['src_ip', 'count'])
    except DataValidationError as e:
        logger.error(f"Ошибка валидации данных IP: {e}")
        raise
    
    # Проверка на пустой DataFrame
    if ip_df.empty:
        logger.warning("DataFrame с IP пуст, будет сохранён пустой файл")
    
    # Создание директории
    try:
        reports_path = ensure_reports_dir(reports_dir)
    except DirectoryCreationError as e:
        logger.error(f"Ошибка создания директории: {e}")
        raise
    
    # Формирование полного пути
    filepath = reports_path / filename
    
    try:
        # Сохранение в CSV
        ip_df.to_csv(
            filepath, 
            index=include_index, 
            encoding=DEFAULT_CSV_ENCODING,
            errors='replace'
        )
        
        file_size = filepath.stat().st_size
        logger.info(f"Сохранён отчёт с топ IP: {filepath} (размер: {file_size} байт, записей: {len(ip_df)})")
        
        return str(filepath)
        
    except PermissionError:
        raise FileWriteError(f"Нет прав на запись в {filepath}")
    except Exception as e:
        raise FileWriteError(f"Ошибка при сохранении {filepath}: {e}")


def save_summary(
    stats: Dict[str, Any], 
    filename: str = "summary.json",
    reports_dir: str = DEFAULT_REPORTS_DIR,
    required_keys: Optional[List[str]] = None
) -> str:
    """
    Сохраняет словарь со статистикой в JSON-файл.
    
    Функция автоматически обрабатывает специальные типы данных
    (например, numpy типы) для корректной сериализации в JSON.
    
    Args:
        stats: Словарь со статистикой
        filename: Имя файла (по умолчанию "summary.json")
        reports_dir: Директория для сохранения
        required_keys: Список обязательных ключей
    
    Returns:
        str: Полный путь к сохранённому файлу
    
    Raises:
        DataValidationError: Если данные некорректны
        FileWriteError: Если не удалось записать файл
    
    Examples:
        >>> stats = {'total_alerts': 100, 'unique_ips': 5}
        >>> path = save_summary(stats)
        
        >>> # С указанием обязательных ключей
        >>> path = save_summary(stats, required_keys=['total_alerts'])
    """
    # Валидация
    try:
        validate_dict(stats, required_keys)
    except DataValidationError as e:
        logger.error(f"Ошибка валидации статистики: {e}")
        raise
    
    # Создание директории
    try:
        reports_path = ensure_reports_dir(reports_dir)
    except DirectoryCreationError as e:
        logger.error(f"Ошибка создания директории: {e}")
        raise
    
    # Формирование полного пути
    filepath = reports_path / filename
    
    # Функция для обработки специальных типов данных
    def json_serializer(obj):
        """Сериализует специальные типы для JSON"""
        # Pandas Timestamp
        if isinstance(obj, pd.Timestamp):
            return obj.isoformat()
        
        # datetime
        if isinstance(obj, datetime):
            return obj.isoformat()
        
        # Pandas Series
        if isinstance(obj, pd.Series):
            return obj.to_list()
        
        # Pandas DataFrame
        if isinstance(obj, pd.DataFrame):
            return obj.to_dict('records')
        
        # NumPy скаляры (int, float)
        if hasattr(obj, 'dtype') and hasattr(obj, 'shape') and obj.shape == ():
            return obj.item()
        
        # NumPy массивы
        if hasattr(obj, 'dtype') and hasattr(obj, 'tolist'):
            return obj.tolist()
        
        # NumPy типы (старый способ проверки)
        if hasattr(obj, 'item') and not hasattr(obj, '__len__'):
            return obj.item()
        
        # Если ничего не подошло
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(
                stats, 
                f, 
                ensure_ascii=False, 
                indent=DEFAULT_JSON_INDENT,
                default=json_serializer
            )
        
        # Проверяем, что файл создан
        if not filepath.exists():
            raise FileWriteError(f"Файл {filepath} не был создан")
        
        file_size = filepath.stat().st_size
        logger.info(f"Сохранён JSON-отчёт: {filepath} (размер: {file_size} байт)")
        
        return str(filepath)
        
    except TypeError as e:
        raise FileWriteError(f"Ошибка сериализации данных в JSON: {e}")
    except PermissionError:
        raise FileWriteError(f"Нет прав на запись в {filepath}")
    except Exception as e:
        raise FileWriteError(f"Ошибка при сохранении {filepath}: {e}")


def save_all_reports(
    cve_df: pd.DataFrame,
    ip_df: pd.DataFrame,
    stats: Dict[str, Any],
    reports_dir: str = DEFAULT_REPORTS_DIR,
    prefix: str = ""
) -> Dict[str, str]:
    """
    Сохраняет все отчёты одной командой.
    
    Args:
        cve_df: DataFrame с CVE
        ip_df: DataFrame с IP
        stats: Словарь со статистикой
        reports_dir: Директория для сохранения
        prefix: Префикс для имён файлов (например, "scan_20240101_")
    
    Returns:
        Dict[str, str]: Словарь с путями к сохранённым файлам
    
    Examples:
        >>> files = save_all_reports(cve_df, ip_df, stats, prefix="morning_")
        >>> print(f"CVE сохранены в {files['cve_file']}")
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if prefix:
        cve_filename = f"{prefix}critical_cves.csv"
        ip_filename = f"{prefix}top_ips.csv"
        json_filename = f"{prefix}summary.json"
    else:
        cve_filename = f"critical_cves_{timestamp}.csv"
        ip_filename = f"top_ips_{timestamp}.csv"
        json_filename = f"summary_{timestamp}.json"
    
    results = {}
    
    try:
        results['cve_file'] = save_cves(cve_df, cve_filename, reports_dir)
    except Exception as e:
        logger.error(f"Не удалось сохранить CVE: {e}")
        results['cve_file'] = None
    
    try:
        results['ip_file'] = save_top_ips(ip_df, ip_filename, reports_dir)
    except Exception as e:
        logger.error(f"Не удалось сохранить IP: {e}")
        results['ip_file'] = None
    
    try:
        results['json_file'] = save_summary(stats, json_filename, reports_dir)
    except Exception as e:
        logger.error(f"Не удалось сохранить JSON: {e}")
        results['json_file'] = None
    
    return results


def cleanup_old_reports(
    reports_dir: str = DEFAULT_REPORTS_DIR,
    days_to_keep: int = 7,
    pattern: str = "*.csv"
) -> int:
    """
    Удаляет старые отчётные файлы.
    
    Args:
        reports_dir: Директория с отчётами
        days_to_keep: Сколько дней хранить файлы
        pattern: Маска для выбора файлов
    
    Returns:
        int: Количество удалённых файлов
    
    Examples:
        >>> deleted = cleanup_old_reports(days_to_keep=30)
        >>> print(f"Удалено {deleted} старых файлов")
    """
    from datetime import timedelta
    import time
    
    cutoff_time = time.time() - (days_to_keep * 24 * 60 * 60)
    deleted_count = 0
    
    try:
        reports_path = Path(reports_dir)
        if not reports_path.exists():
            return 0
        
        for file_path in reports_path.glob(pattern):
            if file_path.stat().st_mtime < cutoff_time:
                file_path.unlink()
                deleted_count += 1
                logger.info(f"Удалён старый файл: {file_path}")
        
        logger.info(f"Очистка завершена, удалено {deleted_count} файлов")
        return deleted_count
        
    except Exception as e:
        logger.error(f"Ошибка при очистке старых файлов: {e}")
        return 0


if __name__ == "__main__":
    # Пример использования
    logging.basicConfig(level=logging.INFO)
    
    # Создаём тестовые данные
    test_cves = pd.DataFrame({
        'cve_id': ['CVE-2023-1234', 'CVE-2023-5678'],
        'cvss': [9.8, 7.5],
        'description': ['Critical RCE', 'High XSS']
    })
    
    test_ips = pd.DataFrame({
        'src_ip': ['192.168.1.10', '192.168.1.20', '192.168.1.30'],
        'count': [15, 8, 3],
        'avg_severity': [1.2, 2.0, 2.7]
    })
    
    test_stats = {
        'total_alerts': 100,
        'unique_ips': 25,
        'scan_time': datetime.now().isoformat(),
        'threat_level': 'HIGH'
    }
    
    print("Тестирование сохранения отчётов...")
    
    # Сохраняем отдельно
    print("\n1. Сохраняем CVE:")
    cve_path = save_cves(test_cves)
    print(f"   {cve_path}")
    
    print("\n2. Сохраняем IP:")
    ip_path = save_top_ips(test_ips)
    print(f"   {ip_path}")
    
    print("\n3. Сохраняем статистику:")
    json_path = save_summary(test_stats)
    print(f"   {json_path}")
    
    print("\n4. Сохраняем всё вместе:")
    all_files = save_all_reports(test_cves, test_ips, test_stats, prefix="test_")
    for name, path in all_files.items():
        print(f"   {name}: {path}")
    
    print("\n✅ Все тесты сохранения завершены")