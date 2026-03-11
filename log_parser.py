"""
Модуль для парсинга логов Suricata в формате JSON lines (eve.json).

Предоставляет функции для извлечения событий типа 'alert' с последующим
анализом и валидацией данных.
"""

import json
import logging
import os
import sys
from typing import List, Dict, Any, Optional, Generator
from dataclasses import dataclass, asdict
from datetime import datetime
import gzip
import pandas as pd

logger = logging.getLogger(__name__)


class SuricataParseError(Exception):
    """Базовое исключение для ошибок парсинга логов Suricata"""
    pass


class FileAccessError(SuricataParseError):
    """Ошибка доступа к файлу"""
    pass


class InvalidJsonError(SuricataParseError):
    """Ошибка при парсинге JSON"""
    pass


@dataclass
class SuricataAlert:
    """
    Структурированное представление alert-события из логов Suricata.
    
    Attributes:
        timestamp: Время события (строка в формате ISO)
        src_ip: Исходный IP-адрес
        dest_ip: IP-адрес назначения (может быть None)
        alert_severity: Уровень серьёзности (1-3, где 1 - самый высокий)
        alert_signature: Название сигнатуры срабатывания
        proto: Протокол (tcp/udp/icmp) - опционально
        src_port: Порт источника - опционально
        dest_port: Порт назначения - опционально
    """
    timestamp: str
    src_ip: str
    alert_severity: int
    alert_signature: str
    dest_ip: Optional[str] = None
    proto: Optional[str] = None
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует в словарь, убирая None значения"""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    @property
    def severity_level(self) -> str:
        """Возвращает текстовое описание уровня серьёзности"""
        levels = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW'}
        return levels.get(self.alert_severity, 'UNKNOWN')


def parse_suricata_logs(
    file_path: str, 
    max_alerts: Optional[int] = None,
    severity_filter: Optional[List[int]] = None
) -> List[Dict[str, Any]]:
    """
    Парсит логи Suricata. Поддерживает как JSON Lines (построчный),
    так и обычный JSON массив.
    
    Функция автоматически определяет формат файла:
    - Если файл начинается с '[', парсится как JSON массив
    - Иначе парсится как JSON Lines (построчно)
    
    Args:
        file_path: Путь к файлу с логами (может быть .json или .json.gz)
        max_alerts: Максимальное количество событий для извлечения (None - все)
        severity_filter: Список уровней серьёзности для фильтрации (например, [1, 2])
    
    Returns:
        List[Dict]: Список словарей с полями:
            - timestamp: время события
            - src_ip: исходный IP-адрес
            - dest_ip: IP назначения (опционально)
            - alert_severity: уровень серьёзности (1-3)
            - alert_signature: название сигнатуры
            - proto: протокол (опционально)
            - src_port: порт источника (опционально)
            - dest_port: порт назначения (опционально)
    
    Raises:
        FileAccessError: Если файл не существует или нет прав на чтение
        SuricataParseError: При критических ошибках парсинга
    """
    # Проверка существования файла
    if not os.path.exists(file_path):
        raise FileAccessError(f"Файл не найден: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise FileAccessError(f"Нет прав на чтение файла: {file_path}")
    
    alerts = []
    line_num = 0
    errors_count = 0
    
    # Определяем, как открывать файл (обычный или gzip)
    open_func = gzip.open if file_path.endswith('.gz') else open
    mode = 'rt' if file_path.endswith('.gz') else 'r'
    
    try:
        with open_func(file_path, mode, encoding='utf-8') as f:
            # Читаем первый символ для определения формата
            first_char = f.read(1)
            f.seek(0)  # Возвращаемся в начало файла
            
            # Если файл начинается с '[', это JSON массив
            if first_char == '[':
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        logger.info(f"Обнаружен JSON массив с {len(data)} элементами")
                        
                        for idx, item in enumerate(data, 1):
                            # Проверяем лимит
                            if max_alerts and len(alerts) >= max_alerts:
                                logger.info(f"Достигнут лимит в {max_alerts} событий, остановка")
                                break
                            
                            # Проверяем тип события
                            if item.get('event_type') != 'alert':
                                continue
                            
                            # Извлекаем поля (та же логика что и для построчного формата)
                            timestamp = item.get('timestamp')
                            src_ip = item.get('src_ip')
                            dest_ip = item.get('dest_ip')
                            proto = item.get('proto')
                            src_port = item.get('src_port')
                            dest_port = item.get('dest_port')
                            
                            # Извлекаем информацию из alert
                            alert_info = item.get('alert', {})
                            if not isinstance(alert_info, dict):
                                logger.warning(f"Элемент {idx}: поле 'alert' не является словарём")
                                continue
                            
                            severity = alert_info.get('severity')
                            signature = alert_info.get('signature')
                            
                            # Валидация обязательных полей
                            if not src_ip:
                                logger.debug(f"Элемент {idx}: пропущен - нет src_ip")
                                continue
                            
                            if severity is None:
                                logger.debug(f"Элемент {idx}: пропущен - нет severity")
                                continue
                            
                            # Приводим severity к int
                            try:
                                severity = int(severity)
                            except (TypeError, ValueError):
                                logger.warning(f"Элемент {idx}: некорректный severity '{severity}'")
                                continue
                            
                            # Фильтр по severity
                            if severity_filter and severity not in severity_filter:
                                continue
                            
                            # Создаём структурированный объект
                            alert = SuricataAlert(
                                timestamp=timestamp or '',
                                src_ip=src_ip,
                                dest_ip=dest_ip,
                                alert_severity=severity,
                                alert_signature=signature or 'unknown',
                                proto=proto,
                                src_port=src_port,
                                dest_port=dest_port
                            )
                            
                            alerts.append(alert.to_dict())
                        
                        logger.info(f"Обработан JSON массив, загружено {len(alerts)} alert-событий")
                        return alerts
                        
                except json.JSONDecodeError as e:
                    logger.warning(f"Ошибка парсинга JSON массива: {e}, пробуем как JSON Lines")
                    f.seek(0)  # Возвращаемся в начало для построчного чтения
            
            # Построчное чтение (JSON Lines)
            for line_num, line in enumerate(f, 1):
                # Проверяем лимит
                if max_alerts and len(alerts) >= max_alerts:
                    logger.info(f"Достигнут лимит в {max_alerts} событий, остановка")
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # Пропускаем скобки JSON массива если они есть
                if line in ['[', ']'] or line.startswith(']'):
                    continue
                
                # Убираем запятые в конце строк (для случая когда файл это массив с элементами на отдельных строках)
                if line.endswith(','):
                    line = line[:-1]
                
                # Парсинг JSON с обработкой ошибок
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as e:
                    errors_count += 1
                    if errors_count <= 10:
                        logger.warning(f"Строка {line_num} не является валидным JSON: {e}")
                    elif errors_count == 11:
                        logger.warning("Слишком много JSON ошибок, дальнейшие подавляются")
                    continue
                
                # Проверяем тип события
                if event.get('event_type') != 'alert':
                    continue
                
                # Извлекаем основные поля
                timestamp = event.get('timestamp')
                src_ip = event.get('src_ip')
                dest_ip = event.get('dest_ip')
                proto = event.get('proto')
                src_port = event.get('src_port')
                dest_port = event.get('dest_port')
                
                # Извлекаем информацию из alert
                alert_info = event.get('alert', {})
                if not isinstance(alert_info, dict):
                    logger.warning(f"Строка {line_num}: поле 'alert' не является словарём")
                    continue
                
                severity = alert_info.get('severity')
                signature = alert_info.get('signature')
                
                # Валидация обязательных полей
                if not src_ip:
                    logger.debug(f"Строка {line_num}: пропущена - нет src_ip")
                    continue
                
                if severity is None:
                    logger.debug(f"Строка {line_num}: пропущена - нет severity")
                    continue
                
                # Приводим severity к int
                try:
                    severity = int(severity)
                except (TypeError, ValueError):
                    logger.warning(f"Строка {line_num}: некорректный severity '{severity}'")
                    continue
                
                # Фильтр по severity
                if severity_filter and severity not in severity_filter:
                    continue
                
                # Создаём структурированный объект
                alert = SuricataAlert(
                    timestamp=timestamp or '',
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    alert_severity=severity,
                    alert_signature=signature or 'unknown',
                    proto=proto,
                    src_port=src_port,
                    dest_port=dest_port
                )
                
                alerts.append(alert.to_dict())
                
    except FileNotFoundError:
        raise FileAccessError(f"Файл не найден: {file_path}")
    except PermissionError:
        raise FileAccessError(f"Нет прав на чтение файла: {file_path}")
    except Exception as e:
        raise SuricataParseError(f"Критическая ошибка при чтении файла {file_path}: {e}")
    
    # Логируем статистику
    logger.info(f"Обработано строк: {line_num}, ошибок JSON: {errors_count}")
    logger.info(f"Загружено {len(alerts)} alert-событий из файла {file_path}")
    
    if severity_filter:
        logger.info(f"Применён фильтр по severity: {severity_filter}")
    
    return alerts


def stream_suricata_logs(
    file_path: str,
    chunk_size: int = 100
) -> Generator[List[Dict[str, Any]], None, None]:
    """
    Потоковое чтение логов Suricata для экономии памяти.
    
    Args:
        file_path: Путь к файлу с логами
        chunk_size: Количество событий в одном чанке
    
    Yields:
        Списки alert-событий размером не более chunk_size
    
    Examples:
        >>> for chunk in stream_suricata_logs('large_log.json.gz'):
        ...     process_alerts(chunk)
    """
    chunk = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        chunk.append(event)
                        
                        if len(chunk) >= chunk_size:
                            yield chunk
                            chunk = []
                except json.JSONDecodeError:
                    continue
                    
    except Exception as e:
        logger.error(f"Ошибка при потоковом чтении: {e}")
        raise
    
    # Возвращаем остаток
    if chunk:
        yield chunk


def get_log_statistics(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Возвращает статистику по загруженным alert-событиям.
    
    Args:
        alerts: Список alert-событий
    
    Returns:
        Словарь со статистикой:
            - total_alerts: общее количество
            - unique_ips: количество уникальных src_ip
            - severity_distribution: распределение по severity
            - top_signatures: топ-5 сигнатур
            - time_range: временной диапазон (если есть timestamp)
    
    Examples:
        >>> alerts = parse_suricata_logs('eve.json')
        >>> stats = get_log_statistics(alerts)
        >>> print(f"Уникальных IP: {stats['unique_ips']}")
    """
    if not alerts:
        return {
            'total_alerts': 0,
            'unique_ips': 0,
            'severity_distribution': {1: 0, 2: 0, 3: 0},
            'top_signatures': [],
            'time_range': None
        }
    
    df = pd.DataFrame(alerts) if 'pandas' in sys.modules else None
    
    if df is not None:
        # Используем pandas для быстрой статистики
        stats = {
            'total_alerts': len(df),
            'unique_ips': df['src_ip'].nunique(),
            'severity_distribution': df['alert_severity'].value_counts().to_dict(),
            'top_signatures': df['alert_signature'].value_counts().head(5).to_dict()
        }
        
        # Временной диапазон
        if 'timestamp' in df.columns:
            try:
                times = pd.to_datetime(df['timestamp'])
                stats['time_range'] = {
                    'start': times.min().isoformat(),
                    'end': times.max().isoformat(),
                    'duration_seconds': (times.max() - times.min()).total_seconds()
                }
            except:
                stats['time_range'] = None
    else:
        # Ручной подсчёт (без pandas)
        from collections import Counter
        
        ips = Counter()
        signatures = Counter()
        severity_count = {1: 0, 2: 0, 3: 0}
        
        for alert in alerts:
            ips[alert['src_ip']] += 1
            signatures[alert['alert_signature']] += 1
            sev = alert['alert_severity']
            if sev in severity_count:
                severity_count[sev] += 1
        
        stats = {
            'total_alerts': len(alerts),
            'unique_ips': len(ips),
            'severity_distribution': severity_count,
            'top_signatures': dict(signatures.most_common(5))
        }
    
    return stats


def validate_log_format(file_path: str) -> bool:
    """
    Проверяет, что файл имеет корректный формат логов Suricata.
    
    Args:
        file_path: Путь к файлу
    
    Returns:
        True если формат корректен, иначе False
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Проверяем первые 10 строк
            for i, line in enumerate(f):
                if i >= 10:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    # Проверяем наличие обязательных полей
                    if 'event_type' not in event:
                        return False
                    if 'timestamp' not in event:
                        return False
                except json.JSONDecodeError:
                    return False
        
        return True
        
    except Exception:
        return False


if __name__ == "__main__":
    # Тестовый запуск с обработкой аргументов командной строки
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Парсер логов Suricata')
    parser.add_argument('file', help='Путь к файлу лога')
    parser.add_argument('--limit', type=int, help='Максимальное количество событий')
    parser.add_argument('--severity', type=int, nargs='+', choices=[1,2,3],
                       help='Фильтр по severity (например: --severity 1 2)')
    parser.add_argument('--stats', action='store_true', 
                       help='Показать статистику')
    
    args = parser.parse_args()
    
    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Проверка формата
        if not validate_log_format(args.file):
            print("⚠️  Файл не похож на корректный лог Suricata")
        
        # Парсинг
        alerts = parse_suricata_logs(
            args.file,
            max_alerts=args.limit,
            severity_filter=args.severity
        )
        
        print(f"\n✅ Найдено {len(alerts)} alert-событий")
        
        # Показываем первые несколько
        if alerts:
            print("\n📋 Первые 5 событий:")
            for i, alert in enumerate(alerts[:5], 1):
                print(f"{i}. {alert['timestamp']} | {alert['src_ip']} | "
                      f"sev:{alert['alert_severity']} | {alert['alert_signature'][:50]}...")
        
        # Статистика
        if args.stats and alerts:
            print("\n📊 Статистика:")
            stats = get_log_statistics(alerts)
            print(f"   Уникальных IP: {stats['unique_ips']}")
            print(f"   Распределение по severity: {stats['severity_distribution']}")
            print(f"   Топ сигнатур: {stats['top_signatures']}")
            
    except FileAccessError as e:
        print(f"❌ Ошибка доступа к файлу: {e}")
        sys.exit(1)
    except SuricataParseError as e:
        print(f"❌ Ошибка парсинга: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        sys.exit(1)