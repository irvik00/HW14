"""
Главный модуль системы автоматизированного мониторинга и реагирования на угрозы.

Координирует работу всех компонентов:
- Сбор данных из API Vulners и логов Suricata
- Анализ уязвимостей и подозрительной активности
- Имитация реагирования на угрозы
- Сохранение отчётов и визуализация результатов
"""
import os
import sys
import logging
import argparse
import signal
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path

from dotenv import load_dotenv

from api_client import get_vulnerabilities, VulnersAPIError
from log_parser import parse_suricata_logs, SuricataParseError, FileAccessError
from analyzer import find_critical_cves, get_top_ips, cvss_distribution, get_cvss_summary_stats
from responder import simulate_blocking, notify_critical_cves, ResponderError, DataValidationError
from reporter import save_cves, save_top_ips, save_summary, ReportError
from visualizer import plot_top_ips, plot_cvss_distribution, VisualizationError
from config import get_user_config
from email_sender import send_alert


# Настройка логирования
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("threat_analyzer.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ThreatAnalyzerError(Exception):
    """Базовое исключение для ошибок анализатора угроз"""
    pass


class ConfigurationError(ThreatAnalyzerError):
    """Ошибка конфигурации"""
    pass


class DataCollectionError(ThreatAnalyzerError):
    """Ошибка при сборе данных"""
    pass


class AnalysisError(ThreatAnalyzerError):
    """Ошибка при анализе данных"""
    pass


class ReportingError(ThreatAnalyzerError):
    """Ошибка при формировании отчётов"""
    pass


def parse_arguments() -> argparse.Namespace:
    """
    Парсит аргументы командной строки.
    """
    parser = argparse.ArgumentParser(
        description='Автоматизированный мониторинг и реагирование на угрозы',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py --log-file logs/eve.json --vuln-limit 50
  python main.py --no-block --threshold 8.0
  python main.py --skip-vulns --skip-logs --test-mode
        """
    )
    
    parser.add_argument('--log-file', type=str, help='Путь к файлу логов Suricata')
    parser.add_argument('--vuln-limit', type=int, help='Количество уязвимостей для загрузки')
    parser.add_argument('--threshold', type=float, help='Порог CVSS для критичности')
    parser.add_argument('--block-threshold', type=int, help='Порог событий для блокировки IP')
    parser.add_argument('--top-n', type=int, help='Количество IP в топе')
    
    parser.add_argument(
        '--no-block', 
        action='store_true',
        help='Отключить имитацию блокировки IP'
    )
    
    parser.add_argument(
        '--skip-vulns', 
        action='store_true',
        help='Пропустить загрузку уязвимостей (только логи)'
    )
    
    parser.add_argument(
        '--skip-logs', 
        action='store_true',
        help='Пропустить загрузку логов (только уязвимости)'
    )
    
    parser.add_argument(
        '--test-mode', 
        action='store_true',
        help='Тестовый режим (использует тестовые данные)'
    )
    
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Подробный вывод (уровень DEBUG)'
    )    
    return parser.parse_args()


def setup_logging(verbose: bool = False) -> None:
    """Настраивает уровень логирования."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Включён подробный режим логирования")


def validate_configuration(args: argparse.Namespace) -> None:
    """Проверяет корректность конфигурации."""
    if args.skip_vulns and args.skip_logs:
        raise ConfigurationError("Нельзя пропустить оба источника данных")
    
    if args.threshold < 0 or args.threshold > 10:
        raise ConfigurationError(f"Порог CVSS должен быть от 0 до 10, получен {args.threshold}")
    
    if args.block_threshold < 0:
        raise ConfigurationError(f"Порог блокировки не может быть отрицательным: {args.block_threshold}")


def collect_data(args: argparse.Namespace) -> Tuple[list, list]:
    """Собирает данные из источников."""
    vulns = []
    alerts = []
    
    # Сбор уязвимостей
    if not args.skip_vulns:
        try:
            logger.info("Получение данных из API Vulners")
            vulns = get_vulnerabilities(limit=args.vuln_limit, min_cvss=None)
            logger.info(f"Получено {len(vulns)} уязвимостей")
        except VulnersAPIError as e:
            logger.error(f"Ошибка API Vulners: {e}")
            if not args.test_mode:
                raise DataCollectionError(f"Не удалось получить уязвимости: {e}")
            logger.warning("Продолжаем работу без данных об уязвимостях")
    
    # Сбор логов
    if not args.skip_logs:
        try:
            logger.info(f"Чтение логов Suricata из {args.log_file}")
            alerts = parse_suricata_logs(args.log_file)
            logger.info(f"Загружено {len(alerts)} alert-событий")
        except FileAccessError as e:
            logger.error(f"Ошибка доступа к файлу логов: {e}")
            if not args.test_mode:
                raise DataCollectionError(f"Не удалось прочитать логи: {e}")
            logger.warning("Продолжаем работу без данных из логов")
        except SuricataParseError as e:
            logger.error(f"Ошибка парсинга логов: {e}")
            if not args.test_mode:
                raise DataCollectionError(f"Ошибка при парсинге логов: {e}")
            logger.warning("Продолжаем работу с повреждёнными данными логов")
    
    return vulns, alerts


def analyze_threats(
    vulns: list,
    alerts: list,
    threshold: float,
    top_n: int
) -> Tuple[Any, Any, Any]:
    """Анализирует собранные данные."""
    try:
        logger.info("Анализ данных")
        
        critical_cves_df = find_critical_cves(vulns, threshold=threshold)
        top_ips_df = get_top_ips(alerts, top_n=top_n)
        cvss_series = cvss_distribution(vulns)
        
        # Логируем статистику
        if not critical_cves_df.empty:
            logger.info(f"Найдено {len(critical_cves_df)} критических уязвимостей")
            stats = get_cvss_summary_stats(vulns)
            logger.debug(f"Статистика CVSS: {stats}")
        
        if not top_ips_df.empty:
            logger.info(f"Топ-{top_n} IP: {top_ips_df['src_ip'].tolist()}")
        
        return critical_cves_df, top_ips_df, cvss_series
        
    except Exception as e:
        raise AnalysisError(f"Ошибка при анализе данных: {e}")


def respond_to_threats(
    critical_cves_df: Any,
    top_ips_df: Any,
    block_threshold: int,
    no_block: bool
) -> List[str]:
    """Выполняет реагирование на угрозы (только блокировка, без уведомления)."""
    suspicious_ips = []
    
    try:
        logger.info("Реагирование на угрозы (блокировка IP)")
        
        # Блокировка IP - УБРАН ВЫЗОВ notify_critical_cves
        if not no_block and not top_ips_df.empty:
            suspicious_ips = top_ips_df[
                top_ips_df['count'] >= block_threshold
            ]['src_ip'].tolist()
            
            if suspicious_ips:
                simulate_blocking(suspicious_ips, reason=f"Более {block_threshold} событий")
            else:
                logger.info(f"Нет IP с количеством событий >= {block_threshold}")
        
        return suspicious_ips
        
    except DataValidationError as e:
        logger.error(f"Ошибка валидации данных при реагировании: {e}")
        raise
    except ResponderError as e:
        logger.error(f"Ошибка при реагировании: {e}")
        raise


def generate_reports(
    vulns: list,
    alerts: list,
    critical_cves_df: Any,
    top_ips_df: Any,
    suspicious_ips: List[str],
    skip_vulns: bool,
    skip_logs: bool
) -> Dict[str, str]:
    """Генерирует и сохраняет отчёты."""
    files = {}
    
    try:
        logger.info("Сохранение отчётов")
        
        # Сохраняем CVE
        if not critical_cves_df.empty:
            files['cve'] = save_cves(critical_cves_df)
        else:
            logger.info("Нет данных для сохранения CVE")
        
        # Сохраняем IP
        if not top_ips_df.empty:
            files['ip'] = save_top_ips(top_ips_df)
        else:
            logger.info("Нет данных для сохранения IP")
        
        # Собираем общую статистику
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities_received": len(vulns),
            "critical_cves_found": len(critical_cves_df),
            "total_alerts_processed": len(alerts),
            "top_5_ips": top_ips_df.to_dict(orient='records') if not top_ips_df.empty else [],
            "blocked_ips_count": len(suspicious_ips),
            "blocked_ips": suspicious_ips,
            "sources": {
                "vulns_loaded": not skip_vulns,
                "logs_loaded": not skip_logs
            }
        }
        
        files['summary'] = save_summary(summary)
        
        return files
        
    except ReportError as e:
        raise ReportingError(f"Ошибка при сохранении отчётов: {e}")
    except Exception as e:
        raise ReportingError(f"Неожиданная ошибка при формировании отчётов: {e}")


def create_visualizations(
    top_ips_df: Any,
    cvss_series: Any
) -> Dict[str, str]:
    """Создаёт визуализации."""
    plots = {}
    
    try:
        logger.info("Построение графиков")
        
        # График IP
        if not top_ips_df.empty:
            plots['ips'] = plot_top_ips(top_ips_df, filename="threat_analysis.png")
        else:
            logger.info("Нет данных для построения графика IP")
        
        # Гистограмма CVSS
        if not cvss_series.empty:
            plots['cvss'] = plot_cvss_distribution(cvss_series, filename="cvss_distribution.png")
        else:
            logger.info("Нет данных для построения гистограммы CVSS")
        
        return plots
        
    except VisualizationError as e:
        logger.error(f"Ошибка при создании визуализаций: {e}")
        raise
    except Exception as e:
        raise VisualizationError(f"Неожиданная ошибка при создании графиков: {e}")


def print_summary(
    vulns: list,
    alerts: list,
    critical_cves_df: Any,
    top_ips_df: Any,
    suspicious_ips: list,
    files: Dict[str, str],
    plots: Dict[str, str]
) -> None:
    """Выводит краткую сводку результатов."""
    print("\n" + "="*60)
    print("ИТОГОВАЯ СВОДКА АНАЛИЗА УГРОЗ")
    print("="*60)
    
    print(f"\nИсточники данных:")
    print(f"  • Уязвимости: {len(vulns)}")
    print(f"  • Alert-события: {len(alerts)}")
    
    print(f"\nРезультаты анализа:")
    print(f"  • Критические CVE: {len(critical_cves_df)}")
    print(f"  • Уникальных IP в логах: {len(top_ips_df) if not top_ips_df.empty else 0}")
    
    print(f"\nРеагирование:")
    print(f"  • Заблокировано IP: {len(suspicious_ips)}")
    if suspicious_ips:
        print(f"  • Список: {', '.join(suspicious_ips[:5])}")
        if len(suspicious_ips) > 5:
            print(f"    и ещё {len(suspicious_ips) - 5}")
    
    print(f"\nСохранённые файлы:")
    for name, path in files.items():
        if path:
            print(f"  • {name}: {path}")
    
    print(f"\n📈 Графики:")
    for name, path in plots.items():
        if path:
            print(f"  • {name}: {path}")
    
    print("\n" + "="*60)
    print("✅ Анализ успешно завершён!")
    print("="*60)


def signal_handler(sig, frame):
    """
    Обработчик сигналов (Ctrl+C).
    
    Args:
        sig: Номер сигнала
        frame: Текущий стек вызовов
    """
    print("\n\n" + "="*60)
    print("⚠️  ПРОГРАММА ПРЕРВАНА ПОЛЬЗОВАТЕЛЕМ")
    print("="*60)
    print("\nДо свидания! 👋")
    sys.exit(130)


def main() -> int:
    """
    Главная функция программы.
    
    Returns:
        int: Код возврата (0 - успех, 1 - ошибка, 130 - прерывание)
    """
    # Устанавливаем обработчик сигналов
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Парсинг аргументов командной строки
        args = parse_arguments()
        
        # Проверяем, были ли переданы какие-либо аргументы
        has_args = any([
            args.log_file is not None,
            args.vuln_limit is not None,
            args.threshold is not None,
            args.block_threshold is not None,
            args.top_n is not None,
            args.no_block,
            args.skip_vulns,
            args.skip_logs,
            args.test_mode,
            args.verbose
        ])
        
        if has_args:
            # Если есть аргументы командной строки, создаём конфиг без интерактива
            from config import Config
            config = Config()
            
            # Применяем аргументы
            if args.log_file is not None:
                config.log_file = args.log_file
            if args.vuln_limit is not None:
                config.vuln_limit = args.vuln_limit
            if args.threshold is not None:
                config.cvss_threshold = args.threshold
            if args.block_threshold is not None:
                config.block_threshold = args.block_threshold
            if args.top_n is not None:
                config.top_n = args.top_n
            if args.no_block:
                config.block_threshold = -1
            if args.skip_vulns:
                config.skip_vulns = True
            if args.skip_logs:
                config.skip_logs = True
            if args.test_mode:
                config.test_mode = True
            
            print("\nИспользуются настройки из командной строки")
        else:
            # Если аргументов нет, запускаем интерактивную настройку
            print("\n" + "="*60)
            print("ИНИЦИАЛИЗАЦИЯ АНАЛИЗАТОРА УГРОЗ")
            print("="*60)
            print("(Для прерывания нажмите Ctrl+C в любой момент)\n")
            from config import get_user_config
            config = get_user_config()
        
        # Настройка логирования
        setup_logging(args.verbose or (hasattr(config, 'verbose') and config.verbose))
        
        # Загружаем переменные окружения
        load_dotenv()
        logger.info("Запуск анализатора угроз")
        
        # Валидация конфигурации
        if config.skip_vulns and config.skip_logs:
            raise ConfigurationError("Нельзя пропустить оба источника данных")
        
        # Сбор данных с использованием config
        vulns = []
        alerts = []
        
        if not config.skip_vulns:
            logger.info("Получение данных из API Vulners...")
            vulns = get_vulnerabilities(limit=config.vuln_limit, min_cvss=None)
            logger.info(f"Получено {len(vulns)} уязвимостей")
        
        if not config.skip_logs:
            logger.info(f"Чтение логов Suricata из {config.log_file}...")
            alerts = parse_suricata_logs(config.log_file)
            logger.info(f"Загружено {len(alerts)} alert-событий")
        
        # Анализ
        logger.info("Анализ данных...")
        critical_cves_df, top_ips_df, cvss_series = analyze_threats(
            vulns, alerts, config.cvss_threshold, config.top_n
        )
        
        # Реагирование
        suspicious_ips = []

        notify_critical_cves(critical_cves_df, threshold=config.cvss_threshold)

        if config.block_threshold >= 0:
            suspicious_ips = respond_to_threats(
                critical_cves_df, top_ips_df, config.block_threshold, False
            )
            
        else:
            # Только уведомление без блокировки
            notify_critical_cves(critical_cves_df)
        
        # EMAIL-УВЕДОМЛЕНИЕ (если есть угрозы и email включён)
        if config.email_enabled and (not critical_cves_df.empty or suspicious_ips):
            logger.info("Отправка email-уведомления...")
            send_alert(config, len(critical_cves_df), len(suspicious_ips))
        
        # Отчёты
        logger.info("Сохранение отчётов...")
        files = generate_reports(
            vulns, alerts, critical_cves_df, top_ips_df, suspicious_ips,
            config.skip_vulns, config.skip_logs
        )
        
        # Визуализация
        logger.info("Построение графиков...")
        plots = create_visualizations(top_ips_df, cvss_series)
        
        # Вывод сводки
        print_summary(vulns, alerts, critical_cves_df, top_ips_df, suspicious_ips, files, plots)
        
        logger.info("Анализ завершён успешно")
        return 0
        
    except ConfigurationError as e:
        logger.error(f"Ошибка конфигурации: {e}")
        print(f"\nОшибка конфигурации: {e}")
        print("Используйте --help для справки")
        return 1
        
    except DataCollectionError as e:
        logger.error(f"Ошибка сбора данных: {e}")
        print(f"\nНе удалось собрать данные: {e}")
        print("Проверьте:")
        print("  • Наличие файла .env с ключом API")
        print("  • Существование файла логов")
        print("  • Подключение к интернету")
        return 1
        
    except AnalysisError as e:
        logger.error(f"Ошибка анализа: {e}")
        print(f"\nОшибка при анализе данных: {e}")
        return 1
        
    except (ResponderError, ReportingError, VisualizationError) as e:
        logger.error(f"Ошибка обработки результатов: {e}")
        print(f"\nОшибка при обработке результатов: {e}")
        return 1
        
    except KeyboardInterrupt:
        logger.info("Программа прервана пользователем")
        print("\n\nПрограмма прервана пользователем")
        return 130
        
    except Exception as e:
        logger.exception(f"Непредвиденная ошибка: {e}")
        print(f"\nПроизошла непредвиденная ошибка: {e}")
        print("Проверьте логи в файле threat_analyzer.log")
        return 1


if __name__ == "__main__":
    sys.exit(main())