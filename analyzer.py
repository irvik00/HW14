import pandas as pd
import logging
from typing import List, Dict, Any, Optional, Tuple
import numpy as np

logger = logging.getLogger(__name__)

# Константы для удобства
DEFAULT_CVSS_THRESHOLD = 7.0
DEFAULT_TOP_IPS_COUNT = 5

class DataValidationError(Exception):
    """Исключение при проблемах с валидацией данных"""
    pass

def find_critical_cves(vulns_list: List[Dict[str, Any]], threshold: float = DEFAULT_CVSS_THRESHOLD) -> pd.DataFrame:
    """
    Фильтрует список уязвимостей по CVSS >= threshold.
    
    Функция не только фильтрует, но и проверяет данные на корректность,
    а также добавляет колонку с категорией критичности.
    
    Args:
        vulns_list: Список словарей с уязвимостями (cve_id, cvss, description)
        threshold: Пороговое значение CVSS для критичности (по умолчанию 7.0)
    
    Returns:
        DataFrame с колонками: cve_id, cvss, description, severity_category
        
    Examples:
        >>> vulns = [{'cve_id': 'CVE-2023-1234', 'cvss': 8.5, 'description': '...'}]
        >>> critical = find_critical_cves(vulns, threshold=7.0)
        >>> print(critical.shape[0])  # количество критических
    """
    # Проверка входных данных
    if not isinstance(vulns_list, list):
        logger.error(f"Ожидался список, получен {type(vulns_list)}")
        return pd.DataFrame(columns=['cve_id', 'cvss', 'description', 'severity_category'])
    
    if not vulns_list:
        logger.info("Список уязвимостей пуст, возвращается пустой DataFrame")
        return pd.DataFrame(columns=['cve_id', 'cvss', 'description', 'severity_category'])

    try:
        df = pd.DataFrame(vulns_list)
        
        # Проверяем наличие необходимых колонок
        required_columns = ['cve_id', 'cvss']
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            logger.warning(f"Отсутствуют колонки: {missing_cols}. Заполняем пропуски...")
            for col in missing_cols:
                df[col] = None
        
        # Приводим cvss к числовому типу, некорректные значения становятся NaN
        df['cvss'] = pd.to_numeric(df['cvss'], errors='coerce')
        
        # Добавляем колонку с описанием, если её нет
        if 'description' not in df.columns:
            df['description'] = ''
        
        # Считаем статистику до фильтрации
        total_with_cvss = df['cvss'].notna().sum()
        if total_with_cvss == 0:
            logger.warning("Нет записей с валидным CVSS баллом")
            return pd.DataFrame(columns=['cve_id', 'cvss', 'description', 'severity_category'])
        
        # Удаляем строки с некорректным cvss
        df_clean = df.dropna(subset=['cvss']).copy()
        
        # Добавляем категорию критичности (полезно для отчётов)
        def get_severity_category(score):
            if score >= 9.0:
                return 'Критическая'
            elif score >= 7.0:
                return 'Высокая'
            elif score >= 4.0:
                return 'Средняя'
            elif score >= 0.1:
                return 'Низкая'
            else:
                return 'Не определена'
        
        df_clean['severity_category'] = df_clean['cvss'].apply(get_severity_category)
        
        # Фильтруем по порогу
        critical_df = df_clean[df_clean['cvss'] >= threshold].copy()
        
        # Сортируем по убыванию cvss
        critical_df = critical_df.sort_values('cvss', ascending=False)
        
        # Логируем подробную статистику
        logger.info(f"Всего уязвимостей с CVSS: {total_with_cvss}")
        logger.info(f"Найдено {len(critical_df)} критических (CVSS >= {threshold})")
        
        if len(critical_df) > 0:
            logger.info(f"Максимальный CVSS: {critical_df['cvss'].max()}, "
                       f"средний CVSS: {critical_df['cvss'].mean():.2f}")
        
        return critical_df[['cve_id', 'cvss', 'description', 'severity_category']]
        
    except Exception as e:
        logger.error(f"Неожиданная ошибка при анализе уязвимостей: {e}")
        return pd.DataFrame(columns=['cve_id', 'cvss', 'description', 'severity_category'])


def get_top_ips(alerts_list: List[Dict[str, Any]], top_n: int = DEFAULT_TOP_IPS_COUNT) -> pd.DataFrame:
    """
    Анализирует alert-события и возвращает топ IP-адресов по активности.
    
    Группирует события по src_ip, подсчитывает количество и среднюю серьёзность.
    Добавляет дополнительную статистику для каждого IP.
    
    Args:
        alerts_list: Список словарей с alert-событиями (src_ip, alert_severity, ...)
        top_n: Количество IP в топе (по умолчанию 5)
    
    Returns:
        DataFrame с колонками: src_ip, count, avg_severity, max_severity, risk_score
        
    Examples:
        >>> alerts = [{'src_ip': '192.168.1.10', 'alert_severity': 1}]
        >>> top_ips = get_top_ips(alerts, top_n=10)
    """
    # Проверка входных данных
    if not isinstance(alerts_list, list):
        logger.error(f"Ожидался список, получен {type(alerts_list)}")
        return pd.DataFrame(columns=['src_ip', 'count', 'avg_severity', 'max_severity', 'risk_score'])
    
    if not alerts_list:
        logger.info("Список alert-событий пуст, возвращается пустой DataFrame")
        return pd.DataFrame(columns=['src_ip', 'count', 'avg_severity', 'max_severity', 'risk_score'])

    try:
        df = pd.DataFrame(alerts_list)
        
        # Проверяем наличие обязательных колонок
        required_columns = ['src_ip', 'alert_severity']
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            logger.error(f"В данных отсутствуют обязательные колонки: {missing_cols}")
            return pd.DataFrame(columns=['src_ip', 'count', 'avg_severity', 'max_severity', 'risk_score'])
        
        # Проверяем, что src_ip не пустые
        empty_ips = df['src_ip'].isna().sum()
        if empty_ips > 0:
            logger.warning(f"Найдено {empty_ips} записей с пустым src_ip, они будут пропущены")
            df = df.dropna(subset=['src_ip'])
        
        # Убираем пустые строки
        df = df[df['src_ip'] != '']
        
        if df.empty:
            logger.warning("После удаления пустых IP нет данных для анализа")
            return pd.DataFrame(columns=['src_ip', 'count', 'avg_severity', 'max_severity', 'risk_score'])
        
        # Приводим severity к числовому типу
        df['alert_severity'] = pd.to_numeric(df['alert_severity'], errors='coerce')
        
        # Убираем строки с некорректной severity
        df = df.dropna(subset=['alert_severity'])
        
        if df.empty:
            logger.warning("Нет данных с корректной alert_severity")
            return pd.DataFrame(columns=['src_ip', 'count', 'avg_severity', 'max_severity', 'risk_score'])
        
        # Базовая группировка по IP (без alert_signature, так как её может не быть)
        grouped = df.groupby('src_ip').agg(
            count=('src_ip', 'size'),
            avg_severity=('alert_severity', 'mean'),
            max_severity=('alert_severity', 'max')
        ).reset_index()
        
        # Добавляем скоринговый балл
        max_count = grouped['count'].max()
        if max_count > 0:
            grouped['risk_score'] = (
                (grouped['count'] / max_count) * 0.6 +
                (grouped['avg_severity'] / 3) * 0.4
            ) * 100
        else:
            grouped['risk_score'] = 0
        
        # Сортируем по риску
        grouped = grouped.sort_values('risk_score', ascending=False)
        
        # Берём топ-N
        top_df = grouped.head(top_n).copy()
        
        # Форматируем числа
        top_df['avg_severity'] = top_df['avg_severity'].round(2)
        top_df['risk_score'] = top_df['risk_score'].round(1)
        
        logger.info(f"Всего уникальных IP: {len(grouped)}")
        if not top_df.empty:
            logger.info(f"Топ-{top_n} IP-адресов: {top_df['src_ip'].tolist()}")
        
        return top_df[['src_ip', 'count', 'avg_severity', 'max_severity', 'risk_score']]
        
    except Exception as e:
        logger.error(f"Неожиданная ошибка при анализе IP: {e}")
        return pd.DataFrame(columns=['src_ip', 'count', 'avg_severity', 'max_severity', 'risk_score'])


def cvss_distribution(vulns_list: List[Dict[str, Any]]) -> pd.Series:
    """
    Возвращает распределение CVSS-баллов для статистического анализа.
    
    Args:
        vulns_list: Список словарей с уязвимостями
    
    Returns:
        Series с CVSS баллами для построения гистограммы
        
    Examples:
        >>> cvss_series = cvss_distribution(vulns)
        >>> print(f"Средний CVSS: {cvss_series.mean():.2f}")
        >>> print(f"Медианный CVSS: {cvss_series.median():.2f}")
    """
    if not isinstance(vulns_list, list):
        logger.error(f"Ожидался список, получен {type(vulns_list)}")
        return pd.Series(dtype=float)
    
    if not vulns_list:
        logger.info("Список уязвимостей пуст, возвращается пустая Series")
        return pd.Series(dtype=float)

    try:
        df = pd.DataFrame(vulns_list)
        
        if 'cvss' not in df.columns:
            logger.error("В данных отсутствует колонка cvss")
            return pd.Series(dtype=float)
        
        # Приводим к числовому типу и удаляем NaN
        cvss_series = pd.to_numeric(df['cvss'], errors='coerce').dropna()
        
        if len(cvss_series) == 0:
            logger.warning("Нет валидных CVSS баллов")
            return pd.Series(dtype=float)
        
        # Добавляем базовую статистику в лог
        logger.info(f"CVSS статистика: всего={len(cvss_series)}, "
                   f"среднее={cvss_series.mean():.2f}, "
                   f"медиана={cvss_series.median():.2f}, "
                   f"мин={cvss_series.min():.1f}, "
                   f"макс={cvss_series.max():.1f}")
        
        return cvss_series
        
    except Exception as e:
        logger.error(f"Ошибка при анализе распределения CVSS: {e}")
        return pd.Series(dtype=float)


def get_cvss_summary_stats(vulns_list: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Возвращает сводную статистику по CVSS баллам.
    
    Args:
        vulns_list: Список словарей с уязвимостями
    
    Returns:
        Словарь со статистикой: mean, median, min, max, q25, q75
        
    Examples:
        >>> stats = get_cvss_summary_stats(vulns)
        >>> print(f"25% перцентиль: {stats['q25']}")
    """
    cvss_series = cvss_distribution(vulns_list)
    
    if cvss_series.empty:
        return {
            'mean': 0.0,
            'median': 0.0,
            'min': 0.0,
            'max': 0.0,
            'q25': 0.0,
            'q75': 0.0,
            'count': 0
        }
    
    return {
        'mean': round(cvss_series.mean(), 2),
        'median': round(cvss_series.median(), 2),
        'min': round(cvss_series.min(), 1),
        'max': round(cvss_series.max(), 1),
        'q25': round(cvss_series.quantile(0.25), 2),
        'q75': round(cvss_series.quantile(0.75), 2),
        'count': len(cvss_series)
    }


def analyze_threat_correlation(vulns_df: pd.DataFrame, ips_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Анализирует корреляцию между уязвимостями и активностью IP.
    
    Args:
        vulns_df: DataFrame с критическими уязвимостями
        ips_df: DataFrame с топ IP
    
    Returns:
        Словарь с корреляционными метриками
    """
    correlation_data = {
        'has_critical_vulns': not vulns_df.empty if vulns_df is not None else False,
        'has_suspicious_ips': not ips_df.empty if ips_df is not None else False,
        'total_critical_vulns': len(vulns_df) if vulns_df is not None else 0,
        'total_suspicious_ips': len(ips_df) if ips_df is not None else 0,
        'threat_level': 'Низкий'
    }
    
    # Определяем общий уровень угрозы
    if correlation_data['total_critical_vulns'] > 10 and correlation_data['total_suspicious_ips'] > 5:
        correlation_data['threat_level'] = 'Критический'
    elif correlation_data['total_critical_vulns'] > 5 or correlation_data['total_suspicious_ips'] > 3:
        correlation_data['threat_level'] = 'Высокий'
    elif correlation_data['total_critical_vulns'] > 0 or correlation_data['total_suspicious_ips'] > 0:
        correlation_data['threat_level'] = 'Средний'
    
    return correlation_data


if __name__ == "__main__":
    # Простой тест при запуске файла
    logging.basicConfig(level=logging.INFO)
    
    # Тестовые данные
    test_vulns = [
        {'cve_id': 'CVE-2023-001', 'cvss': 9.8, 'description': 'Critical RCE'},
        {'cve_id': 'CVE-2023-002', 'cvss': 7.5, 'description': 'High XSS'},
        {'cve_id': 'CVE-2023-003', 'cvss': 5.5, 'description': 'Medium info leak'},
        {'cve_id': 'CVE-2023-004', 'cvss': 2.1, 'description': 'Low impact'},
    ]
    
    test_alerts = [
        {'src_ip': '192.168.1.10', 'alert_severity': 1, 'alert_signature': 'Malware'},
        {'src_ip': '192.168.1.10', 'alert_severity': 1, 'alert_signature': 'Malware'},
        {'src_ip': '192.168.1.20', 'alert_severity': 2, 'alert_signature': 'Scan'},
        {'src_ip': '192.168.1.10', 'alert_severity': 1, 'alert_signature': 'C2'},
        {'src_ip': '192.168.1.30', 'alert_severity': 3, 'alert_signature': 'Policy'},
    ]
    
    print("Тестирование анализатора...")
    
    critical = find_critical_cves(test_vulns, threshold=7.0)
    print(f"\nКритические CVE (CVSS >= 7.0): {len(critical)}")
    print(critical[['cve_id', 'cvss', 'severity_category']] if not critical.empty else "Нет данных")
    
    top_ips = get_top_ips(test_alerts, top_n=3)
    print(f"\nТоп IP:")
    print(top_ips if not top_ips.empty else "Нет данных")
    
    stats = get_cvss_summary_stats(test_vulns)
    print(f"\nСтатистика CVSS: {stats}")