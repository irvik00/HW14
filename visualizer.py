"""
Модуль для визуализации результатов анализа угроз.
Предоставляет функции для построения графиков распределения CVSS-баллов
и топ IP-адресов с сохранением в файлы.
"""

import matplotlib.pyplot as plt
import pandas as pd
import logging
import os
import numpy as np
from typing import Optional, List, Tuple
from pathlib import Path
from datetime import datetime
import matplotlib

matplotlib.use('Agg')

logger = logging.getLogger(__name__)

# Константы
DEFAULT_REPORTS_DIR = "reports"
DEFAULT_FIGURE_SIZE = (14, 8)
DEFAULT_DPI = 120

# Цветовая палитра
COLORS = {
    'background': '#f8f9fa',
    'grid': '#dee2e6',
    'text': '#212529',
    'title': '#495057',
    'watermark': '#6c757d',
    'ip_bar_base': '#4dabf7',
    'ip_bar_high': '#ff6b6b',
    'risk_zones': {
        'critical': '#ff6b6b',
        'high': '#ffa8a8',
        'medium': '#ffd43b',
        'low': '#69db7e'
    },
    'risk_zones_alpha': {
        'critical': '#ff6b6b20',
        'high': '#ffa8a820',
        'medium': '#ffd43b20',
        'low': '#69db7e20'
    }
}


class VisualizationError(Exception):
    """Базовое исключение для ошибок визуализации."""
    pass


def ensure_reports_dir(reports_dir: str = DEFAULT_REPORTS_DIR) -> Path:
    """
    Создаёт папку для отчётов, если её нет.
    
    Args:
        reports_dir: Путь к директории для отчётов
    
    Returns:
        Path: Объект Path созданной директории
    """
    try:
        path = Path(reports_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path
    except Exception as e:
        raise VisualizationError(f"Не удалось создать директорию {reports_dir}: {e}")


def _add_watermark(fig: plt.Figure) -> None:
    """
    Добавляет водяной знак с информацией о генерации.
    
    Args:
        fig: Объект фигуры matplotlib
    """
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    watermark_text = f"Threat Analyzer · Итоговое задание · {current_time}"
    
    fig.text(
        0.02, 0.02, 
        watermark_text,
        fontsize=7,
        color=COLORS['watermark'],
        alpha=0.7,
        ha='left',
        va='bottom',
        transform=fig.transFigure
    )


def _add_risk_zones(ax: plt.Axes, x_max: float) -> None:
    """
    Добавляет цветные зоны риска на график CVSS.
    
    Args:
        ax: Объект осей matplotlib
        x_max: Максимальное значение по оси X
    """
    # Зоны риска 
    ax.axvspan(0, 4.0, alpha=0.2, color=COLORS['risk_zones_alpha']['low'], label='Низкий риск (0-3.9)')
    ax.axvspan(4.0, 7.0, alpha=0.2, color=COLORS['risk_zones_alpha']['medium'], label='Средний риск (4.0-6.9)')
    ax.axvspan(7.0, 9.0, alpha=0.2, color=COLORS['risk_zones_alpha']['high'], label='Высокий риск (7.0-8.9)')
    ax.axvspan(9.0, 10.0, alpha=0.2, color=COLORS['risk_zones_alpha']['critical'], label='Критический риск (9.0-10.0)')
    
    # Вертикальные линии-разделители
    ax.axvline(x=4.0, color=COLORS['grid'], linestyle='-', linewidth=0.5, alpha=0.5)
    ax.axvline(x=7.0, color=COLORS['grid'], linestyle='-', linewidth=0.5, alpha=0.5)
    ax.axvline(x=9.0, color=COLORS['grid'], linestyle='-', linewidth=0.5, alpha=0.5)


def _setup_axes(ax: plt.Axes, xlim: Tuple[float, float] = (0, 10)) -> None:
    """
    Настраивает оси графика для правильного отображения.
    
    Args:
        ax: Объект осей matplotlib
        xlim: Границы по оси X
    """
    # Устанавливаем границы осей
    ax.set_xlim(xlim)
    ax.set_ylim(bottom=0)
    
    # Настраиваем деления
    ax.xaxis.set_major_locator(plt.MultipleLocator(1.0))
    ax.xaxis.set_minor_locator(plt.MultipleLocator(0.5))
    
    # Убираем лишние границы
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color(COLORS['grid'])
    ax.spines['bottom'].set_color(COLORS['grid'])
    ax.spines['left'].set_position(('outward', 10))
    ax.spines['bottom'].set_position(('outward', 10))


def plot_top_ips(
    ip_df: pd.DataFrame,
    filename: str = "threat_analysis.png",
    reports_dir: str = DEFAULT_REPORTS_DIR,
    figsize: Tuple[int, int] = (12, 8),
    top_n: int = 5,
    title: Optional[str] = None
) -> str:
    """
    Строит горизонтальную столбчатую диаграмму топ IP-адресов.
    
    Args:
        ip_df: DataFrame с колонками 'src_ip' и 'count'
        filename: Имя файла для сохранения
        reports_dir: Директория для сохранения
        figsize: Размер фигуры (ширина, высота)
        title: Заголовок графика
        top_n: Количество IP для отображения (по умолчанию 5)
    
    Returns:
        str: Полный путь к сохранённому файлу
    """
    reports_path = ensure_reports_dir(reports_dir)
    filepath = reports_path / filename

    if ip_df.empty:
        return _create_empty_plot(filepath, "Нет данных по IP", figsize)

    # Подготовка данных
    plot_df = ip_df.sort_values('count', ascending=True).tail(top_n).copy()
    max_count = plot_df['count'].max()
    
    # Расчёт цвета на основе активности (градиент)
    colors = []
    for count in plot_df['count']:
        intensity = count / max_count if max_count > 0 else 0
        # Интерполяция между базовым и высоким цветом
        r = (1 - intensity) * int(COLORS['ip_bar_base'][1:3], 16) + intensity * int(COLORS['ip_bar_high'][1:3], 16)
        g = (1 - intensity) * int(COLORS['ip_bar_base'][3:5], 16) + intensity * int(COLORS['ip_bar_high'][3:5], 16)
        b = (1 - intensity) * int(COLORS['ip_bar_base'][5:7], 16) + intensity * int(COLORS['ip_bar_high'][5:7], 16)
        colors.append(f'#{int(r):02x}{int(g):02x}{int(b):02x}')
    
    # Создание графика
    fig, ax = plt.subplots(figsize=figsize, facecolor=COLORS['background'])
    ax.set_facecolor(COLORS['background'])
    
    # Горизонтальные столбцы
    bars = ax.barh(plot_df['src_ip'], plot_df['count'], color=colors, alpha=0.9,
                   edgecolor='white', linewidth=1.5, height=0.7)
    
    # Значения на столбцах
    for bar, count in zip(bars, plot_df['count']):
        ax.text(
            count + (max_count * 0.02 if max_count > 0 else 0.1),
            bar.get_y() + bar.get_height() / 2,
            f'{int(count)}',
            va='center',
            ha='left',
            fontsize=10,
            color=COLORS['text']
        )
    
    # Настройка осей
    ax.set_xlabel('Количество событий', fontsize=11, color=COLORS['title'])
    ax.set_ylabel('IP-адрес', fontsize=11, color=COLORS['title'])
    
    if title is None:
        title = f'Топ {len(plot_df)} IP-адресов по количеству срабатываний'
    ax.set_title(title, fontsize=14, color=COLORS['text'], pad=15)
    
    # Сетка
    ax.grid(axis='x', alpha=0.2, linestyle='--', color=COLORS['grid'])
    ax.set_axisbelow(True)
    
    # Настройка осей
    _setup_axes(ax, xlim=(0, max_count * 1.1))
    
    # Водяной знак
    _add_watermark(fig)
    
    plt.tight_layout()
    plt.savefig(filepath, dpi=DEFAULT_DPI, bbox_inches='tight', facecolor=COLORS['background'])
    plt.close()
    
    logger.info(f"Сохранён график топ IP: {filepath}")
    return str(filepath)


def plot_cvss_distribution(
    cvss_series: pd.Series,
    filename: str = "cvss_distribution.png",
    reports_dir: str = DEFAULT_REPORTS_DIR,
    figsize: Tuple[int, int] = (14, 8),
    bins: int = 20,
    title: Optional[str] = None,
    show_stats: bool = True
) -> str:
    """
    Строит гистограмму распределения CVSS-баллов с зонами риска.
    
    Args:
        cvss_series: Series с CVSS-баллами
        filename: Имя файла для сохранения
        reports_dir: Директория для сохранения
        figsize: Размер фигуры (ширина, высота)
        bins: Количество корзин гистограммы
        title: Заголовок графика
        show_stats: Показывать ли статистику на графике
    
    Returns:
        str: Полный путь к сохранённому файлу
    """
    reports_path = ensure_reports_dir(reports_dir)
    filepath = reports_path / filename

    if cvss_series.empty:
        return _create_empty_plot(filepath, "Нет данных по CVSS", figsize)

    # Очищаем данные
    clean_series = cvss_series.dropna()
    if clean_series.empty:
        return _create_empty_plot(filepath, "Нет валидных данных по CVSS", figsize)
    
    # Создание графика
    fig, ax = plt.subplots(figsize=figsize, facecolor=COLORS['background'])
    ax.set_facecolor(COLORS['background'])
    
    # Сначала строим гистограмму без отображения, чтобы узнать максимальное значение
    hist_counts, bin_edges = np.histogram(clean_series, bins=np.arange(0, 10.1, 0.5))
    max_count = hist_counts.max()
    
    # Настройка осей с динамическим верхним пределом
    y_max = max_count + 2  
    ax.set_ylim(0, y_max)
    
    # Настраиваем деления по Y с шагом, зависящим от максимального значения
    if y_max <= 10:
        y_step = 1
    elif y_max <= 20:
        y_step = 2
    elif y_max <= 50:
        y_step = 5
    else:
        y_step = 10
    
    ax.yaxis.set_major_locator(plt.MultipleLocator(y_step))
    ax.yaxis.set_minor_locator(plt.MultipleLocator(y_step / 2))

    # Настройка осей X
    _setup_axes(ax)
    
    # Добавляем цветные зоны риска
    _add_risk_zones(ax, 10)
    
    # Строим гистограмму
    n, bins, patches = ax.hist(
        clean_series,
        bins=np.arange(0, 10.1, 0.5),
        edgecolor='white',
        linewidth=1,
        alpha=0.8,
        color=COLORS['risk_zones']['critical'],
        zorder=3,
        align='mid'
    )
    
    # Окрашиваем столбцы в соответствии с зонами риска
    for patch, bin_edge in zip(patches, bins[:-1]):
        if bin_edge < 4.0:
            patch.set_facecolor(COLORS['risk_zones']['low'])
        elif bin_edge < 7.0:
            patch.set_facecolor(COLORS['risk_zones']['medium'])
        elif bin_edge < 9.0:
            patch.set_facecolor(COLORS['risk_zones']['high'])
        else:
            patch.set_facecolor(COLORS['risk_zones']['critical'])
    
    # Добавляем значения над столбцами (опционально)
    for i, (count, bin_edge) in enumerate(zip(n, bins[:-1])):
        if count > 0:
            ax.text(
                bin_edge + 0.25,
                count + 0.1,
                str(int(count)),
                ha='center',
                va='bottom',
                fontsize=8,
                color=COLORS['text'],
                alpha=0.7
            )
    
    # Статистика
    if show_stats:
        stats_text = (
            f"Статистика:\n"
            f"Среднее: {clean_series.mean():.2f}\n"
            f"Медиана: {clean_series.median():.2f}\n"
            f"Мин: {clean_series.min():.1f}\n"
            f"Макс: {clean_series.max():.1f}\n"
            f"Всего: {len(clean_series)}"
        )
        
        props = dict(boxstyle='round', facecolor='white', alpha=0.9, edgecolor=COLORS['grid'])
        ax.text(
            0.97, 0.97, stats_text,
            transform=ax.transAxes,
            verticalalignment='top',
            horizontalalignment='right',
            bbox=props,
            fontsize=9,
            fontfamily='monospace',
            color=COLORS['text']
        )
    
    # Настройка осей
    ax.set_xlabel('CVSS балл', fontsize=11, color=COLORS['title'])
    ax.set_ylabel('Количество уязвимостей', fontsize=11, color=COLORS['title'])
    
    if title is None:
        title = 'Распределение уязвимостей по CVSS баллам'
    ax.set_title(title, fontsize=14, color=COLORS['text'], pad=15)
    
    # Сетка
    ax.grid(axis='y', alpha=0.2, linestyle='--', color=COLORS['grid'], zorder=1)
    ax.set_axisbelow(True)

    # Убираем лишние границы
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color(COLORS['grid'])
    ax.spines['bottom'].set_color(COLORS['grid'])
    
    # Легенда для зон риска
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=COLORS['risk_zones']['low'], alpha=0.3, label='Низкий риск (0-3.9)'),
        Patch(facecolor=COLORS['risk_zones']['medium'], alpha=0.3, label='Средний риск (4.0-6.9)'),
        Patch(facecolor=COLORS['risk_zones']['high'], alpha=0.3, label='Высокий риск (7.0-8.9)'),
        Patch(facecolor=COLORS['risk_zones']['critical'], alpha=0.3, label='Критический риск (9.0-10.0)')
    ]
    ax.legend(handles=legend_elements, loc='upper left', framealpha=0.9, fontsize=8)
    
    # Водяной знак
    _add_watermark(fig)
    
    plt.tight_layout()
    plt.savefig(filepath, dpi=DEFAULT_DPI, bbox_inches='tight', facecolor=COLORS['background'])
    plt.close()
    
    logger.info(f"Сохранён график распределения CVSS: {filepath}")
    return str(filepath)


def _create_empty_plot(
    filepath: Path,
    message: str,
    figsize: Tuple[int, int]
) -> str:
    """
    Создаёт пустой график с информационным сообщением.
    
    Args:
        filepath: Путь для сохранения
        message: Сообщение для отображения
        figsize: Размер фигуры
    
    Returns:
        str: Путь к сохранённому файлу
    """
    fig, ax = plt.subplots(figsize=figsize, facecolor=COLORS['background'])
    ax.set_facecolor(COLORS['background'])
    
    ax.text(0.5, 0.5, message,
            ha='center', va='center', fontsize=14, color=COLORS['text'],
            transform=ax.transAxes)
    
    ax.axis('off')
    
    _add_watermark(fig)
    
    plt.tight_layout()
    plt.savefig(filepath, dpi=DEFAULT_DPI, bbox_inches='tight', facecolor=COLORS['background'])
    plt.close()
    
    return str(filepath)


if __name__ == "__main__":
    # Тестирование
    logging.basicConfig(level=logging.INFO)
    
    print("Тестирование модуля визуализации")
    print("-" * 50)
    
    # Тестовые данные
    test_ips = pd.DataFrame({
        'src_ip': ['192.168.1.10', '192.168.1.20', '192.168.1.30',
                   '192.168.1.40', '192.168.1.50', '10.0.0.1', '172.16.0.5'],
        'count': [45, 32, 28, 15, 12, 8, 3]
    })
    
    test_cvss = pd.Series([9.8, 9.2, 8.5, 8.1, 7.8, 7.2, 6.8, 6.5, 5.9, 5.2,
                           4.8, 4.1, 3.5, 2.8, 2.1, 1.5, 0.8, 9.5, 8.9, 7.5])
    
    print("\n1. Построение графика IP:")
    ip_path = plot_top_ips(test_ips, "test_ips.png")
    print(f"   Сохранено: {ip_path}")
    
    print("\n2. Построение гистограммы CVSS:")
    cvss_path = plot_cvss_distribution(test_cvss, "test_cvss.png")
    print(f"   Сохранено: {cvss_path}")
      

    print("\nВсе графики созданы")
