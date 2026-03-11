import os
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import List, Dict, Optional, Union

logger = logging.getLogger(__name__)


class VulnersAPIError(Exception):
    """Базовое исключение для ошибок Vulners API"""
    pass

class VulnersAuthError(VulnersAPIError):
    """Ошибка аутентификации (неверный ключ)"""
    pass

class VulnersRateLimitError(VulnersAPIError):
    """Превышен лимит запросов к API"""
    pass

class VulnersServerError(VulnersAPIError):
    """Ошибка на стороне сервера Vulners"""
    pass

def get_vulnerabilities(limit: int = 50, min_cvss: Optional[float] = None) -> List[Dict[str, Union[str, float]]]:
    """
    Получает список уязвимостей из Vulners API.
    
    Если API ключ не найден или запрос не удался, возвращает пустой список,
    но при этом логирует ошибку. В некоторых случаях может бросить исключение
    (если проблема явно требует внимания пользователя).
    
    Args:
        limit: Максимальное количество результатов (по умолчанию 50)
        min_cvss: Минимальный балл CVSS для фильтрации. Если None - не фильтруем
    
    Returns:
        List[Dict]: Список словарей с ключами 'cve_id', 'cvss', 'description'
        
    Пример:
        >>> vulns = get_vulnerabilities(limit=10, min_cvss=7.0)
        >>> for v in vulns:
        ...     print(f"{v['cve_id']}: {v['cvss']}")
    """
    # Проверяем наличие ключа API
    api_key = os.getenv('VULNERS_API_KEY')
    if not api_key:
        logger.error("VULNERS_API_KEY не найден в переменных окружения. Проверьте .env файл")
        return []

    url = "https://vulners.com/api/v3/search/lucene/"
    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': api_key
    }

    # Vulners ищет по запросу, type:cve означает только уязвимости
    # Сортируем по дате публикации, чтобы видеть свежие
    payload = {
        "query": "type:cve",
        "size": limit,
        "sort": "published"
    }

    # Настройка повторных попыток на случай временных сбоев
    session = requests.Session()
    retry = Retry(
        total=3,  # максимум 3 попытки
        backoff_factor=1,  # пауза между попытками: 1, 2, 4 секунды
        status_forcelist=[429, 500, 502, 503, 504],  # коды для повторных попыток
        allowed_methods=["POST"]  # POST тоже можно повторять
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)

    try:
        logger.debug(f"Отправляем запрос к Vulners API с limit={limit}")
        response = session.post(url, json=payload, headers=headers, timeout=10)
        
        # Отдельно обрабатываем частые ошибки
        if response.status_code == 401:
            raise VulnersAuthError("Неверный API ключ или ключ неактивен")
        elif response.status_code == 429:
            raise VulnersRateLimitError("Превышен лимит запросов к API")
        elif response.status_code >= 500:
            raise VulnersServerError(f"Сервер Vulners вернул ошибку {response.status_code}")
        
        response.raise_for_status()  # Для остальных кодов ошибок
        data = response.json()
        
    except requests.exceptions.Timeout:
        logger.error("Таймаут при запросе к Vulners API (сервер не отвечает 10 секунд)")
        return []
    except requests.exceptions.ConnectionError:
        logger.error("Ошибка соединения с Vulners API (проверьте интернет)")
        return []
    except VulnersAuthError as e:
        logger.error(f"Ошибка аутентификации: {e}")
        return []
    except VulnersRateLimitError as e:
        logger.error(f"Лимит запросов: {e}. Попробуйте позже или уменьшите limit")
        return []
    except requests.exceptions.RequestException as e:
        logger.error(f"Неожиданная ошибка при запросе: {e}")
        return []

    # Проверяем, что API вернул успешный статус
    if data.get('result') != 'OK':
        error_msg = data.get('error', 'Неизвестная ошибка API')
        logger.error(f"Vulners API вернул ошибку: {error_msg}")
        return []

    # Извлекаем результаты поиска
    results = data.get('data', {}).get('search', [])
    if not results:
        logger.info("Vulners API не вернул ни одной уязвимости")
        return []

    vulnerabilities = []
    skipped = 0

    for idx, item in enumerate(results, 1):
        try:
            source = item.get('_source', {})
            cve_id = source.get('id')
            cvss = source.get('cvss', {}).get('score')
            description = source.get('description', '')
            
            # Пропускаем записи без CVE ID или CVSS - это неполные данные
            if not cve_id:
                logger.debug(f"Запись {idx} пропущена: нет CVE ID")
                skipped += 1
                continue
                
            if cvss is None:
                logger.debug(f"Запись {cve_id} пропущена: нет CVSS балла")
                skipped += 1
                continue
            
            # Фильтр по минимальному CVSS, если задан
            if min_cvss is not None and cvss < min_cvss:
                logger.debug(f"Запись {cve_id} пропущена: CVSS {cvss} < {min_cvss}")
                skipped += 1
                continue
            
            # Обрезаем описание, но сохраняем полезную нагрузку
            short_desc = description[:200] + ('...' if len(description) > 200 else '')
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'cvss': float(cvss),
                'description': short_desc
            })
            
        except (ValueError, TypeError) as e:
            logger.warning(f"Ошибка при обработке записи {idx}: {e}")
            skipped += 1
            continue

    logger.info(f"Получено {len(vulnerabilities)} уязвимостей, пропущено {skipped}")
    
    # Сортируем по CVSS от высоких к низким
    vulnerabilities.sort(key=lambda x: x['cvss'], reverse=True)
    
    return vulnerabilities


if __name__ == "__main__":
    # Тестовый запуск
    from dotenv import load_dotenv
    load_dotenv()
    
    # Настраиваем логирование для консоли
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Тестируем получение уязвимостей...")
    vulns = get_vulnerabilities(limit=5, min_cvss=7.0)
    
    if vulns:
        print(f"\nНайдено {len(vulns)} критических уязвимостей (CVSS >= 7.0):")
        for v in vulns:
            print(f"  • {v['cve_id']}: CVSS {v['cvss']}")
            if v['description']:
                print(f"    {v['description'][:100]}...")
    else:
        print("\nУязвимости не найдены или произошла ошибка. Проверьте:")
        print("  - Файл .env с ключом API")
        print("  - Интернет-соединение")

        print("  - Логи выше для деталей")
