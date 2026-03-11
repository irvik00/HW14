"""
Модуль для отправки email-уведомлений о критических угрозах.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def send_alert(config, critical_cves_count: int, suspicious_ips_count: int) -> bool:
    """
    Отправляет email-уведомление об угрозах, используя объект config.
    
    Args:
        config: Объект с настройками (из config.py)
        critical_cves_count: Количество критических CVE
        suspicious_ips_count: Количество подозрительных IP
    
    Returns:
        bool: True если отправка успешна, иначе False
    """
    # Проверяем, включены ли email-уведомления
    if not config.email_enabled:
        logger.info("Email-уведомления отключены")
        return False
    
    # Проверяем, есть ли все необходимые данные
    if not all([config.sender_email, config.recipient_email, config.sender_password]):
        logger.error("Не все данные для email указаны в конфигурации")
        print("\n❌ Не все данные для email указаны в конфигурации")
        print("   Проверьте настройки в .env или при следующем запуске")
        return False
    
    # Проверяем, есть ли угрозы
    if critical_cves_count == 0 and suspicious_ips_count == 0:
        logger.info("Нет угроз для отправки email")
        return False
    
    # Формируем сообщение
    subject = f"🚨 ALERT: Обнаружены угрозы! ({critical_cves_count} CVE, {suspicious_ips_count} IP)"
    
    message = f"""
КРИТИЧЕСКИЕ УГРОЗЫ ОБНАРУЖЕНЫ!

📊 Статистика:
- Критических CVE: {critical_cves_count}
- Подозрительных IP: {suspicious_ips_count}

🕐 Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📁 Отчёты сохранены в папке reports/

--
Автоматическое уведомление от Threat Analyzer
    """
    
    try:
        # Создаём сообщение
        msg = MIMEMultipart()
        msg['From'] = config.sender_email
        msg['To'] = config.recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain', 'utf-8'))
        
        # Отправляем
        logger.info(f"Подключение к SMTP серверу {config.smtp_server}:{config.smtp_port}")
        server = smtplib.SMTP(config.smtp_server, config.smtp_port)
        server.starttls()
        server.login(config.sender_email, config.sender_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email-уведомление отправлено на {config.recipient_email}")
        print(f"\n✅ Email-уведомление отправлено на {config.recipient_email}")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка отправки email: {e}")
        print(f"\n❌ Ошибка отправки email: {e}")
        print("   Проверьте:")
        print("   • Правильность email и пароля")
        print("   • Для Gmail нужен пароль приложения, не обычный пароль")
        print("   • Настройки SMTP сервера")
        return False
