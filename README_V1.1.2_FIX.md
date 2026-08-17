# JPCars v1.1.2 — Telegram Webhook Fix

Исправлена причина, по которой Telegram-бот не реагировал на Start.

## Причина
Общая browser CSRF-защита блокировала POST-запросы Telegram на `/telegram/webhook`,
потому что Telegram Bot API не является браузером и не присылает Origin/Referer.

## Исправление
- `/telegram/webhook` исключён только из browser CSRF middleware;
- webhook по-прежнему защищён `TELEGRAM_WEBHOOK_SECRET`;
- в Railway Deploy Logs теперь появляется `Telegram webhook received` при получении update.

## После обновления
1. Загрузить v1.1.2 в GitHub.
2. Дождаться успешного Railway deploy.
3. В админке открыть Telegram и снова нажать «Установить webhook».
4. В клиентском кабинете нажать «Подключить Telegram».
5. Нажать Start в Telegram.
6. Бот должен подтвердить подключение.
