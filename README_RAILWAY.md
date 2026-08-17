# JPCars Cabinet v0.9 Cloud Security

Версия подготовлена для тестового размещения на Railway.

## Что изменено

- приложение слушает Railway-порт и все интерфейсы;
- добавлен `/healthz`;
- база и загрузки можно вынести на persistent volume;
- production требует `ADMIN_PASSWORD` и `SESSION_SECRET`;
- secure-cookie включается через `NODE_ENV=production`;
- добавлен `trust proxy` для HTTPS за Railway proxy;
- ограничены типы и размер загружаемых файлов;
- сохранена вся функциональность v0.8.

## Railway: рекомендуемые настройки

### 1. Persistent Volume
Добавьте один Volume и смонтируйте:

`/data`

### 2. Variables

Добавьте:

`NODE_ENV=production`

`DATA_DIR=/data`

`ADMIN_PASSWORD=<сложный пароль минимум 12 символов>`

`SESSION_SECRET=<случайная строка минимум 32 символа>`

`PORT` вручную задавать не нужно: Railway передаёт его приложению.

### 3. Healthcheck
Путь:

`/healthz`

В проекте также есть `railway.toml`.

### 4. Public Networking
После успешного deploy создайте Railway Domain. После этого появится HTTPS-адрес.

## Важно про Volume

На `/data` будут созданы:

`/data/data/jpcars.db`

`/data/uploads/`

Поэтому и база, и загруженные файлы сохранятся между деплоями.

## Тестирование с клиентами

Для теста можно создавать персональные ссылки и отправлять их клиентам.

Однако до полноценного production рекомендуется дополнительно сделать:
- постоянное session-хранилище вместо MemoryStore;
- CSRF-защиту;
- rate limiting входа;
- журнал доступа к документам;
- антивирусную проверку загрузок;
- резервное копирование volume;
- отдельное object storage для документов;
- политику хранения и удаления персональных данных.


## v0.9
Админские сессии теперь хранятся в SQLite на persistent volume, добавлены rate limits, security headers и журнал доступа к файлам.
