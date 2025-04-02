### Веб-приложение с авторизацией и персонализацией

Это учебное веб-приложение, демонстрирующее реализацию системы аутентификации, персонализации интерфейса и кэширования данных на стороне сервера.


### Шаги установки

1. Клонируйте репозиторий:

```shellscript
git clone https://github.com/fuglyy/15-16.git
cd имя-репозитория
```


2. Установите зависимости:

```shellscript
npm install
```


3. Запустите сервер:

```shellscript
npm start
```


4. Откройте приложение в браузере:

```plaintext
http://localhost:3000
```




## Использование

### Демо-доступ

Для быстрого тестирования используйте:

- **Логин**: admin
- **Пароль**: 12345


### Регистрация нового пользователя

1. Перейдите на вкладку "Регистрация"
2. Введите логин и пароль (минимум 5 символов)
3. Нажмите кнопку "Зарегистрироваться"


### Вход в систему

1. Перейдите на вкладку "Вход"
2. Введите логин и пароль
3. Нажмите кнопку "Войти"


### Персонализация

- Для переключения темы нажмите на кнопку с иконкой солнца/луны
- Выбранная тема сохраняется между сессиями


### Работа с данными

- Данные загружаются автоматически при входе в систему
- Для обновления данных нажмите кнопку "Обновить"
- Время последнего обновления отображается под данными
