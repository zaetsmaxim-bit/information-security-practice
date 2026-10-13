# information-security-practice
# Захищений REST API «Електронний деканат»

**Короткий опис:** FastAPI + SQLite + JWT + RBAC
**Дисципліна:** Безпека інформаційних систем
**Студент:** Заєць Максим Михайлович
**Група:** 223 група
**Репозиторій:** https://github.com/zaetsmaxim-bit/information-security-practice
**Останній коміт:** 0ca52ba

## Інструкція запуску
1. `git clone https://github.com/zaetsmaxim-bit/information-security-practice.git`
2. `cd information-security-practice`
3. `cp .env.example .env` (або створіть вручну)
4. `docker compose up -d --build`
5. `docker compose exec api alembic upgrade head`
6. `docker compose exec api python -m app.seed`

## Адреси
- **API:** http://localhost:8000
- **Swagger UI:** http://localhost:8000/docs

## Тестові облікові записи
| Логін | Роль |
|---|---|
| `admin` | admin |
| `teacher01` | teacher |
| `student01` | student |
*(Паролі зберігаються лише у файлі seed.py)*

## Ендпоінти та ролі
| Ендпоінт | Метод | Доступ (Роль) |
|---|---|---|
| `/auth/register` | POST | Public |
| `/auth/login` | POST | Public |
| `/auth/refresh` | POST | Будь-який автентифікований |
| `/auth/me` | GET | Будь-який автентифікований |
| `/students/me/grades` | GET | student |
| `/teachers/students/{id}/grades` | GET | teacher, admin |
| `/teachers/grades` | POST | teacher, admin |
| `/admin/users` | GET | admin |

## Моделювання загроз (STRIDE)
| Загроза | Контрзахід у коді | Що можна покращити |
|---|---|---|
| **Spoofing** | CORS з allow-list доменів | Додати WAF |
| **Tampering** | Security Headers (CSP, nosniff), bleach (санітизація) | HttpOnly cookie + CSRF-токен |
| **Repudiation** | Поле `assigned_by` в таблиці оцінок | Повноцінний аудит-лог дій |
| **Information Disclosure** | JWT без паролів у payload | RS256 замість HS256 для підпису |
| **Denial of Service** | Rate Limiting (5 запитів/хв на логін) | Redis-blacklist токенів |
| **Elevation of Privilege**| RBAC (require_role перевіряє БД) | Двофакторна автентифікація (2FA) |

## Фінальна перевірка
| № | Сценарій | Запит | Фактичний результат |
|---|---|---|---|
| 1 | Health | `GET /health` | 200, tables: 8 |
| 2 | Реєстрація (успіх) | `POST /auth/register` | 201, без password_hash |
| 3 | Дублікат | повторна реєстрація | 409 |
| 4 | Слабкий пароль | `password` | 422 |
| 5 | XSS в імені | `<script>alert(1)</script>` | 422 |
| 6 | Логін (успіх) | `POST /auth/login` admin | 200, access + refresh токени |
| 7 | Невірний пароль | `POST /auth/login` wrong | 401 |
| 8 | Без токена | `GET /auth/me` | 401 |
| 9 | Підроблений токен | `GET /auth/me` Bearer abc | 401 |
| 10 | Refresh замість access | `GET /auth/me` Bearer $RT | 401 |
| 11 | Оновлення токенів | `POST /auth/refresh` | 200 |
| 12 | Свої оцінки | `GET /students/me/grades` | 200 |
| 13 | Студент -> admin | `GET /admin/users` | 403 |
| 14 | Викладач -> admin | `GET /admin/users` | 403 |
| 15 | Адмін -> admin | `GET /admin/users` | 200 |
| 16 | Оцінка поза діапазоном | `POST /teachers/grades` 9999 | 422 |
| 17 | Stored XSS у коментарі | `POST /teachers/grades` script | 201, тег вирізано |
| 18 | Security Headers | `GET /health` | CSP, X-Frame-Options присутні |
| 19 | CORS чужий домен | `OPTIONS /auth/login` | 400 |
| 20 | Rate Limiting | 6x `POST /auth/login` | 429 Too Many Requests |
