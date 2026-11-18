---
title: Снять ограничения сверок 2.7.0 - Plan
date: 2026-11-18
type: fix
topic: guard-limitations
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan-bootstrap
execution: code
---

# Снять ограничения сверок 2.7.0 - Plan

## Goal Capsule

- **Objective:** сверки порта и имени хоста и «Нет данных TCP-проверки» из 7.0-2.7.0 не дают ложных срабатываний и не молчат там, где план 2.7.0 записал это как ограничение, если это можно исправить без новой дыры.
- **Means:** окна `nodata` из макросов, чтение порта и имени из ответов с ошибкой, нормализация точки в конце имени в `web_check.py`, исправление для отключённого веб-сценария только после живой проверки (KTD1–KTD4).
- **Product authority:** владелец репозитория. Выкладка шаблона и `web_check.py` только после его «да».
- **Open blockers:** нет.
- **Execution profile:** шаблон, словарь, `web_check.py`, тесты и документация в ветке; выкладка (U6) отдельным шагом.
- **Stop conditions:** остановиться и спросить, если U1 не объясняет, почему `nodata()` не сработал на временных хостах 18.11; если пробное сравнение показывает удаление или смену uuid; если после выкладки на любом хосте открылась сверка, «нет данных» или «Сертификат не покрывает имя хоста», которых не было до неё; если `web_check.py self-test` на сборщике не проходит.
- **Who finishes:** исполнитель доводит U1–U5 до зелёных локальных проверок и коммитов в ветке. U6 выполняется после «да» владельца.

---

## Product Contract

### Summary

Окна `nodata`, связанные с проверкой сертификата и TCP-проверкой, берутся из макросов, поэтому более редкий опрос перестаёт давать ложный «нет данных». Сверки порта и имени читают значение из любого ответа проверки сертификата, кроме `bad_url`, и начинают работать с первой проверки, даже если сайт лежит. `web_check.py` 2.2.4 убирает точку в конце имени хоста. «Нет данных TCP-проверки» перестаёт зависеть от одного веб-сценария, если живая проверка подтвердит механизм.

### Problem Frame

План 2.7.0 (`docs/plans/2026-11-18-1330-feat-host-config-guards-plan.md`) записал четыре ограничения. 18.11 каждое разобрано до причины:

- **Окна `nodata` литералом.** 13 вызовов `nodata(...,15m)` по элементам сертификата и TCP в полном профиле (ещё 2 у HTTP/3 остаются литералами, см. Scope Boundaries) при интервалах, заданных макросами `{$WEB_SERVICE.CERT.CHECK.INTERVAL}` и `{$WEB_SERVICE.DIAG.CHECK.INTERVAL}`. Если поднять интервал до 15m и больше, «нет данных» и условия свежести срабатывают между опросами. В профиле Certificate-TLS окно уже вынесено в `{$WEB_SERVICE.CERT.NODATA.PERIOD}`.
- **Сверки ждут успешной проверки.** `web_check.cert.port` и `web_check.cert.host` отбрасывают ответ с `"ok":false`. Но каждый ответ `check_cert` с ошибкой (`dns_error`, `tcp_timeout`, `tcp_error`, `tls_error`, `cert_parse`, `missing_dependency`) несёт настоящие `host` и `port` из URL (`scripts/externalscripts/web_check.py`, `check_cert`); заглушки у `bad_url`, а при недопустимом порте в URL (`https://example.org:99999/`) `main()` отдаёт `internal_error` вообще без `host` и `port`. Проверено: ответ с `dns_error` для URL с портом 20443 содержит `port: 20443`.
- **Точка в конце имени.** `url_host` (`web_check.py:190`) берёт `urlparse(...).hostname`, а он оставляет точку: `https://example.org./` даёт `example.org.`. Тогда не совпадает не только сверка имени: `_hostname_covered` (`web_check.py:645`) сравнивает имя с SAN без точки и возвращает `False`, то есть открывается HIGH «Сертификат не покрывает имя хоста».
- **Отключённый веб-сценарий.** Выражение «Нет данных TCP-проверки» требует свежих данных веб-сценария; у отключённого их нет, триггер не срабатывает никогда. Сейчас все 55 веб-сценариев включены.

Три живых опыта 18.11 с временными хостами не дали срабатывания `nodata()` даже в базовом случае (TCP-элемент молчит, веб-сценарий свежий), хотя утром того же дня такой же опыт срабатывал. Причина не выяснена, поэтому механизм исправления для отключённого веб-сценария не подтверждён.

### Requirements

**Окна нет-данных**

- R1. Все окна `nodata` по элементам проверки сертификата (основной элемент, `web_check.cert.port`, `web_check.cert.host`) берутся из `{$WEB_SERVICE.CERT.NODATA.PERIOD}`, окно «Нет данных TCP-проверки» — из нового `{$WEB_SERVICE.DIAG.NODATA.PERIOD}`. Оба по умолчанию 15m, поведение на текущих хостах не меняется. Описания говорят: не меньше трёх интервалов соответствующей проверки.

**Сверки с первой проверки**

- R2. `web_check.cert.port` и `web_check.cert.host` отбрасывают только ответы с `error_code` `bad_url` и `internal_error`; значение из любого другого ответа проверки сертификата сохраняется. Сверки открываются с первой проверки после добавления хоста, даже если сайт недоступен.

**Точка в конце имени**

- R3. `web_check.py` 2.2.4: хост из URL без конечной точки во всех командах. Для `https://example.org./` проверка сертификата покрывает имя `example.org`, сверка имени не срабатывает при `{$WEB_SERVICE.HOST}` = `example.org`.

**Отключённый веб-сценарий**

- R4. «Нет данных TCP-проверки» срабатывает и на хосте с отключённым веб-сценарием, при этом при молчании всего сборщика задача остаётся одна. Делается, только если U1 подтвердит механизм вживую; иначе ограничение остаётся записанным, с причиной.

**Сборка и выкладка**

- R5. Русская версия из словаря; версия полного шаблона `7.0-2.7.1`, `web_check.py` `2.2.4`; записи в CHANGELOG.
- R6. Выкладка по порядку проекта: шаблон на оба сервера, `web_check.py` на все сборщики, которые обслуживают хосты шаблона, через `scripts/deploy/install.sh` с `self-test`. Порядок: сначала `web_check.py`, потом шаблон.

### Key Decisions

- **Имя макроса окна сертификата — `{$WEB_SERVICE.CERT.NODATA.PERIOD}`, как в профиле Certificate-TLS.** Один макрос для одной проверки в обоих профилях. Governs R1.
- **Отбрасывать только `bad_url` и `internal_error`.** Остальные ответы с ошибкой заполняют `host` и `port` из URL до сетевого обращения; у `bad_url` заглушки (пустой хост, порт 443), у `internal_error` этих полей нет. Governs R2.
- **Сверка с открытым расхождением держит TCP-аварию подавленной и во время аварии сайта.** В 2.7.0 условие свежести закрывало сверку через 15 минут без успешной проверки, потому что значение порта и имени устаревало. С R2 значение приходит из каждого ответа и не устаревает: исправленный макрос закрывает сверку по таймеру сразу, а открытой она остаётся, только пока макрос действительно не совпадает с URL, то есть TCP-проверка смотрит не туда. WARNING о расхождении при этом виден. Условие свежести остаётся на случай, когда основной элемент сертификата не присылает ничего. Пересматривает решение 2.7.0 (KTD2 того плана). Governs R2. (session-settled: user-directed — chosen over поведения 2.7.0, где сверка отпускала TCP-аварию через 15 минут без успешной проверки: значение больше не устаревает, исправленный макрос закрывает сверку по таймеру)
- **R4 не строится на непроверенном поведении.** Три опыта не дали срабатывания `nodata()` на временных хостах; причина не выяснена. Сначала объяснение, потом исправление. Governs R4. (session-settled: user-directed — chosen over исключения R4 и U1 из плана: живые проверки изменений `nodata()` опираются на понимание его поведения на временных хостах; не больше двух опытов)

### Acceptance Examples

- AE1. **Covers R1.** **Given** хост с `{$WEB_SERVICE.CERT.CHECK.INTERVAL}` = `20m` и `{$WEB_SERVICE.CERT.NODATA.PERIOD}` = `1h`. **When** проверки сертификата идут раз в 20 минут. **Then** «Нет данных внешнего скрипта сертификата» и условия свежести сверок не срабатывают.
- AE2. **Covers R2.** **Given** новый хост с URL на порту 20443, макрос порта не задан, сайт недоступен (`tcp_timeout`). **When** приходит первая проверка сертификата. **Then** открыт WARNING о расхождении порта, «Нет соединения TCP» молчит.
- AE3. **Covers R2.** **Given** URL пуст, не разбирается или с недопустимым портом (`bad_url`, `internal_error`). **Then** сверки не открываются; об ошибке сообщает веб-сценарий.
- AE4. **Covers R3.** **Given** URL `https://example.org./`, сертификат на `example.org`, `{$WEB_SERVICE.HOST}` = `example.org`. **Then** «Сертификат не покрывает имя хоста» и сверка имени не открыты.

### Success Criteria

- После выкладки на обоих серверах не открылось ни одной сверки, «нет данных» и «Сертификат не покрывает имя хоста», которых не было до неё, кроме сверок из списка ожидаемых (U6, шаг 2).
- `web_check.py self-test` проходит на всех сборщиках, которые обслуживают хосты шаблона, версия 2.2.4.

### Scope Boundaries

- Окна нет-данных HTTP/3, WHOIS и TLS-скана остаются литералами (15m, 3h, 3d). Их интервалы тоже макросы, но ограничение 2.7.0 касалось сертификата и TCP. Изменит решение: хост, где интервал HTTP/3 подняли.
- Нормализация регистра и формы `xn--` в `{$WEB_SERVICE.HOST}` не делается: описание макроса задаёт форму, все текущие значения ей соответствуют.

---

## Planning Contract

### Key Technical Decisions

- KTD1. **Окна из макросов, а не вычисленные из интервала.** Zabbix не умножает макросы в выражениях; макрос периода с правилом «не меньше трёх интервалов» в описании — принятый в профиле Certificate-TLS приём.
- KTD2. **Первый шаг предобработки `web_check.cert.port` и `web_check.cert.host` — `NOT_MATCHES_REGEX "error_code":"(bad_url|internal_error)"` с `DISCARD_VALUE`.** Тест `test_cert_dependents_discard_the_error_envelope` получает для этих двух ключей явное исключение с причиной, как у `web_check.cert.ok`. Условие свежести сверок остаётся: теперь оно истекает, только когда основной элемент сертификата не присылает ничего.
- KTD3. **Нормализация в `url_host`, единственной точке разбора хоста.** Её используют все команды; правка в одном месте покрывает проверку сертификата, TLS-скан, HTTP/3 и WHOIS.
- KTD4. **R4 решается в U1 по фактам.** Кандидат — признак «сборщик жив» только по основному элементу сертификата, без элемента веб-сценария: `nodata(tcp,{$WEB_SERVICE.DIAG.NODATA.PERIOD})=1 and nodata(web_check.py["cert",…],{$WEB_SERVICE.CERT.NODATA.PERIOD})=0`. Элемент веб-сценария в выражении сделал бы триггер зависимым от его включённости. Когда молчит весь сборщик, о нём сообщают существующие «нет данных» веб-сценария и сертификата. Сейчас ни один основной элемент сертификата не отключён. Если U1 не подтвердит кандидата вживую, R4 закрывается как ограничение с измеренной причиной.

---

## Implementation Units

### U1. Разобраться с `nodata()` на временных хостах и решить R4

- **Goal:** объяснить, почему `nodata()` не срабатывал в опытах 18.11 после обеда, и проверить кандидата для R4.
- **Requirements:** R4; KTD4.
- **Dependencies:** нет.
- **Files:** нет изменений в репозитории; результат записывается в этот план.
- **Approach:**
  1. Сравнить удачный утренний опыт (trapper-элементы, интерфейс `127.0.0.1`, окно 3m, срабатывание через 8 минут) с тремя неудачными (окна 1m и 2m, показ через 100–200 с): время с момента создания триггера, тип значения, окно, режим `nodata` (документация Zabbix 7.0 о `strict` и доступности прокси), журнал сервера.
  2. Повторить базовый случай так, чтобы он сработал, и только потом проверить кандидата KTD4 на хосте с отключённым элементом веб-сценария.
- **Execution note:** исследование; не больше двух новых опытов, затем решение по фактам.
- **Test scenarios:** `Test expectation: none -- живой опыт на временном хосте, триггеры INFO`.
- **Verification:** в плане записана причина и решение по R4.

### U2. Сверки из ответов с ошибкой

- **Goal:** сверки порта и имени работают с первой проверки сертификата.
- **Requirements:** R2; AE2, AE3; KTD2.
- **Dependencies:** нет.
- **Files:** `templates/web-service-by-itforprof/template_web_service_by_itforprof_com.yaml`, `templates/web-service-by-itforprof/i18n/ru.yaml`, `templates/web-service-by-itforprof/template_web_service_by_itforprof_com_ru.yaml` (генерируется), `scripts/tests/test_template_contract.py`, `scripts/tests/test_cert.py`.
- **Approach:** первый шаг предобработки обоих элементов по KTD2; описания элементов («только из успешных проверок») и описания обеих сверок («закрывается через 15 минут без успешной проверки») переписать по новому решению; переводы и пересборка `_ru.yaml`.
- **Patterns to follow:** исключение для `web_check.cert.ok` в `test_cert_dependents_discard_the_error_envelope`.
- **Test scenarios:**
  - Covers AE2. Ответ `check_cert` с `dns_error` для URL с портом 20443 не отбрасывается шагом элемента порта, JSONPath даёт 20443; то же для имени хоста.
  - Covers AE3. Ответы `bad_url` и `internal_error` (настоящий `main()` для URL `https://example.org:99999/`) отбрасываются шагом обоих элементов.
  - Остальные зависимые элементы сертификата по-прежнему начинаются с отбрасывания `"ok":false`.
- **Verification:** контрактные тесты и `test_cert.py` зелёные.

### U3. Окна нет-данных из макросов

- **Goal:** окна сертификата и TCP задаются макросами.
- **Requirements:** R1; AE1; KTD1.
- **Dependencies:** U1 (условный шаг R4), U2 (тот же файл).
- **Files:** `templates/web-service-by-itforprof/template_web_service_by_itforprof_com.yaml`, `templates/web-service-by-itforprof/i18n/ru.yaml`, `templates/web-service-by-itforprof/template_web_service_by_itforprof_com_ru.yaml` (генерируется), `scripts/tests/test_template_contract.py`.
- **Approach:** макросы `{$WEB_SERVICE.CERT.NODATA.PERIOD}` и `{$WEB_SERVICE.DIAG.NODATA.PERIOD}` (15m) с описаниями; все 12 вызовов `nodata` по элементам сертификата (основной элемент, порт и имя хоста — по 4) и 1 по TCP переписать на макросы, включая выражения зависимостей и выражение «Нет соединения TCP»; 15m в `event_name`, `opdata` и описаниях обоих триггеров нет-данных заменить макросом, как в профиле Certificate-TLS; описания `{$WEB_SERVICE.DIAG.CHECK.INTERVAL}` и `{$WEB_SERVICE.NODATA.PERIOD}` переписать через `{$WEB_SERVICE.DIAG.NODATA.PERIOD}`. Если U1 подтвердил KTD4, условие веб-сценария в «Нет данных TCP-проверки» заменить кандидатом KTD4; переводы и пересборка `_ru.yaml`.
- **Patterns to follow:** `{$WEB_SERVICE.CERT.NODATA.PERIOD}` в `template_web_service_by_itforprof_com_tls.yaml`.
- **Test scenarios:**
  - В полном профиле нет `nodata(` с литералом `15m` по элементам сертификата и TCP.
  - `test_persistent_cert_failure_escalates_after_three_polls_and_requires_fresh_data` ожидает `{$WEB_SERVICE.CERT.NODATA.PERIOD}` в обоих профилях.
  - Тесты сверок и «нет данных TCP» ожидают выражения с макросами.
- **Verification:** контрактные тесты зелёные; `test_trigger_dependency_expressions_match_target_triggers` проходит.

### U4. `web_check.py` 2.2.4: точка в конце имени

- **Goal:** хост из URL без конечной точки.
- **Requirements:** R3; AE4; KTD3.
- **Dependencies:** нет.
- **Files:** `scripts/externalscripts/web_check.py`, `scripts/tests/test_apex.py`, `scripts/tests/test_cert.py`.
- **Approach:** в `url_host` убрать конечную точку после `lower()`; версия `__version__` 2.2.4.
- **Execution note:** сначала тест, который падает на текущем коде.
- **Test scenarios:**
  - `url_host("https://example.org./")` возвращает `("example.org", 443)`; `url_host("https://Example.org.:8443/", force_tls=True)` — `("example.org", 8443)`.
  - Covers AE4. `_hostname_covered` для хоста из `https://example.org./` и SAN `example.org` возвращает `True`.
- **Verification:** `pytest -q`, `ruff`, `mypy --strict` по `web_check.py` в версиях из `ci.yml`.

### U5. Описания, русская сборка, версии, CHANGELOG

- **Goal:** документация и версии отражают U2–U4 (и U1, если R4 сделан).
- **Requirements:** R5.
- **Dependencies:** U1–U4.
- **Files:** `templates/web-service-by-itforprof/i18n/ru.yaml`, `templates/web-service-by-itforprof/template_web_service_by_itforprof_com_ru.yaml` (генерируется), `templates/web-service-by-itforprof/README.md`, `docs/architecture.md`, `README.md`, `README_EN.md`, `CHANGELOG.md`, `scripts/tests/test_template_contract.py` (тест версии).
- **Approach:** переводы и пересборка в каждом юните, меняющем строки шаблона; версия шаблона `7.0-2.7.1`; таблица макросов README (31); записи CHANGELOG для шаблона и `web_check`.
- **Test scenarios:** тесты русской сборки проходят; тест версии ожидает `7.0-2.7.1`.
- **Verification:** `translate-templates.py --check` выходит с 0.

### U6. Живая проверка и выкладка

- **Goal:** `web_check.py` 2.2.4 на всех сборщиках, шаблон 7.0-2.7.1 на обоих серверах, без новых сигналов.
- **Requirements:** R6; Success Criteria.
- **Dependencies:** U1–U5 в main, «да» владельца.
- **Files:** нет изменений в репозитории.
- **Approach:**
  1. Живая проверка AE2 на временном хосте: trapper-элемент с JSON основного элемента и созданные вручную зависимые элементы с новой предобработкой (не импорт шаблона).
  2. Список ожидаемых сверок: хосты, где `web_check.cert.ok` сейчас 0 или порт/имя давно не обновлялись; для каждого — ожидаемое расхождение по URL и макросам.
  3. `install.sh` с `REF` на коммит main на каждом сборщике, который обслуживает хосты шаблона (список сверить по `host.get` с `monitored_by` и прокси), `self-test`, версия 2.2.4.
  4. Шаблон: пробное сравнение, снимок отключённых объектов, импорт `_ru.yaml`, возврат статусов, дедупликация, `check-template-preprocessing.py`, `recovery_mode`.
  5. Через 20 минут: Success Criteria.
- **Test scenarios:** `Test expectation: none -- операционная выкладка`.
- **Verification:** Success Criteria на обоих серверах.

---

## Verification Contract

| Проверка | Команда или способ | Когда |
|---|---|---|
| Тесты | `pytest -q` в `scripts/` с зависимостями из `ci.yml` | U2–U5 |
| Линт, формат, типы | `ruff check .`, `ruff format --check .`, `mypy --strict --ignore-missing-imports --python-version 3.11 externalscripts/web_check.py` (mypy 1.13, как в `ci.yml`) | U2–U5 |
| YAML | yamllint с правилами `.github/workflows/yaml-validate.yml` | U2, U3, U5 |
| Русская сборка | `scripts/translate-templates.py --check` | U5 |
| Сборщики | `web_check.py self-test`, версия 2.2.4 | U6 |
| Импорт | `configuration.importcompare`, `check-template-preprocessing.py`, `item.get`, `problem.get` | U6 |

---

## Definition of Done

- U1–U5: локальные проверки зелёные, коммиты без AI-атрибуции и без клиентских имён, IP и ID.
- R4 сделан или закрыт как ограничение с измеренной причиной.
- В диффе нет брошенного кода.
- U6 выполняется только после «да» владельца и закончен, когда выполнены Success Criteria.

---

## U1 Result

- **Why the afternoon experiments did not fire:** every `history.push` was rejected with "Client IP is not in item's allowed hosts list" (the helper ignored the per-item errors), so the trapper items had no data at all. `nodata()` itself behaved as documented: with no data it counts from when the item entered the configuration cache.
- **Experiment with `trapper_hosts` set (two temporary hosts, 2m windows):** with the web item enabled both gates fired 2 min after TCP went silent; with the web item disabled the web gate stayed UNKNOWN ("Cannot evaluate function nodata(...): item is disabled") and the certificate gate fired. KTD4 is confirmed; R4 is done.
- **Race the candidate adds:** when the whole collector stops, the TCP item can go stale up to one certificate interval before the certificate item. `{$WEB_SERVICE.DIAG.NODATA.PERIOD}` defaults to 20m (certificate window 15m + one 5m interval) so only the certificate no-data problem opens.

## Deployment Record

Выкладка 2026-11-18: main `5da4f70`.

- Живая проверка AE2 на временном хосте production (trapper с ответами настоящего `web_check.py`, хост удалён): ответ `tcp_error` для порта 20443 записан в элементы порта и имени; ответы `bad_url` и `internal_error` отброшены, элементы остались поддерживаемыми.
- `web_check.py` 2.2.4 через `install.sh` (REF `5da4f70`) установлен на втором сервере и четырёх прокси production; `self-test` везде чистый. Сервер production не обновлён: SSH сообщил о смене ключа хоста и отклонил вход, ключ не трогали. Шаблон 7.0-2.7.1 работает и с 2.2.3: изменение `web_check` касается только URL с точкой на конце, таких хостов нет.
- Пробное сравнение: удалений и новых элементов нет; 16 «добавленных» триггеров уже есть на серверах с тем же uuid (шум сравнения для триггеров на нескольких элементах), 6 триггеров обновлены.
- Импорт RU-шаблона (`createMissing` + `updateExisting`, без `deleteMissing`) включил обратно отключённые на хостах триггеры (180 и 27); статусы возвращены по снимку, элементы не тронуты. Дедупликация WHOIS: 0 действий на обоих серверах. `check-template-preprocessing.py`: совпадает с файлами; `recovery_mode` триггера сертификата сохранён; новая предобработка порта и имени стоит на всех хостах (49 и 6), условие «нет данных TCP» на всех хостах опирается на основной элемент сертификата.
- Через 20 минут: новых сверок, «нет данных» и TCP-аварий нет; `web_check.cert.port` свежий на всех хостах (45 из 45 и 6 из 6). Новые события на хостах шаблона (смена ОС на одном хосте из шаблона Linux) и неподдерживаемый `web_check.whois.dnssec` на одном хосте к выкладке не относятся: последнее значение WHOIS пришло до импорта, элементы импорт не менял.

Сравнения, снимки и результаты проверки сохранены в `~/.local/state/zabbix-webservices/deployments/2026-11-18-guard-limitations/`.
