---
title: WHOIS — домены FAITID, разбор DNSSEC и застрявший элемент - Plan
date: 2026-11-18
type: fix
topic: whois-faitid-dnssec
artifact_contract: ce-unified-plan/v1
product_contract_source: ce-plan-bootstrap
execution: code
---

# WHOIS — домены FAITID, разбор DNSSEC и застрявший элемент - Plan

## Goal Capsule

- **Objective:** WHOIS-проверки шаблона «Web service by itforprof.com» отслеживают зарегистрированный домен, верно читают DNSSEC и не застревают в NOTSUPPORTED после разовой ошибки скрипта.
- **Means:** `web_check.py` 2.2.5 (домены FAITID через реестр `whois.flexireg.net`, разбор DNSSEC, кеш без блокировки при отказе в правах), шаблон 7.0-2.7.2 (элемент DNSSEC отбрасывает ответ без поля, а не уходит в NOTSUPPORTED), две мелочи в тестах и типах.
- **Product authority:** владелец репозитория. Выкладка только после его «да».
- **Open blockers:** нет.
- **Execution profile:** код, тесты, шаблон и документация в ветке; слияние в main и выкладка (U6) — отдельным шагом после «да» владельца.
- **Stop conditions:** остановиться и спросить, если `whois.flexireg.net` перестал отвечать или изменил формат; если пробное сравнение шаблона показывает удаление или смену uuid; если после выкладки на любом хосте открылось предупреждение WHOIS, которого не было до неё, кроме ожидаемых событий смены домена (U6, шаг 5); если `self-test` на сборщике не проходит.
- **Who finishes:** исполнитель доводит U1–U5 до зелёных локальных проверок и коммитов в ветке. U6 — после «да» владельца.

---

## Product Contract

### Summary

Для доменов, которые реестр FAITID регистрирует на третьем уровне (`*.msk.ru`, `*.spb.ru`, `*.com.ru`, `*.ru.net`, геодомены `.su` и другие из блока FAITID в Public Suffix List), WHOIS смотрит на сам домен (`example.msk.ru`), а не на суффикс (`msk.ru`), и спрашивает реестр `whois.flexireg.net`. Значения DNSSEC вида `unsignedDelegation` и `signedDelegation` читаются верно. Ошибка, при которой ответ WHOIS приходит без поля `dnssec`, больше не переводит элемент DNSSEC в NOTSUPPORTED, а отказ в правах на каталог кеша не ломает WHOIS.

### Problem Frame

Разбор 18.11 на production:

- **Не тот домен.** `registered_apex` (`scripts/externalscripts/web_check.py`, `_get_psl_extractor`) берёт `tldextract` без private-секции PSL, поэтому для хоста вида `chat.example.msk.ru` получается `msk.ru`. `msk.ru` стоит в private-секции, в блоке FAITID (72 суффикса). Домен третьего уровня под `msk.ru` — отдельная регистрация со своим сроком в реестре `whois.flexireg.net`, а мониторинг видит срок самого `msk.ru`. У затронутого домена срок в реестре на несколько месяцев раньше, чем у `msk.ru`, поэтому предупреждение о сроке не придёт вовремя. Затронуты 2 хоста production; на втором сервере таких хостов нет.
- **Разбор DNSSEC.** `_normalize_whois` считает `signed` всё, кроме `unsigned`, `none`, `no` и пустой строки, поэтому `unsignedDelegation` и `Unsigned delegation` становятся `signed`. Сейчас все 7 значений DNSSEC пришли через RDAP и разбором порта 43 не задеты; при запасном пути порта 43 ложное `signed` с последующим `unsigned` из RDAP открыло бы WARNING «Domain DNSSEC removed». Реестр FAITID отвечает именно `unsignedDelegation`.
- **Застрявший элемент.** На новом сервере production в 15:59 и 16:14 файлы блокировки двух доменов в каталоге кеша WHOIS были недоступны на запись (`PermissionError` на `whois_<sha>.lock`, вероятно созданные не пользователем `zabbix`; к вечеру на всех сборщиках чужих файлов в кеше нет). `WhoisCache.lock()` открывает файл блокировки без защиты (в отличие от `write()`, который ошибки прав пропускает), исключение дошло до `main()`, и тот выдал `internal_error` без поля `dnssec`. Первый шаг `web_check.whois.dnssec` — JSONPath с `CUSTOM_ERROR`, элемент ушёл в NOTSUPPORTED. Следующие ответы `ok: true` несут `dnssec: "unknown"`, их отбрасывает шаг `^(signed|unsigned)$`, а отброшенное значение рабочее состояние не возвращает (наблюдалось: 4 ответа с 16:42 до 19:59, элемент так и остался NOTSUPPORTED).
- **Мелочи.** Параметр `nodata_period` в `test_persistent_cert_failure_escalates_after_three_polls_and_requires_fresh_data` больше не меняется; локальный mypy 2.3.1 даёт 2 ошибки в `web_check.py` (вызов `_quic_handshake` в `cmd_http3` и возврат `Any` из функции с типом `str | None`), которых нет в mypy 1.13 из CI.

### Requirements

- R1. Для хоста, чьё имя оканчивается на `.` плюс суффикс FAITID (по границе метки), зарегистрированный домен — метка слева от суффикса плюс суффикс (`chat.example.msk.ru` → `example.msk.ru`); хост, равный суффиксу (`msk.ru`), и хост, который лишь заканчивается теми же буквами (`www.telecom.ru`), обрабатываются как раньше; WHOIS для него спрашивает `whois.flexireg.net` без перехода к серверу регистратора и разбирает ответ общим разборщиком формата ICANN. Для остальных хостов поведение не меняется.
- R2. DNSSEC: значения, начинающиеся с `unsigned` (без учёта регистра и пробелов), и `no`, `none`, пустая строка → `unsigned`; начинающиеся с `signed`, и `yes` → `signed`; любое другое строковое значение → `unknown`.
- R3. Если файл блокировки кеша WHOIS нельзя открыть из-за отказа в правах (`PermissionError`), проверка WHOIS идёт без блокировки и возвращает данные, а не `internal_error`. Другие ошибки открытия ведут себя как раньше.
- R4. `web_check.whois.dnssec` отбрасывает ответ без поля `dnssec`, а не уходит в NOTSUPPORTED. Об ошибках WHOIS сообщают `web_check.whois.ok` и `web_check.whois.error_code`, как и сейчас.
- R5. Убрать параметр `nodata_period`; `web_check.py` проходит `mypy --strict` и в 1.13, и в 2.3.1.
- R6. Версии: `web_check.py` 2.2.5, шаблон 7.0-2.7.2; CHANGELOG; русская сборка в синхроне.
- R7. Выкладка: `web_check.py` на все сборщики, потом шаблон на оба сервера, потом дедупликация WHOIS на обоих серверах.

### Acceptance Examples

- AE1. **Covers R1.** **Given** URL `https://chat.example.msk.ru/` и ответ реестра FAITID с `Registry Expiry Date` и `DNSSEC: unsignedDelegation`. **Then** `apex` = `example.msk.ru`, `expires_at` — срок из ответа реестра, `dnssec` = `unsigned`.
- AE2. **Covers R1.** **Given** `foo.github.io` или `mail.itforprof.com`. **Then** домен прежний (`github.io`, `itforprof.com`).
- AE3. **Covers R3.** **Given** каталог кеша без прав на запись. **Then** `check_whois` возвращает разобранный ответ, `ok` не `false`.
- AE4. **Covers R4.** **Given** ответ `internal_error` без поля `dnssec`, затем ответ с `dnssec: "unsigned"`. **Then** первый отброшен, второй записан, элемент в рабочем состоянии.

### Success Criteria

- После выкладки `web_check.whois.apex` на обоих затронутых хостах — домен третьего уровня, срок совпадает с ответом реестра FAITID, `web_check.whois.dnssec` в рабочем состоянии со значением из реестра.
- Новых проблем WHOIS на хостах шаблона нет, кроме ожидаемых «Domain registrar changed» и «Domain name servers changed» на хосте-владельце затронутой группы (U6, шаг 5); `self-test` на всех сборщиках проходит, версия 2.2.5.

### Scope Boundaries

- Другие реестры из private-секции PSL (MSK-IX `net.ru`/`org.ru`/`pp.ru`, `ac.ru` и подобные) не обрабатываются: хостов с ними нет. Добавление реестра — одна строка в таблице суффиксов и сервер.
- Остальные элементы WHOIS по-прежнему уходят в NOTSUPPORTED на ответе без поля и восстанавливаются со следующим значением; менять это не нужно.
- GitHub Actions не включаются.

---

## Planning Contract

### Key Technical Decisions

- KTD1. **Суффиксы FAITID — константа в `web_check.py`, а не private-секция PSL целиком.** Private-секция содержит и платформы хостинга (`github.io` и подобные), у поддоменов которых нет WHOIS. Набор FAITID — 72 суффикса из блока «FAITID» PSL; тест сверяет, что каждый есть в private-секции снимка `tldextract`. Домен — строковая операция по суффиксу, без второго экстрактора.
- KTD2. **Запрос к реестру, а не к регистратору.** `whois.flexireg.net` отвечает в формате ICANN со сроком, DNSSEC и серверами имён; переход к `whois.nic.ru` (регистратор) отключается (`find_authoritative_server=False`). Ответ разбирается общим разборщиком `asyncwhois` (как для `com`), а не разборщиком `ru`, который этот формат не читает (проверено на asyncwhois 1.1.15; код запроса и разбора совпадает с закреплённой в `requirements.lock` 1.1.12; `ru` и `su` дают `expires: None`, `com` даёт срок и серверы имён; дата разбирается в UTC при любом часовом поясе сборщика, проверено с `TZ=Europe/Moscow`). RDAP для домена FAITID не вызывается: `asyncwhois.rdap` заново выделяет домен своим экстрактором и спросил бы `msk.ru`; сейчас у `.ru` нет RDAP, и это незаметно, но сломается, когда он появится.
- KTD3. **`registered_apex` меняется в одном месте.** Его используют `check_whois`, `cmd_*` через WHOIS и `scripts/sync-domain-registry-owners.py`; для двух хостов ключ дедупликации станет доменом третьего уровня (оба остаются в одной группе), поэтому после выкладки дедупликация перезапускается.
- KTD4. **`lock()` при отказе в правах на файл отдаёт «без блокировки», а не `None`.** `None` означает «другой процесс уже спрашивает» и ведёт к ответу из кеша или `whois_locked`; отказ в правах — другой случай, проверка должна идти дальше.
- KTD5. **DNSSEC-элемент: JSONPath с `DISCARD_VALUE`.** Элемент и так отбрасывает `unknown`; ответ без поля — тот же случай. Остальные элементы WHOIS оставляют `CUSTOM_ERROR`, чтобы ошибка была видна.

---

## Implementation Units

### U1. Разбор DNSSEC

- **Goal:** R2.
- **Files:** `scripts/externalscripts/web_check.py` (`_normalize_whois`), `scripts/tests/test_whois.py`.
- **Approach:** сначала падающий тест на `unsignedDelegation`, `Unsigned delegation`, `signedDelegation`, `yes`, `no`, `none`, `""`, `inactive`; затем правка ветки строкового значения.
- **Verification:** `pytest tests/test_whois.py`.

### U2. Кеш без блокировки при отказе в правах

- **Goal:** R3; AE3; KTD4.
- **Files:** `scripts/externalscripts/web_check.py` (`WhoisCache.lock`, `check_whois`), `scripts/tests/test_cache.py`.
- **Approach:** падающий тест: в доступном каталоге кеша файл блокировки домена с `chmod 000`, подменённый запрос WHOIS, `check_whois` возвращает данные. Правка: `PermissionError` при открытии файла блокировки → отдать признак «без блокировки», `check_whois` идёт к запросу; прочие `OSError` не перехватываются (иначе при нехватке дескрипторов все параллельные проверки пошли бы в реестр одновременно).
- **Verification:** `pytest tests/test_cache.py tests/test_whois.py`.

### U3. Домены FAITID

- **Goal:** R1; AE1, AE2; KTD1–KTD3.
- **Dependencies:** U1 (ответ реестра несёт `unsignedDelegation`).
- **Files:** `scripts/externalscripts/web_check.py` (`registered_apex`, `_query_registration`, `_query_whois_port43`, константа суффиксов), `scripts/tests/test_apex.py`, `scripts/tests/test_whois.py`, `scripts/tests/fixtures/` (ответ `whois.flexireg.net` в его формате, с выдуманными доменом, сроком и серверами имён).
- **Approach:** падающие тесты: `registered_apex("chat.example.msk.ru") == "example.msk.ru"`; без изменений `foo.github.io`, `mail.itforprof.com`, `www.telecom.ru` (→ `telecom.ru`, не `tele.com.ru`) и сам `msk.ru`; каждый суффикс константы есть в private-секции снимка `tldextract`; разбор этого ответа даёт срок из него и `dnssec` `unsigned`; для домена FAITID запрос идёт к `whois.flexireg.net` (подменённый `query_obj.run`), а `asyncwhois.rdap` не вызывается. Затем правка.
- **Verification:** `pytest`; живой запрос `web_check.py whois` по URL затронутого хоста даёт домен третьего уровня, срок из ответа реестра и `dnssec` `unsigned` (AE1 задаёт форму ответа на выдуманных значениях).

### U4. Шаблон: DNSSEC-элемент и мелочи

- **Goal:** R4, R5; AE4; KTD5.
- **Files:** `templates/web-service-by-itforprof/template_web_service_by_itforprof_com.yaml`, `templates/web-service-by-itforprof/i18n/ru.yaml`, `templates/web-service-by-itforprof/template_web_service_by_itforprof_com_ru.yaml` (генерируется), `scripts/tests/test_template_contract.py`, `scripts/externalscripts/web_check.py` (типы).
- **Approach:** тест: первый шаг `web_check.whois.dnssec` — JSONPath с `DISCARD_VALUE`, и ответ `main()` с `internal_error` не проходит его. Правка шаблона (у `error_handler_params` нет перевода, `ru.yaml` не меняется; другие 9 элементов WHOIS оставляют `CUSTOM_ERROR` с тем же текстом). Убрать параметр `nodata_period`. Типы в `cmd_http3` (аргумент `_quic_handshake`) и в функции, возвращающей `Any` вместо `str | None`, — без `type: ignore`.
- **Verification:** `pytest`, `translate-templates.py --check`, yamllint, mypy 1.13 и 2.3.1.

### U5. Версии и документация

- **Goal:** R6.
- **Files:** `scripts/externalscripts/web_check.py` (`__version__`), шаблон (версия), `CHANGELOG.md`, `README.md`, `README_EN.md`, `templates/web-service-by-itforprof/README.md`, `docs/architecture.md`, `scripts/tests/test_template_contract.py` (тест версии).
- **Verification:** локальные проверки зелёные.

### U6. Выкладка

- **Goal:** R7; Success Criteria.
- **Dependencies:** «да» владельца, затем U1–U5 слиты в main и опубликованы.
- **Approach:**
  1. Живая проверка AE4 на временном хосте (trapper с ответом `internal_error`, затем с `unsigned`, элемент DNSSEC с новой предобработкой; `trapper_hosts` задан, ошибки каждого `history.push` проверены).
  2. `install.sh` с `REF` на коммит main на всех 6 сборщиках, `self-test`, версия 2.2.5; в `/opt/web_check/data/cache` нет файлов, чей владелец не `zabbix`. Ручные запуски `web_check.py` — только `sudo -u zabbix`.
  3. Шаблон: пробное сравнение, снимок отключённых на хостах объектов, импорт `_ru.yaml`, возврат статусов, `check-template-preprocessing.py`, `recovery_mode`.
  4. Дедупликация WHOIS на обоих серверах.
  5. После следующего опроса WHOIS (до 1 часа): Success Criteria. На хосте-владельце затронутой группы ожидаемо откроются «Domain registrar changed» (WARNING) и «Domain name servers changed» (INFO): домен сменился с `msk.ru` на домен третьего уровня, вместе с ним регистратор и серверы имён. Сверить новые значения с ответом реестра и закрыть обе проблемы вручную (у обоих триггеров `manual_close`). Предупреждение о сроке домена не ожидается: срок затронутого домена больше порога `{$WEB_SERVICE.WHOIS.WARN_DAYS}`; если к выкладке он окажется в пределах порога, это верное срабатывание, а не регрессия.

---

## Verification Contract

| Проверка | Как | Когда |
|---|---|---|
| Тесты | `pytest -q` в `scripts/` | U1–U5 |
| Линт и формат | `ruff check .`, `ruff format --check .` | U1–U5 |
| Типы | `mypy --strict --ignore-missing-imports --python-version 3.11 externalscripts/web_check.py` в 1.13 и 2.3.1 | U4, U5 |
| YAML и русская сборка | yamllint по правилам `.github/workflows/yaml-validate.yml`, `translate-templates.py --check` | U4, U5 |
| Сборщики | `self-test`, версия 2.2.5 | U6 |
| Сервер | `configuration.importcompare`, `item.get`, `problem.get` | U6 |

---

## Definition of Done

- U1–U5: проверки зелёные, коммиты без AI-атрибуции, клиентских имён, IP и ID (в коде и тестах — `example.msk.ru` и подобные, не реальные хосты).
- U6 после «да» владельца, закончен при выполненных Success Criteria.
