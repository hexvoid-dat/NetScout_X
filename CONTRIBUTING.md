# Contributing to NetScoutX

Ten plik ma być dla ludzi, którzy naprawdę chcą pomacać kod, a nie dla bota od compliance. Jeśli masz ochotę dorzucić coś do NetScoutX – super, poniżej parę prostych zasad, żeby wszystkim żyło się łatwiej.

## Jak możesz pomóc

Opcji jest sporo:

- zgłaszanie bugów,
- pomysły na funkcje / usprawnienia,
- poprawki w docsach,
- większe zmiany w kodzie (heurystyki, parsery, UX w CLI).

### 1. Zgłaszanie bugów

Jeśli coś się wysypało albo zachowuje się dziwnie:

- zerknij najpierw w istniejące issue na GitHubie – możliwe, że ktoś już to zauważył,
- jeśli zakładasz nowe issue, wrzuć:
  - krótki opis „co miało być vs co wyszło”,
  - kroki do odtworzenia,
  - system, wersja Go,
  - fragment logów / stack trace, jeśli jest.

Im mniej muszę zgadywać, tym szybciej da się to ogarnąć.

### 2. Sugestie funkcji / usprawnień

Masz pomysł na coś, co realnie pomogłoby Ci w pracy z siecią – wrzuć issue jako „feature request”.

Najlepiej opisać:

- w jakim scenariuszu to ma pomagać (homelab, korpo, audyt, DFIR),
- jakiej informacji obecnie Ci brakuje,
- czy to ma być bardziej „jednorazowy raport”, czy coś pod dłuższy monitoring.

Spora część pomysłów z `codozrobienia.md` właśnie tak powstała.

### 3. Kontrybucje w kodzie

Jeśli chcesz grzebać w kodzie, sensowny flow jest taki:

#### a. Środowisko dev

1. forknij repo na GitHubie,
2. sklonuj swojego forka:

   ```bash
   git clone https://github.com/YOUR_USERNAME/net-scout.git
   cd net-scout
   ```

3. doinstaluj zależności:

   ```bash
   go mod tidy
   ```

4. zadbaj o `libpcap` (szczegóły są też w `README.md` / `INSTALL.md`):
   - Ubuntu/Debian: `sudo apt-get install libpcap-dev`
   - macOS: `brew install libpcap`

#### b. Gałęzie

Na `main` nie pchamy rzeczy wprost.

Standardowo:

```bash
git checkout -b feature/nazwa-funkcji main
# albo
git checkout -b bugfix/opis-buga main
```

Nazwa brancha nie musi być perfekcyjna, ale niech coś mówi.

#### c. Styl kodu

Bez zaskoczeń:

- standardowe idiomy Go,
- zawsze `gofmt` (`go fmt ./...`),
- dobrze, jeśli przed PR-em przelecisz `go vet ./...` (i ewentualnie `golint`, jeśli go używasz),
- komentarze tylko tam, gdzie logika faktycznie jest mniej oczywista.

#### d. Testy

Przed PR-em:

```bash
go test ./...
```

Dodajesz nowy parser / heurystykę – dorzuć do tego testy. Dla pasywki często oznacza to:

- `.pcap` w `internal/passive/testdata/`,
- test w `internal/passive/passive_test.go`, który przegryzie ten plik.

#### e. Commity

Lepiej kilka mniejszych, czytelnych commitów niż jeden „big bang”.

Przykładowy commit message:

```text
feat: add passive DHCP server detection

Adds parsing of DHCP OFFER/ACK packets to identify DHCP servers.
Introduces heuristic to flag potential rogue servers based on OUI
and presence of multiple servers on the same segment.
```

Nie musi być idealnie, ale fajnie, jeśli z message’a da się zrozumieć „co i po co”.

#### f. Pull Request

1. wypchnij swoją gałąź:

   ```bash
   git push origin feature/nazwa-funkcji
   ```

2. otwórz PR do `main` w oryginalnym repo,
3. w opisie PR-a:
   - podepnij issue (jeśli istnieje) typu `Closes #123`,
   - opisz krótko, co zostało zmienione,
   - napisz, jak to testowałeś (ręcznie / `go test`, e2e itd.),
   - jeśli PR dotyka UX w CLI, screen / wycinek outputu bardzo pomaga.

### 4. Nowe parsery protokołów (pasywka)

Jeśli dorzucasz nowy moduł do `internal/passive`:

1. nowy plik, np. `parser_mojprot.go` – implementacja parsera,
2. update w `engine.go` – dispatch w `dispatchPacket`, który przekieruje odpowiednie pakiety do nowego parsera,
3. ewentualna rozbudowa modeli w `model.go` (`passive.Host`, `AnalysisResult`),
4. heurystyki pod ten protokół w `heuristics.go` (jeśli mają sens),
5. `.pcap` w `internal/passive/testdata/` + test w `internal/passive/passive_test.go`.

## Code of Conduct

Na poziomie „jak się zachowujemy”, obowiązuje prosty deal:

- szanujemy czas innych (konkret, nie ściana tekstu bez treści),
- feedback w kodzie bez wycieczek osobistych,
- zero toksycznych zagrywek.

Formalny [Code of Conduct](CODE_OF_CONDUCT.md) nadal obowiązuje, jeśli ktoś lubi mieć to w wersji „oficjalnej”.

---
