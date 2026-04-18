## Co do zrobienia / pomysły na rozwój

To nie jest „roadmapa” pod inwestorów, tylko notatnik tego, co fajnie byłoby kiedyś dorobić w NetScoutX. Część rzeczy jest blisko, część to bardziej lista życzeń na spokojniejsze wieczory.

### Faza 1 – to, co już mniej więcej jest

- hybrydowy rekonesans (aktywny + pasywny) działa i daje sensowne wyniki,
- discovery hostów, TCP/UDP port scan, fingerprinting usług,
- analiza ARP z sensownymi anomaliami i risk scoringiem,
- pasywka: ARP, DHCP, mDNS, DNS, pierwsze podejście do TLS JA3,
- dwa CLI: interaktywny (`netscoutx`) i flagowy (`net-scout`),
- JSON + diffowanie raportów w czasie.

To jest „stan gry” – reszta poniżej to rzeczy, które chciałbym dokładać stopniowo.

### Faza 2 – dopieszczenie sieciowego „mięsa”

Kilka pomysłów, które chodzą po głowie:

- pasywny TLS JA3S – fingerprinting serwera po stronie TLS, żeby lepiej rozumieć, z kim hosty gadają,
- lepsze fingerprinting IoT – mieszanka mDNS/SSDP + OUI, żeby z pudełka lepiej rozpoznawać typowe zabawki w sieci,
- prosty graf komunikacji hostów („kto z kim gada i jak często”) – nawet zwykły wypluwany JSON wystarczy na start,
- możliwość podpięcia zewnętrznych feedów threat intel (na początku chociaż prosty lookup domen/IP),
- mały webowy dashboard – lekka nakładka, bez ambicji bycia pełnym SIEM-em,
- prosty system pluginów – żeby community mogło dorzucać swoje parsery / heurystyki bez forka projektu.

### Faza 3 – głębsze grzebanie w protokołach

Rzeczy bardziej czasochłonne, ale dające dużo sygnału:

- głębsze parsowanie SMB / RDP / SSH – wyciąganie dodatkowych informacji i potencjalnych problemów konfiguracyjnych,
- pełniejszy parser TLS – nie tylko JA3, ale szerszy widok handshake’u (np. ciekawe zestawy cipher suite’ów),
- kolejne decodery protokołów aplikacyjnych, tam gdzie ma to sens pod kątem bezpieczeństwa / asset visibility.

### Faza 4 – „pół‑enterprise”, ale po ludzku

Jeśli NetScoutX zacznie być używany na większych środowiskach, przyda się trochę „cięższej” infrastruktury:

- sensowne alertowanie (mail / webhook / coś prostego) na krytyczne anomalie,
- trwałe przechowywanie danych (SQLite / BadgerDB) pod historyczne analizy,
- live dashboard – podgląd, co się dzieje „tu i teraz” w sieci,
- zdalne agentów do rozproszonych sieci (kilka lokalizacji, jeden widok),
- rozproszony skan – koordynacja wielu instancji na większych, podzielonych adresacjach.

### Jak z tego korzystać

- jeśli rozwijasz projekt – potraktuj to jako checklistę „co mnie dziś najbardziej kręci”,
- jeśli wrzucasz PR – możesz się do tego odnieść („to jest krok w stronę fazy 2 / 3”),
- jeśli używasz NetScoutX w boju – dorzuć swoje pomysły, co by Ci realnie pomogło w codziennej pracy.

