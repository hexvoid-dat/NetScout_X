# NetScoutX Architecture

To nie jest korpo-diagram UML, tylko krótki opis tego, jak NetScoutX jest złożony pod spodem tak, żeby dało się go rozwijać bez bólu głowy.

NetScoutX działa jako hybrydowy analizator sieci. W przeciwieństwie do klasycznych skanerów, które jadą tylko aktywnym probingiem, tutaj aktywny skan jest spięty z podsłuchem ruchu. Dzięki temu dostajesz pełniejszy obraz tego, co faktycznie żyje w sieci i jak się zachowuje.

## High-Level Overview

W dużym skrócie, cały system opiera się na dwóch silnikach, które karmią jeden pipeline analityczny:

1. **Active Engine (`internal/scanner`)** – skan portów TCP/UDP, proste OS fingerprinting po TTL, bannery usług itp.
2. **Passive Engine (`internal/passive`)** – `libpcap` + `gopacket` podsłuchują lokalny ruch. Hosty wykrywane są na podstawie ARP, DHCP, mDNS i DNS, bez generowania dodatkowego hałasu w sieci.

### The Pipeline

Przepływ danych jest celowo prosty:
1.  **Discovery**: Quick TCP/ARP sweep to find "alive" hosts.
2.  **Enrichment**: Passive collection runs in parallel to catch devices that don't respond to active probes.
3.  **Active Scan**: Deep-dive into open ports and service versions.
4.  **Merge**: The `internal/merge` package correlates active and passive data (primarily using MAC addresses as the stable identifier).
5.  **Risk Analysis**: Final pass to calculate a risk score based on open ports, detected vulnerabilities, and behavioral anomalies (like ARP spoofing or suspicious DNS patterns).

## Core Components

### Active Probing

Większość „ciężkiej roboty” przy aktywnym skanowaniu siedzi w `internal/scanner`. Port scan jest zrobiony na worker poolu – tak, żeby było szybko, ale bez palenia limitów systemowych. OS guessing to zlepek heurystyk (TTL + bannery), który ma dać sensowną podpowiedź, a nie obietnicę stuprocentowej dokładności.

### Passive Observation

Silnik pasywny stoi na `gopacket` i jest zaprojektowany tak, żeby był jak najmniej inwazyjny. Słuchamy głównie broadcastów (DHCP, mDNS, ARP), z których da się wyciągnąć:

* producenta urządzenia (OUI),
* hostname,
* ogłaszane usługi.

To pozwala zidentyfikować sporo sprzętu, nawet jeśli host ma dość agresywny firewall od strony portów.

### Risk Scoring (`internal/scanner/risk.go`)

Zamiast tylko wypisać listę portów, liczymy wynik 0–100. Nie jest to żadna „oficjalna” metryka, tylko heurystyka sklejona z kilku źródeł:

* niebezpieczne / stare protokoły (Telnet, FTP itd.),
* dopasowane podatności z lokalnego „mini-vulnDB”,
* anomalie sieciowe (konflikty IP, „greedy” MAC),
* sygnały z pasywki (DNS, JA3, mDNS, rogue DHCP).

Kod w `risk.go` jest zorganizowany tak, żeby dokładanie kolejnych reguł było możliwie mało bolesne.

## Project Structure

Najważniejsze katalogi:

* `cmd/` – entrypointy do standardowego CLI i interaktywnego TUI.
* `internal/scanner/` – discovery, skany, ARP i risk score.
* `internal/passive/` – podsłuch i parsery protokołów.
* `internal/merge/` – logika łączenia danych aktywnych i pasywnych.
* `internal/report/` – składanie JSON-a i wyjścia tekstowego.

Jeśli chcesz coś zmienić w przepływie danych, zazwyczaj dotykasz dwóch miejsc: `scanner`/`passive` oraz `merge`.

## Design Decisions

Kilka decyzji projektowych, które przewijają się w całym kodzie:

* **Concurrency** – goroutine’y i kanały wszędzie tam, gdzie ma to sens. Port scan działa na kontrolowanym worker poolu, pasywka ma osobne sniffery na interfejsach.
* **Stability** – MAC to „źródło prawdy” o tożsamości hosta. IP potrafi zmieniać się często (DHCP, VPN), MAC zwykle nie.
* **Portability** – jeśli nie ma uprawnień do `libpcap` / raw socketów, tool powinien zejść do prostszego discovery po TCP, a nie wybuchać z hukiem.

Trzymanie się tych założeń ułatwia dokładanie kolejnych funkcji bez wprowadzania chaosu w zachowaniu narzędzia.
