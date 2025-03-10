// DNS-Header-Struktur ist in ["RFC 1035 - 4.1.1"](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1) definiert.
#[derive(Debug)]
pub struct Header {
    // Hauptsächliche Rolle der Felder:
    //  1. Kennzeichne Typ der Nachricht.
    //  2. Kennzeichne Zustand der Nachricht.
    //  3. Kennzeichne Anzahl von "resource records" von jeweiligen Sektion der Nachricht.
    //  4. Und so weiter.
    // DNS-Nachrichten werden als rau binär-Daten übermittelt.
    // Serialisieren ist deshalb notwendig, Deserialisieren ebenso bei Emfang der Anfrage.
    // *Reihenfolge von Netzwerk-Byte ist "Big-Endian"(Abk. be) und dafür werden entsprechende Funktionen wie z. B. `u16::to_be_bytes()` sowie 'u16::from_be_bytes()' verwendet.
    pub id: u16,    // identifier
    pub qr: bool,   // 0 bedeutet Abfrage (auf E. Query), 1 heißt Antwort (auf E. Response)
    pub opcode: u8, // 0 heißt Standard-Abfrage (auf E. standard query). Eigentlich soll 4 Bit sein, jedoch wird u8 verwendet. Vermutlich weil es keinen primitiven `u4` gibt.
    pub aa: bool,   // Autoritaive Antwort
    pub tc: bool, // TrunCation: Merkmal dafür, ob die Nachricht geschnitten wurde, aufgrund der längeren Länge als "transmission channel"
    pub rd: bool, // Recursion Desire: Wenn gesezt, lässt die Abfrage rekursiv durchführen.
    pub ra: bool, // Recursion Available: Kennzeichnet, ob Unterstützung für rekursive Abfrage verfügbar auf Namen-Server ist.
    pub z: u8,    // Resesrviert für zukünftige Verwendung.
    pub rcode: u8, // Response Code:   0 -> Kein Fehler
    //                  1 -> Formatierungsfehler. Der Namen-Server konnte die Abfrage nicht verstehen.
    //                  2 -> Fehlschlag des Servers. Der Namen-Server konnte aufgrund des internen Problems die Abfrage nicht verarbeiten.
    //                  3 -> Namenfehler. Domain-Name-Referenz von der Abfrage besteht nicht. (Nur bei Anwort von authoritativem Namen-Server)
    //                  4 -> Nicht Implementiert. Der Namen-Server unterstützt Art der Abfrage nicht.
    //                  5 -> Verweigert. Der Namen-Server verweigert die angewiesene Operation, aufgrund von Richtlinie.
    //                  6-15 -> Reserviert für zukünftige Anwendungen.
    pub qdcount: u16, // Anzahl von "Entries"
    pub ancount: u16, // Anzahl von "resource records" in der Antwort-Sektion.
    pub nscount: u16, // Anzahl von "resource records" von Namen-Server in "the authority recors section".
    pub arcount: u16, // Anzahl von "resource Record" in zusätzlicher "records" Sektion.
}
