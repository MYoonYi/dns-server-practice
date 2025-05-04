use std::{error::Error, fmt::format};

use thiserror::Error;

// DNS-Header-Struktur ist in ["RFC 1035 - 4.1.1"](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1) definiert.
#[derive(Debug, Default)]
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

impl Header {
    const SIZE_OF_HEADER: usize = 12;

    pub fn as_bytes(&self) -> Vec<u8> {
        // 'with_capacity()' erzeugt einen Vektor mit Kapazität der Größe von ihrem Argument und mit Länge von 0.
        // - Kapazität heißt, wie vielen Arbeitsspeicher schon allokiert ist und Länge heißt, wie viele Daten schon drin gespeichert sind.
        let mut data_being_serialized = Vec::with_capacity(Header::SIZE_OF_HEADER);
        // id mit 16 Bits
        // `extend_from_slice()`: Da es deutlich geschrieben ist, dass die Methode irgendwann überholt werden wird,
        // habe ich recherchiert, warum das Tutorial diese Methode überhaupt verwendet.
        // Es scheint, sie ist für den Typ von Slice optimiert.
        data_being_serialized.extend_from_slice(&self.id.to_be_bytes());
        {
            // qr verarbeiten. Seine Daten soll an größter Bitstelle von einem Byte liegen.
            let qr = (self.qr as u16) << 15;
            // Weiter
            let opcode = (self.opcode as u16) << 11;
            let aa = (self.aa as u16) << 10;
            let tc = (self.tc as u16) << 9;
            let rd = (self.rd as u16) << 8;
            let ra = (self.ra as u16) << 7;
            let z = (self.z as u16) << 4;
            let rcode = self.rcode as u16;
            let second_block_of_packet = qr | opcode | aa | tc | rd | ra | z | rcode;
            data_being_serialized.extend_from_slice(&second_block_of_packet.to_be_bytes());
        }
        data_being_serialized.extend_from_slice(&self.qdcount.to_be_bytes());
        data_being_serialized.extend_from_slice(&self.ancount.to_be_bytes());
        data_being_serialized.extend_from_slice(&self.nscount.to_be_bytes());
        data_being_serialized.extend_from_slice(&self.arcount.to_be_bytes());

        data_being_serialized
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DnsSerdeError> {
        use DnsSerdeError::*;

        if data.len() < Header::SIZE_OF_HEADER {
            return Err(DeserializationFailed(format!("Bytes too little: {:?}", data.len().to_string())));
        }

        let parse_bits = |byte, start_position_of_data, lenth_of_data| {
            let left_shift_for_removing = start_position_of_data - 1;
            let right_shift_for_correctly_placing = 7 - (lenth_of_data - 1);
            (byte << left_shift_for_removing) >> right_shift_for_correctly_placing
        };
        let as_bool = |byte, position_in_the_byte| parse_bits(byte, position_in_the_byte, 1) > 0;
        let merge_a_pair_of_bytes_in_u16 = |buffer: &mut u16, byte, is_lower_byte| {
            let data: u16 = if is_lower_byte {
                byte as u16
            } else {
                (byte as u16) << 8
            };
            *buffer |= data;
        };

        let mut data_being_deserialized = Header::default();

        data.iter()
            .enumerate()
            .for_each(|(i, &one_byte_of_data)| match i {
                2 => {
                    data_being_deserialized.qr = as_bool(one_byte_of_data, 1);
                    data_being_deserialized.opcode = parse_bits(one_byte_of_data, 2, 4);
                    data_being_deserialized.aa = as_bool(one_byte_of_data, 6);
                    data_being_deserialized.tc = as_bool(one_byte_of_data, 7);
                    data_being_deserialized.rd = as_bool(one_byte_of_data, 8);
                }
                3 => {
                    data_being_deserialized.ra = as_bool(one_byte_of_data, 1);
                    data_being_deserialized.z = parse_bits(one_byte_of_data, 2, 3);
                    data_being_deserialized.rcode = parse_bits(one_byte_of_data, 5, 4);
                }
                ind if (0..=1).chain(4..=11).any(|nth| ind == nth) => {
                    let deserializing_buffer = match ind {
                        0..=1 => &mut data_being_deserialized.id,
                        4..=5 => &mut data_being_deserialized.qdcount,
                        6..=7 => &mut data_being_deserialized.ancount,
                        8..=9 => &mut data_being_deserialized.nscount,
                        10..=11 => &mut data_being_deserialized.arcount,
                        _ => panic!("Compiler can't recognize the guard clause. However, this here should never be executed! Something in the implementation is wrong."),
                    };
                    
                    let is_lower_byte = (i % 2) == 1;
                    merge_a_pair_of_bytes_in_u16(
                        deserializing_buffer,
                        one_byte_of_data,
                        is_lower_byte,
                    );
                }
                _ => (),
            });

        Ok(data_being_deserialized)
    }
}

#[derive(Debug, Error)]
pub enum DnsSerdeError {
    #[error("Too few Bytes has been given for being converted into DNS Header")]
    DeserializationFailed(String),
}
