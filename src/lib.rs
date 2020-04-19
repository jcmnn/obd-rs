#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[cfg(feature = "passthru")]
    #[error(transparent)]
    PassThru(#[from] j2534::Error),

    #[error("empty UDS response")]
    EmptyResponse,

    #[error("negative response: {0:?}")]
    NegativeResponse(Option<u8>),

    #[error("invalid response SID {0:X}")]
    InvalidResponseSID(u8),

    #[error("invalid response PID")]
    InvalidResponsePid,
}

#[cfg(feature = "passthru")]
pub mod passthru;

#[cfg(feature = "passthru")]
pub use passthru::PassThruIsoTp;
use std::convert::TryInto;
use std::fmt;
use std::fmt::{Display, Formatter};

/// ISO 15765 (ISO-TP)
pub trait IsoTp {
    /// Sends an ISO-TP packet.
    ///
    /// # Arguments
    /// - `id` - the CAN arbitration ID.
    /// - `data` - The packet payload. Must not be larger than 4095 bytes.
    fn send_isotp(&mut self, id: u32, data: &[u8]) -> Result<(), Error>;

    /// Receives an ISO-TP packet.
    ///
    /// # Arguments
    /// - `id` - the CAN arbitration ID to listen for.
    fn read_isotp(&mut self, id: u32) -> Result<Vec<u8>, Error>;

    fn query_isotp(&mut self, id: u32, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.send_isotp(id, data)?;
        self.read_isotp(id + 8)
    }
}

// Request SIDs
const UDS_REQ_SESSION: u8 = 0x10;
const UDS_REQ_SECURITY: u8 = 0x27;
const UDS_REQ_READMEM: u8 = 0x23;
const UDS_REQ_REQUESTDOWNLOAD: u8 = 0x34;
const UDS_REQ_REQUESTUPLOAD: u8 = 0x35;
const UDS_REQ_TRANSFERDATA: u8 = 0x36;
const UDS_REQ_READBYID: u8 = 0x22;

const UDS_RES_NEGATIVE: u8 = 0x7F;

/* Negative response codes */
// requestCorrectlyReceivedResponsePending
const UDS_NRES_RCRRP: u8 = 0x78;

/// Diagnostic trouble code
pub struct DTC([u8; 2]);

const DTC_MODULES: [char; 4] = ['P', 'C', 'B', 'U'];
const DTC_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

impl Display for DTC {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            DTC_MODULES[(self.0[0] >> 6) as usize],
            (b'0' + ((self.0[0] >> 4) & 0x3)) as char,
            DTC_CHARS[(self.0[0] & 0xF) as usize],
            DTC_CHARS[(self.0[1] >> 4) as usize],
            DTC_CHARS[(self.0[1] & 0xF) as usize]
        )
    }
}

/// Unified diagnostic services. This is the standard protocol
/// used for reading PIDs and communicating with ECUs.
pub trait Uds {
    fn query_uds(
        &mut self,
        arbitration_id: u32,
        request_sid: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Sends a query for a VIN (vehicle identification number).
    fn query_vin(&mut self, arbitration_id: u32) -> Result<String, Error> {
        let data = self.query_uds(arbitration_id, 0x9, &[0x2])?;
        match data.first() {
            Some(pid) if *pid == 0x2 => (),
            _ => return Err(Error::InvalidResponsePid),
        }

        if let Some(pad) = data.iter().skip(1).position(|i| *i != 0 && *i != 1) {
            Ok(String::from_utf8_lossy(&data[pad + 1..]).to_string())
        } else {
            Ok(String::new())
        }
    }

    /// Queries the list of diagnostic trouble codes
    fn query_trouble_codes(&mut self, arbitration_id: u32) -> Result<Vec<DTC>, Error> {
        let response = self.query_uds(arbitration_id, 0x03, &[])?;
        if let Some(_size) = response.first() {
            Ok((&response[1..])
                .chunks(2)
                .filter_map(|c| c.try_into().ok())
                .map(|c| DTC(c))
                .collect())
        } else {
            Err(Error::EmptyResponse)
        }
    }
}

impl<I: IsoTp> Uds for I {
    fn query_uds(
        &mut self,
        arbitration_id: u32,
        request_sid: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Build the request
        let mut request = Vec::with_capacity(data.len() + 1);
        request.push(request_sid);
        request.extend_from_slice(data);

        loop {
            let mut response = self.query_isotp(arbitration_id, &request)?;

            let response_sid = match response.first() {
                Some(sid) => *sid,
                None => return Err(Error::EmptyResponse),
            };

            // Check the response SID
            if response_sid == UDS_RES_NEGATIVE {
                // Check negative response code
                let code = response.get(1).map(|c| *c);
                if code == Some(UDS_NRES_RCRRP) {
                    // The transmitter is still processing; continue waiting.
                    continue;
                }
                return Err(Error::NegativeResponse(response.get(2).map(|c| *c)));
            }

            if response_sid != request_sid + 0x40 {
                return Err(Error::InvalidResponseSID(response_sid));
            }

            response.remove(0);
            return Ok(response);
        }
    }
}
