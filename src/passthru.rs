use crate::{Error, IsoTp};
use j2534::{Channel, ConnectFlags, FilterId, PassThruMsg, Protocol, TxFlags};

struct PassThruFilter {
    id: FilterId,
    source_id: u32,
    destination_id: u32,
}

/// PassThru ISO-TP channel.
pub struct PassThruIsoTp<'ch> {
    channel: Channel<'ch>,
    timeout: u32,

    /// Flow control filter
    filter: Option<PassThruFilter>,
}

impl<'ch> PassThruIsoTp<'ch> {
    /// Creates a new ISO-TP channel from a device
    ///
    /// # Arguments
    /// - `device` - the PassThru device.
    /// - `baudrate` - the baudrate in Hertz used in the CAN layer.
    /// - `timeout` - the timeout in milliseconds for sending and receiving.
    pub fn new(
        device: &'ch j2534::Device,
        baudrate: u32,
        timeout: u32,
    ) -> j2534::Result<PassThruIsoTp<'ch>> {
        let channel = device.connect(Protocol::ISO15765, ConnectFlags::NONE, baudrate)?;
        Ok(PassThruIsoTp {
            channel,
            timeout,
            filter: None,
        })
    }

    /// Establishes the flow control filter
    pub fn set_filter(&mut self, source_id: u32, destination_id: u32) -> j2534::Result<()> {
        if let Some(ref filter) = self.filter {
            if filter.source_id == source_id && filter.destination_id == destination_id {
                return Ok(());
            }
            self.channel.stop_message_filter(filter.id)?;
        }

        // Create a filter allowing messages with destination ID to be received.
        let mask = PassThruMsg::new_isotp(0xFFFFFFFF, &[]).tx_flags(TxFlags::ISO15765_FRAME_PAD);
        let pattern =
            PassThruMsg::new_isotp(destination_id, &[]).tx_flags(TxFlags::ISO15765_FRAME_PAD);
        // Set flow control packet to use source ID
        let fc_pattern =
            PassThruMsg::new_isotp(source_id, &[]).tx_flags(TxFlags::ISO15765_FRAME_PAD);
        let id = self.channel.start_message_filter(
            j2534::FilterType::FlowControl,
            Some(&mask),
            Some(&pattern),
            Some(&fc_pattern),
        )?;

        self.filter = Some(PassThruFilter {
            id,
            source_id,
            destination_id,
        });
        Ok(())
    }
}

impl IsoTp for PassThruIsoTp<'_> {
    fn send_isotp(&mut self, id: u32, data: &[u8]) -> Result<(), Error> {
        self.set_filter(
            id,
            self.filter
                .as_ref()
                .map_or(id + 8, |filter| filter.destination_id), // Guess the destination ID
        )?;

        let message = PassThruMsg::new_isotp(id, data).tx_flags(TxFlags::ISO15765_FRAME_PAD);
        self.channel.write(&mut [message], self.timeout)?;
        Ok(())
    }

    fn read_isotp(&mut self, id: u32) -> Result<Vec<u8>, Error> {
        // Guess the desination ID
        self.set_filter(
            self.filter
                .as_ref()
                .map_or(id - 8, |filter| filter.source_id), // Guess the source ID
            id,
        )?;

        loop {
            let message = self.channel.read_once(self.timeout)?;
            if message.transmitted() || message.first_frame() {
                // Message has not been fully processed yet..
                continue;
            }
            if let Some((msg_id, data)) = message.isotp_message() {
                if id != msg_id {
                    continue;
                }
                return Ok(data.to_vec());
            }
        }
    }
}
