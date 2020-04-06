//! This example queries a VIN using a PassThru device

use obd::{IsoTp, PassThruIsoTp, Uds};

pub fn main() {
    // Get a list of interfaces
    let device = match j2534::drivers().unwrap().into_iter().next() {
        Some(device) => device,
        None => {
            println!("No J2534 interfaces found");
            return;
        }
    };

    println!("Opening interface '{}'", device.name);
    let i = j2534::Interface::new(&device.path).unwrap();
    // Open any connected device
    let d = i.open_any().unwrap();
    // Get version information
    let version_info = d.read_version().unwrap();
    println!("{:#?}", version_info);

    let mut isotp = PassThruIsoTp::new(&d, 500000, 1000).unwrap();
    // isotp.set_filter(0x7e0, 0x7e8);
    println!("VIN: {}", isotp.query_vin(0x7e0).unwrap());

    // Query trouble codes
    for code in isotp.query_trouble_codes(0x7e0).unwrap().iter() {
        println!("{}", code);
    }
}
