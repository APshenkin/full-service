//! Public Address base58 encoding and decoding.

use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;

pub fn b58_encode_public_address(public_address: &PublicAddress) -> Result<String, String> {
    let mut wrapper = PrintableWrapper::new();
    wrapper.set_public_address(public_address.into());
    Ok(wrapper.b58_encode().map_err(|err| format!("Error on encode_public_address: {:?}", err))?)
}

pub fn b58_decode_public_address(public_address_b58_code: &str) -> Result<PublicAddress, String> {
    let wrapper = PrintableWrapper::b58_decode(public_address_b58_code.to_string())
        .map_err(|err| format!("Error on decode_public_address: {:?}", err))?;

    let public_address_proto = if wrapper.has_public_address() {
        wrapper.get_public_address()
    } else {
        return Err("No Public Address".parse().unwrap());
    };

    Ok(PublicAddress::try_from(public_address_proto)
        .map_err(|err| format!("Error on decode_public_address: {:?}", err))?)
}
