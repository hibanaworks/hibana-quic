//! WRITER: consume headers, body chunks and trailers before acknowledging completion.
use crate::http3::message::{Error, Exchange, Result, global::*};
use crate::io::RandomAccess;
use core::cell::RefCell;
use hibana::Endpoint;
pub async fn run(
    endpoint: &mut Endpoint<'_, WRITER>,
    file: &impl RandomAccess,
    exchange: &Exchange,
    written: &RefCell<u64>,
) -> Result<()> {
    let expected = loop {
        let offered = endpoint.offer().await.map_err(Error::from)?;
        match offered.label() {
            1 => {
                offered.recv::<Information>().await.map_err(Error::from)?;
                let fields = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing informational fields")?;
                if fields.content_length.is_some() {
                    return Err("informational content-length".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
            }
            2 => {
                offered.recv::<Headers>().await.map_err(Error::from)?;
                let fields = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing response fields")?;
                if fields.status != Some(200) {
                    return Err("download response was not 200".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
                break fields.content_length;
            }
            _ => return Err("unexpected response header continuation".into()),
        }
    };
    let mut offset = 0u64;
    loop {
        let offered = endpoint.offer().await.map_err(Error::from)?;
        match offered.label() {
            4 => {
                let count = usize::try_from(offered.recv::<Data>().await.map_err(Error::from)?)
                    .map_err(Error::from)?;
                {
                    let bytes = exchange.bytes.borrow();
                    file.write_all_at(bytes.get(..count).ok_or("body chunk capacity")?, offset)
                        .map_err(Error::from)?;
                }
                offset = offset
                    .checked_add(count as u64)
                    .ok_or("body length overflow")?;
                if expected.is_some_and(|length| offset > length) {
                    return Err("body exceeds content-length".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
            }
            5 => {
                offered.recv::<BodyEnd>().await.map_err(Error::from)?;
                break;
            }
            _ => return Err("unexpected response body continuation".into()),
        }
    }
    let offered = endpoint.offer().await.map_err(Error::from)?;
    match offered.label() {
        6 => {
            offered.recv::<Trailers>().await.map_err(Error::from)?;
            let fields = exchange
                .fields
                .borrow_mut()
                .take()
                .ok_or("missing trailers")?;
            if fields.has_pseudo() || fields.content_length.is_some() {
                return Err("invalid response trailers".into());
            }
            endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
        }
        7 => {
            offered.recv::<NoTrailers>().await.map_err(Error::from)?;
        }
        _ => return Err("unexpected response trailer continuation".into()),
    }
    endpoint.recv::<End>().await.map_err(Error::from)?;
    if expected.is_some_and(|length| length != offset) {
        return Err("body differs from content-length".into());
    }
    file.set_len(offset).map_err(Error::from)?;
    *written.borrow_mut() = offset;
    endpoint.send::<Done>(&()).await.map_err(Error::from)?;
    Ok(())
}
