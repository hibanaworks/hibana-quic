//! Reconstructed bounded long-packet protection; fresh validation required.
use super::*;
use crate::{crypto::PacketKey,packet::{self,Frame,LongHeader,LongType}};

/// A successful prefix has already consumed actual Initial retirement evidence.
/// Handshake keys remain owned here until authenticated confirmation.
pub struct ReceiveContinuation<'scope,const P:usize>{
 pub initial:Option<ReceivePacketKey<'scope>>,pub handshake:ReceivePacketKey<'scope>,pub application:ApplicationReadKeys<'scope>,pub integrity:IntegrityBudget,pub finished:Finished<'scope,P>,pub largest_received:[Option<u64>;2],pub(super) peer:ConnectionId,
}
impl<'scope,const P:usize> ReceiveContinuation<'scope,P>{
 pub fn peer_connection_id(&self)->&[u8]{self.peer.bytes()}
 pub fn into_parts(self)->(ReceiveMaterial<'scope>,Finished<'scope,P>){(ReceiveMaterial{initial:self.initial,handshake:self.handshake,application:self.application,integrity:self.integrity,largest_received:self.largest_received,peer:self.peer},self.finished)}
}
pub struct ReceiveMaterial<'scope>{pub initial:Option<ReceivePacketKey<'scope>>,pub handshake:ReceivePacketKey<'scope>,pub application:ApplicationReadKeys<'scope>,pub integrity:IntegrityBudget,pub largest_received:[Option<u64>;2],pub(super) peer:ConnectionId}
impl ReceiveMaterial<'_>{pub fn peer_connection_id(&self)->&[u8]{self.peer.bytes()}}
/// Initial is absent after the finite prefix retirement join; unacknowledged
/// Handshake flights remain in the same recovery book for the application roles.
pub struct TransmitContinuation<'scope>{pub initial:Option<PacketKey>,pub handshake:TransmitPacketKey<'scope>,pub application:ApplicationWriteKeys<'scope>}
pub(crate) struct Datagram<'book,const N:usize>{pub(super) sealed:Bytes<N>,pub(super) reservation:recovery::Reservation<'book>,pub(super) acknowledgment:Option<recovery::AckSnapshot<'book>>}
pub(super) struct Bytes<const N:usize>{data:[u8;N],len:usize}
impl<const N:usize> Bytes<N>{pub fn bytes(&self)->&[u8]{&self.data[..self.len]}}
impl<const N:usize> Drop for Bytes<N>{fn drop(&mut self){use zeroize::Zeroize;self.data.zeroize();}}
pub(super) struct WriteKeys<'initial,'scope>{pub initial:&'initial super::initial::Keys<'scope>,pub handshake:Option<TransmitPacketKey<'scope>>,pub application:Option<ApplicationWriteKeys<'scope>>}
pub(super) struct PlainPacket<const N:usize>{bytes:Bytes<N>,header_len:usize,plaintext_len:usize,level:Level,padded:bool}
impl<const N:usize> PlainPacket<N>{
 pub fn new(config:Config<'_>,peer:&ConnectionId,level:Level,frame:Frame<'_>)->Result<Self,Error>{
  let mut plain=[0u8;N];let mut plen=packet::encode_frame(&frame,&mut plain)?;let encoded_len=plen;
  let kind=match level{Level::Initial=>LongType::Initial,Level::Handshake=>LongType::Handshake,_=>return Err(Error::UnsupportedLevel)};
  let mut bytes=Bytes{data:[0;N],len:0};let header=LongHeader{kind,destination_id:peer.bytes(),source_id:config.local_connection_id,token:&[],packet_number:0,packet_number_len:4};let mut hlen=packet::encode_long_header(&header,plen+16,&mut bytes.data)?;
  if level==Level::Initial{loop{let padded_len=encoded_len.max(1200usize.saturating_sub(hlen+16));if padded_len==plen{break;}plen=padded_len;if plen>N{return Err(Error::Capacity);}hlen=packet::encode_long_header(&header,plen+16,&mut bytes.data)?;}}
  let len=hlen+plen+16;if len>N{return Err(Error::Capacity);}bytes.data[hlen..hlen+plen].copy_from_slice(&plain[..plen]);bytes.len=len;
  Ok(Self{bytes,header_len:hlen,plaintext_len:plen,level,padded:plen>encoded_len||matches!(frame,Frame::Padding{length}if length!=0)})
 }
 pub fn len(&self)->usize{self.bytes.len}
 pub fn padded(&self)->bool{self.padded}
 pub fn seal<'book>(self,keys:&mut WriteKeys<'_,'_>,reservation:recovery::Reservation<'book>,acknowledgment:Option<recovery::AckSnapshot<'book>>)->Result<Datagram<'book,N>,(Error,recovery::Reservation<'book>)>{
  match self.level{Level::Initial=>keys.initial.seal(self,reservation,acknowledgment),Level::Handshake=>match keys.handshake.as_mut(){Some(key)=>self.seal_handshake(key,reservation,acknowledgment),None=>Err((Error::UnsupportedLevel,reservation))},_=>Err((Error::UnsupportedLevel,reservation))}
 }
 pub fn seal_initial<'book>(self,key:&mut PacketKey,reservation:recovery::Reservation<'book>,acknowledgment:Option<recovery::AckSnapshot<'book>>)->Result<Datagram<'book,N>,(Error,recovery::Reservation<'book>)>{self.seal_borrowed(BorrowedWriteKey::Initial(key),reservation,acknowledgment)}
 pub fn seal_handshake<'book>(self,key:&mut TransmitPacketKey<'_>,reservation:recovery::Reservation<'book>,acknowledgment:Option<recovery::AckSnapshot<'book>>)->Result<Datagram<'book,N>,(Error,recovery::Reservation<'book>)>{self.seal_borrowed(BorrowedWriteKey::Handshake(key),reservation,acknowledgment)}
 fn seal_borrowed<'book>(mut self,mut key:BorrowedWriteKey<'_,'_>,reservation:recovery::Reservation<'book>,acknowledgment:Option<recovery::AckSnapshot<'book>>)->Result<Datagram<'book,N>,(Error,recovery::Reservation<'book>)>{
  let mut seal=||->Result<(),Error>{
   let expected=match self.level{Level::Initial=>crate::accounting::PacketNumberSpace::Initial,Level::Handshake=>crate::accounting::PacketNumberSpace::Handshake,_=>return Err(Error::UnsupportedLevel)};
   if reservation.bytes()!=self.bytes.len as u64||reservation.packet().space!=expected{return Err(Error::Binding);}
   if !reservation.matches_plaintext(&self.bytes.data[self.header_len..self.header_len+self.plaintext_len])?{return Err(Error::Binding);}
   match &key{BorrowedWriteKey::Initial(k)if self.level==Level::Initial&&k.kind()==crypto::KeyKind::Initial=>{},BorrowedWriteKey::Handshake(k)if self.level==Level::Handshake&&k.kind()==crypto::KeyKind::Handshake&&core::ptr::eq(k.scope(),reservation.scope())=>{},_=>return Err(Error::Binding)}
   let pn=reservation.packet().value;self.bytes.data[self.header_len-4..self.header_len].copy_from_slice(&pn.to_be_bytes()[4..]);let(header,payload)=self.bytes.data.split_at_mut(self.header_len);
   let len=match &mut key{BorrowedWriteKey::Initial(k)=>k.seal(pn,header,payload,self.plaintext_len)?,BorrowedWriteKey::Handshake(k)=>k.seal(pn,header,payload,self.plaintext_len)?};
   if self.header_len+len!=self.bytes.len{return Err(Error::Binding);}
   let sample:&[u8;16]=self.bytes.data[self.header_len..self.header_len+16].try_into().map_err(|_|Error::Capacity)?;
   let mask=match &key{BorrowedWriteKey::Initial(k)=>k.header_mask(sample)?,BorrowedWriteKey::Handshake(k)=>k.header_mask(sample)?};self.bytes.data[0]^=mask[0]&0xf;for i in 0..4{self.bytes.data[self.header_len-4+i]^=mask[i+1];}Ok(())
  };
  match seal(){Ok(())=>Ok(Datagram{sealed:self.bytes,reservation,acknowledgment}),Err(e)=>Err((e,reservation))}
 }
}
enum BorrowedWriteKey<'key,'scope>{Initial(&'key mut PacketKey),Handshake(&'key mut TransmitPacketKey<'scope>)}
