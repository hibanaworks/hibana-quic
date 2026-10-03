//! Reconstructed from retained author tool calls after executor replacement.
//! Last pre-loss local implementation; not newly validated.
use super::*;
use super::protocol as p;
use super::wire::{WriteKeys,PlainPacket};
use crate::{crypto::directional::ApplicationKeyScope,packet::{self,Frame,FrameIter,Header,LongType,PacketIter,ParseLimits},parameters::{Parameters,Peer}};
use core::{future::Future,pin::pin};
use hibana::g::Message;
fn check(actual:u64,expected:u64)->Result<(),Error>{if actual==expected{Ok(())}else{Err(Error::Binding)}}
struct ReceiveWire<'scope,'buf,const N:usize>{initial:ReceivePacketKey<'scope>,handshake:Option<ReceivePacketKey<'scope>>,integrity:IntegrityBudget,reassembly:[CryptoBuffer<'buf>;2],largest:[Option<u64>;2],datagram:[u8;N],len:usize,offset:usize,opened:[u8;N],peer_learned:bool}
impl<'scope,const N:usize> ReceiveWire<'scope,'_,N>{
 fn ready(&self,scope:&'scope ApplicationKeyScope)->Result<Option<(CryptoInput<'scope,N>,usize,usize)>,Error>{for index in 0..2{let(first,_)=self.reassembly[index].ready();if !first.is_empty(){let count=first.len().min(N);return Ok(Some((CryptoInput::new(scope,if index==0{Level::Initial}else{Level::Handshake},self.reassembly[index].consumed(),&first[..count])?,index,count)));}}Ok(None)}
 async fn packet<const P:usize>(&mut self,io:&mut impl DatagramRx,slots:&Storage<'scope,'_,N,P>,config:Config<'_>,book:&mut recovery::Rx<'_,'scope,N>,clock:&impl Clock,may_finish:bool)->Result<bool,Error>{
  if self.offset>=self.len{
   if may_finish&&slots.schedule.transmit_done.get(){return Ok(false);}
   let received={let mut read=pin!(io.receive(&mut self.datagram));poll_fn(|cx|{if may_finish{slots.schedule.register(0,cx.waker());if slots.schedule.transmit_done.get(){return Poll::Ready(Ok(None));}}read.as_mut().poll(cx).map(|result|result.map(Some))}).await?};
   let Some(len)=received else{return Ok(false);};if len>N{return Err(Error::Capacity);}self.len=len;self.offset=0;book.received_datagram(len as u64)?;slots.schedule.changed()?;
  }
  let untrusted=match PacketIter::new(&self.datagram[self.offset..self.len],config.local_connection_id.len(),1)?.next(){Some(Ok(packet))=>packet,_=>{self.offset=self.len;return Ok(true);}};
  self.offset+=untrusted.bytes.len();
  let(level,index,pn_offset,source_id)=match untrusted.header{Header::Long{kind,destination_id,source_id,packet_number_offset,..}=>{if destination_id!=config.local_connection_id&&!(config.side==Side::Server&&kind==LongType::Initial&&destination_id==config.original_destination_id){return Ok(true);}match kind{LongType::Initial if config.side!=Side::Server||self.len>=1200=>(Level::Initial,0,packet_number_offset,source_id),LongType::Handshake=>(Level::Handshake,1,packet_number_offset,source_id),_=>return Ok(true)}},_=>return Ok(true)};
  let key=if index==0{&self.initial}else{match self.handshake.as_ref(){Some(key)=>key,None=>return Ok(true)}};
  self.opened[..untrusted.bytes.len()].copy_from_slice(untrusted.bytes);let bytes=&mut self.opened[..untrusted.bytes.len()];
  let pn_len=match key.unprotect_header(bytes,pn_offset){Ok(len)=>len,Err(_)=>return Ok(true)};
  let(truncated,_)=packet::decode_truncated_packet_number(bytes[0],&bytes[pn_offset..])?;let pn=packet::restore_packet_number(truncated,pn_len as u8,self.largest[index])?;
  let(header,payload)=bytes.split_at_mut(pn_offset+pn_len);let authentication=match key.open_authenticated(pn,header,payload,&mut self.integrity){Ok(receipt)=>receipt,Err(crypto::Error::AuthenticationFailed)=>return Ok(true),Err(error)=>return Err(error.into())};
  packet::validate_reserved_bits(header[0])?;let plaintext=&payload[..authentication.len()];
  if self.peer_learned||config.side==Side::Server{if slots.peer.borrow().bytes()!=source_id{return Err(Error::Binding);}}else{*slots.peer.borrow_mut()=ConnectionId::new(source_id)?;self.peer_learned=true;}
  self.largest[index]=Some(self.largest[index].map_or(pn,|last|last.max(pn)));let outcome=book.apply_packet(authentication,plaintext,clock.now())?;slots.schedule.changed()?;
  if !outcome.duplicate{for frame in FrameIter::new(plaintext,if level==Level::Initial{packet::EncryptionLevel::Initial}else{packet::EncryptionLevel::Handshake},ParseLimits::default())?{match frame?{Frame::Crypto{offset,data}=>self.reassembly[index].insert(offset,data)?,Frame::Padding{..}|Frame::Ping|Frame::Ack{..}=>{},_=>return Err(Error::UnsupportedFrame)}}}
  Ok(true)
 }
}
async fn receive_phase<'scope,Stage,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::RX}>,io:&mut impl DatagramRx,slots:&Storage<'scope,'_,N,P>,config:Config<'_>,scope:&'scope ApplicationKeyScope,wire:&mut ReceiveWire<'scope,'_,N>,book:&mut recovery::Rx<'_,'scope,N>,clock:&impl Clock,id:&mut u64)->Result<(),Error> where Stage:p::ReceivePhase{
 loop{let route=endpoint.offer().await?;if route.label()==Stage::Boundary::LOGICAL_LABEL{check(route.recv::<Stage::Boundary>().await?,*id)?;return Ok(());}if route.label()!=Stage::Need::LOGICAL_LABEL{return Err(Error::UnexpectedLabel(route.label()));}check(route.recv::<Stage::Need>().await?,*id)?;
  let(input,index,count)=loop{if let Some(input)=wire.ready(scope)?{break input;}wire.packet(io,slots,config,book,clock,false).await?;};
  slots.input.put(input)?;endpoint.send::<Stage::Input>(id).await?;let result=endpoint.offer().await?;
  match result.label(){label if label==Stage::Accepted::LOGICAL_LABEL=>check(result.recv::<Stage::Accepted>().await?,*id)?,label if label==Stage::Rejected::LOGICAL_LABEL=>{check(result.recv::<Stage::Rejected>().await?,*id)?;endpoint.send::<Stage::Taken>(id).await?;return Err(slots.failure.get().unwrap_or(crate::tls::Error::Handshake).into());},label=>return Err(Error::UnexpectedLabel(label))}
  wire.reassembly[index].consume(count)?;endpoint.send::<Stage::Taken>(id).await?;*id=id.checked_add(1).ok_or(Error::Binding)?;
 }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn receive<'scope,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::RX}>,io:&mut impl DatagramRx,slots:&Storage<'scope,'_,N,P>,config:Config<'_>,scope:&'scope ApplicationKeyScope,initial:crypto::PacketKey,integrity:IntegrityBudget,reassembly:[CryptoBuffer<'_>;2],book:&mut recovery::Rx<'_,'scope,N>,clock:&impl Clock)->Result<ReceiveContinuation<'scope,P>,Error>{
 let mut wire=ReceiveWire{initial:ReceivePacketKey::from_initial(scope,initial)?,handshake:None,integrity,reassembly,largest:[None;2],datagram:[0;N],len:0,offset:0,opened:[0;N],peer_learned:false};let mut id=0;
 receive_phase::<p::InitialReceive,N,P>(endpoint,io,slots,config,scope,&mut wire,book,clock,&mut id).await?;check(endpoint.recv::<p::ReadHandshake>().await?,id)?;wire.handshake=Some(slots.read_handshake.take()?);
 receive_phase::<p::HandshakeReceive,N,P>(endpoint,io,slots,config,scope,&mut wire,book,clock,&mut id).await?;check(endpoint.recv::<p::ReadApplication>().await?,id)?;let application=slots.read_application.take()?;
 receive_phase::<p::FinishedReceive,N,P>(endpoint,io,slots,config,scope,&mut wire,book,clock,&mut id).await?;let finished=slots.finished.take()?;let peer=*slots.peer.borrow();
 if !finished.receipt().authenticates_peer_parameters(finished.parameters()){return Err(Error::Binding);}let parameters=Parameters::parse(finished.parameters(),if config.side==Side::Client{Peer::Server}else{Peer::Client},&mut[0;64]).map_err(|_|Error::Binding)?;parameters.verify_connection_ids(peer.bytes(),if config.side==Side::Client{Some(config.original_destination_id)}else{None},None).map_err(|_|Error::Binding)?;
 while wire.packet(io,slots,config,book,clock,true).await?{}
 endpoint.send::<p::ReceiveComplete>(&id).await?;check(endpoint.recv::<p::ReceiveContinuation>().await?,id)?;
 // Parent added peer to ReceiveContinuation immediately before replacement;
 // the initializer fix was the command which never ran. Keep recovery explicit.
 Ok(ReceiveContinuation{initial:wire.initial,handshake:wire.handshake.ok_or(Error::Binding)?,application,integrity:wire.integrity,finished,largest_received:wire.largest})
}
fn limited(error:&recovery::Error)->bool{matches!(error,recovery::Error::CongestionLimited|recovery::Error::Accounting(crate::accounting::AccountingError::AmplificationLimited))}
#[allow(clippy::too_many_arguments)]
fn prepare<'book,'scope,const N:usize>(keys:&mut WriteKeys<'scope>,book:&mut recovery::Tx<'book,'scope,N>,config:Config<'_>,peer:&ConnectionId,level:Level,frame:Frame<'_>,flight:Option<crate::flights::FlightId>,probe:bool,ack:Option<recovery::AckSnapshot<'book>>,now:u64)->Result<Option<wire::Datagram<'book,N>>,Error>{
 let ack_eliciting=frame.ack_eliciting();let plain=PlainPacket::<N>::new(config,peer,level,frame)?;let reservation=match book.reserve(level,plain.len()as u64,flight,ack_eliciting,plain.padded(),probe,now){Ok(r)=>r,Err(e)if limited(&e)=>return Ok(None),Err(e)=>return Err(e.into())};match plain.seal(keys,reservation,ack){Ok(d)=>Ok(Some(d)),Err((e,r))=>{book.cancel(r)?;Err(e)}}
}
async fn send<'scope,'book,Pub:p::Publication,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::TX_WIRE}>,slots:&Storage<'scope,'book,N,P>,datagram:wire::Datagram<'book,N>,id:u64)->Result<(),Error>{
 slots.datagram.put(datagram)?;endpoint.send::<Pub::Datagram>(&id).await?;let result=endpoint.offer().await?;let accepted=match result.label(){label if label==Pub::Accepted::LOGICAL_LABEL=>{check(result.recv::<Pub::Accepted>().await?,id)?;true},label if label==Pub::Rejected::LOGICAL_LABEL=>{check(result.recv::<Pub::Rejected>().await?,id)?;false},label=>return Err(Error::UnexpectedLabel(label))};endpoint.send::<Pub::Settled>(&id).await?;if accepted{Ok(())}else{Err(Error::Io(IoError::Rejected))}
}
#[allow(clippy::too_many_arguments)]
async fn numerical<'scope,'book,Ack:p::Publication,Probe:p::Publication,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::TX_WIRE}>,timer:&mut Endpoint<'_,{p::TIMER_TX}>,slots:&Storage<'scope,'book,N,P>,keys:&mut WriteKeys<'scope>,book:&mut recovery::Tx<'book,'scope,N>,config:Config<'_>,clock:&impl Clock,id:u64)->Result<bool,Error>{
 super::timer::take(timer,&slots.schedule).await?;let peer=*slots.peer.borrow();
 if let Some(ack)=book.pending_ack(){let level=ack.level();if level!=Level::Handshake||keys.handshake.is_some(){let frame=Frame::Ack{delay:0,ranges:packet::AckRanges::new(ack.ranges())?,ecn:None};let plain=PlainPacket::<N>::new(config,&peer,level,frame)?;let reservation=match book.reserve(level,plain.len()as u64,None,false,plain.padded(),false,clock.now()){Ok(r)=>Some(r),Err(e)if limited(&e)=>None,Err(e)=>return Err(e.into())};if let Some(r)=reservation{let d=match plain.seal(keys,r,Some(ack)){Ok(d)=>d,Err((e,r))=>{book.cancel(r)?;return Err(e);}};send::<Ack,N,P>(endpoint,slots,d,id).await?;return Ok(true);}}}
 if let Some((flight,probe))=book.next_retransmit(){let data=book.flight_data(flight)?;if let Some(d)=prepare(keys,book,config,&peer,data.level(),Frame::Crypto{offset:data.offset(),data:data.bytes()},Some(flight),probe,None,clock.now())?{send::<Probe,N,P>(endpoint,slots,d,id).await?;return Ok(true);}}
 else if let Some(level)=book.pending_probe(){if let Some(d)=prepare(keys,book,config,&peer,level,Frame::Ping,None,true,None,clock.now())?{send::<Probe,N,P>(endpoint,slots,d,id).await?;return Ok(true);}}
 Ok(false)
}
struct PublicationPhaseSettled<Stage>{id:u64,phase:core::marker::PhantomData<Stage>}
impl<Stage> PublicationPhaseSettled<Stage>{fn into_id(self)->u64{self.id}}
async fn settle_phase<Stage:p::TransmitPhase>(output:&mut Endpoint<'_,{p::TX_WIRE}>,id:u64)->Result<PublicationPhaseSettled<Stage>,Error>{output.send::<Stage::WireBoundary>(&id).await?;check(output.recv::<Stage::WireBoundarySeen>().await?,id)?;Ok(PublicationPhaseSettled{id,phase:core::marker::PhantomData})}
#[allow(clippy::too_many_arguments)]
async fn transmit_phase<'scope,'book,Stage,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::TX}>,output:&mut Endpoint<'_,{p::TX_WIRE}>,timer:&mut Endpoint<'_,{p::TIMER_TX}>,slots:&Storage<'scope,'book,N,P>,config:Config<'_>,keys:&mut WriteKeys<'scope>,book:&mut recovery::Tx<'book,'scope,N>,clock:&impl Clock,id:&mut u64)->Result<(),Error> where Stage:p::TransmitPhase{
 loop{if numerical::<Stage::Ack,Stage::Probe,N,P>(output,timer,slots,keys,book,config,clock,*id).await?{continue;}let revision=slots.schedule.revision.get();endpoint.send::<Stage::Request>(id).await?;let response=endpoint.offer().await?;
  if response.label()==Stage::Boundary::LOGICAL_LABEL{check(response.recv::<Stage::Boundary>().await?,*id)?;let settled=settle_phase::<Stage>(output,*id).await?;endpoint.send::<Stage::PhaseSettled>(&settled.into_id()).await?;*id=id.checked_add(1).ok_or(Error::Binding)?;return Ok(());}
  match response.label(){label if label==Stage::Flight::LOGICAL_LABEL=>{check(response.recv::<Stage::Flight>().await?,*id)?;let flight=slots.flight.take()?;endpoint.send::<Stage::Taken>(id).await?;let mut offset=0;
   while offset<flight.bytes().len(){let count=(flight.bytes().len()-offset).min(N-128);let at=flight.offset()+offset as u64;let bytes=&flight.bytes()[offset..offset+count];let retained=book.store_crypto(flight.level(),at,bytes)?;
    loop{let revision=slots.schedule.revision.get();let peer=*slots.peer.borrow();if let Some(d)=prepare(keys,book,config,&peer,flight.level(),Frame::Crypto{offset:at,data:bytes},Some(retained),false,None,clock.now())?{send::<Stage::Data,N,P>(output,slots,d,*id).await?;break;}if !numerical::<Stage::Ack,Stage::Probe,N,P>(output,timer,slots,keys,book,config,clock,*id).await?{slots.schedule.wait_changed(1,revision).await;}}
    offset+=count;
   }
  },label if label==Stage::Idle::LOGICAL_LABEL=>{response.recv::<Stage::Idle>().await?;endpoint.send::<Stage::Taken>(id).await?;slots.schedule.wait_changed(1,revision).await;},label=>return Err(Error::UnexpectedLabel(label))}
  *id=id.checked_add(1).ok_or(Error::Binding)?;crate::runtime::yield_now().await;
 }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn transmit<'scope,'book,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::TX}>,output:&mut Endpoint<'_,{p::TX_WIRE}>,timer:&mut Endpoint<'_,{p::TIMER_TX}>,slots:&Storage<'scope,'book,N,P>,config:Config<'_>,scope:&'scope ApplicationKeyScope,initial:crypto::PacketKey,book:&mut recovery::Tx<'book,'scope,N>,clock:&impl Clock)->Result<TransmitContinuation<'scope>,Error>{
 let mut keys=WriteKeys{initial,handshake:None,application:None};let mut id=0;
 transmit_phase::<p::InitialTransmit,N,P>(endpoint,output,timer,slots,config,&mut keys,book,clock,&mut id).await?;check(endpoint.recv::<p::WriteHandshake>().await?,id)?;let handshake=slots.write_handshake.take()?;if !core::ptr::eq(scope,handshake.scope()){return Err(Error::Binding);}keys.handshake=Some(handshake);slots.schedule.keys.set([true,true]);slots.schedule.changed()?;
 transmit_phase::<p::HandshakeTransmit,N,P>(endpoint,output,timer,slots,config,&mut keys,book,clock,&mut id).await?;check(endpoint.recv::<p::WriteApplication>().await?,id)?;let application=slots.write_application.take()?;if !core::ptr::eq(scope,application.scope()){return Err(Error::Binding);}keys.application=Some(application);
 transmit_phase::<p::ApplicationTransmit,N,P>(endpoint,output,timer,slots,config,&mut keys,book,clock,&mut id).await?;
 loop{let revision=slots.schedule.revision.get();if numerical::<p::DrainAck,p::DrainProbe,N,P>(output,timer,slots,&mut keys,book,config,clock,id).await?{continue;}if !book.has_outstanding_crypto()&&book.pending_ack().is_none(){break;}slots.schedule.wait_changed(1,revision).await;}
 output.send::<p::RecoveryDrained>(&id).await?;super::timer::retire(timer,&slots.schedule).await?;endpoint.send::<p::TransmitComplete>(&id).await?;check(endpoint.recv::<p::TransmitContinuation>().await?,id)?;output.send::<p::AdapterComplete>(&id).await?;check(output.recv::<p::AdapterRetired>().await?,id)?;slots.schedule.transmit_done.set(true);slots.schedule.changed()?;
 Ok(TransmitContinuation{initial:keys.initial,handshake:keys.handshake.ok_or(Error::Binding)?,application:keys.application.ok_or(Error::Binding)?})
}
async fn publish_result<Pub:p::Publication,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::UDP}>,io:&mut impl DatagramTx,slots:&Storage<'_,'_,N,P>,issuer:&mut publication_gate::Issuer<'_,'_>,outcome:&Outcome,book:&mut recovery::Publication<'_,'_,N>,id:u64)->Result<(),Error>{
 let wire::Datagram{sealed,reservation,acknowledgment}=slots.datagram.take()?;let permit=match issuer.begin(){Ok(p)=>p,Err(e)=>{book.cancel(reservation)?;return Err(e.into());}};if !core::ptr::eq(permit.scope(),reservation.scope()){book.cancel(reservation)?;return Err(Error::Binding);}
 let result=permit.submit(io.send(sealed.bytes())).await;let accepted_at=match result{Ok(Ok(at))=>Some(at),_=>None};book.settle(recovery::Completion::from_adapter(reservation,accepted_at))?;if accepted_at.is_some(){if let Some(ack)=acknowledgment{book.acknowledgment_sent(ack)?;}}slots.schedule.changed()?;outcome.set(accepted_at.is_some())?;
 match outcome.resolver::<{p::ADAPTER_RESULT}>().decide()?{DecisionArm::Left=>endpoint.send::<Pub::Accepted>(&id).await?,DecisionArm::Right=>endpoint.send::<Pub::Rejected>(&id).await?};check(endpoint.recv::<Pub::Settled>().await?,id)?;outcome.clear();match result{Ok(Ok(_))=>Ok(()),Ok(Err(e))=>Err(e.into()),Err(e)=>Err(e.into())}
}
async fn publish_phase<Stage:p::TransmitPhase,const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::UDP}>,io:&mut impl DatagramTx,slots:&Storage<'_,'_,N,P>,issuer:&mut publication_gate::Issuer<'_,'_>,outcome:&Outcome,book:&mut recovery::Publication<'_,'_,N>)->Result<(),Error>{
 loop{let input=endpoint.offer().await?;macro_rules! accept{($pub:ty)=>{{let id=input.recv::<<$pub as p::Publication>::Datagram>().await?;publish_result::<$pub,N,P>(endpoint,io,slots,issuer,outcome,book,id).await?;}};}
  match input.label(){label if label==<Stage::Ack as p::Publication>::Datagram::LOGICAL_LABEL=>accept!(Stage::Ack),label if label==<Stage::Probe as p::Publication>::Datagram::LOGICAL_LABEL=>accept!(Stage::Probe),label if label==<Stage::Data as p::Publication>::Datagram::LOGICAL_LABEL=>accept!(Stage::Data),label if label==Stage::WireBoundary::LOGICAL_LABEL=>{let id=input.recv::<Stage::WireBoundary>().await?;endpoint.send::<Stage::WireBoundarySeen>(&id).await?;return Ok(());},label=>return Err(Error::UnexpectedLabel(label))}
  crate::runtime::yield_now().await;
 }
}
pub(super) async fn publish<const N:usize,const P:usize>(endpoint:&mut Endpoint<'_,{p::UDP}>,io:&mut impl DatagramTx,slots:&Storage<'_,'_,N,P>,issuer:&mut publication_gate::Issuer<'_,'_>,outcome:&Outcome,book:&mut recovery::Publication<'_,'_,N>)->Result<(),Error>{
 publish_phase::<p::InitialTransmit,N,P>(endpoint,io,slots,issuer,outcome,book).await?;publish_phase::<p::HandshakeTransmit,N,P>(endpoint,io,slots,issuer,outcome,book).await?;publish_phase::<p::ApplicationTransmit,N,P>(endpoint,io,slots,issuer,outcome,book).await?;
 loop{let input=endpoint.offer().await?;match input.label(){128=>{let id=input.recv::<<p::DrainAck as p::Publication>::Datagram>().await?;publish_result::<p::DrainAck,N,P>(endpoint,io,slots,issuer,outcome,book,id).await?;},132=>{let id=input.recv::<<p::DrainProbe as p::Publication>::Datagram>().await?;publish_result::<p::DrainProbe,N,P>(endpoint,io,slots,issuer,outcome,book,id).await?;},136=>{input.recv::<p::RecoveryDrained>().await?;break;},label=>return Err(Error::UnexpectedLabel(label))}}
 let id=endpoint.recv::<p::AdapterComplete>().await?;endpoint.send::<p::AdapterRetired>(&id).await?;Ok(())
}
