//! Reconstructed bounded ordinary-publication authority. Fresh tests required.
//! Closing publication requires a separate consumed terminal capability.
use core::{cell::{Cell,RefCell},future::{Future,poll_fn},task::{Poll,Waker}};
use crate::crypto::directional::{ApplicationKeyScope,PublicationGateInstallation};
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Error{AlreadySplit,Revoked,Busy}
pub struct PublicationGate<'scope>{scope:&'scope ApplicationKeyScope,split:bool,revoked:Cell<bool>,active:Cell<bool>,waker:RefCell<Option<Waker>>}
impl<'scope> PublicationGate<'scope>{
 pub fn new(installation:PublicationGateInstallation<'scope>)->Self{Self{scope:installation.into_scope(),split:false,revoked:Cell::new(false),active:Cell::new(false),waker:RefCell::new(None)}}
 pub fn split(&mut self)->Result<(Issuer<'_,'scope>,Stop<'_,'scope>),Error>{if self.split{return Err(Error::AlreadySplit);}self.split=true;Ok((Issuer{gate:self},Stop{gate:self}))}
 fn revoke(&self){self.revoked.set(true);let wake=self.waker.borrow_mut().take();if let Some(wake)=wake{wake.wake();}}
 fn register(&self,waker:&Waker){let next=waker.clone();let old=self.waker.borrow_mut().replace(next);drop(old);}
 fn release(&self){self.active.set(false);let old=self.waker.borrow_mut().take();drop(old);}
}
pub struct Issuer<'gate,'scope>{gate:&'gate PublicationGate<'scope>}
impl<'scope> Issuer<'_,'scope>{
 pub fn begin(&mut self)->Result<Permit<'_,'scope>,Error>{if self.gate.revoked.get(){return Err(Error::Revoked);}if self.gate.active.replace(true){return Err(Error::Busy);}Ok(Permit{gate:self.gate})}
 pub fn scope(&self)->&'scope ApplicationKeyScope{self.gate.scope}
}
impl Drop for Issuer<'_,'_>{fn drop(&mut self){self.gate.revoke();}}
pub struct Stop<'gate,'scope>{gate:&'gate PublicationGate<'scope>}
impl Stop<'_,'_>{pub fn revoke(self){self.gate.revoke();}}
impl Drop for Stop<'_,'_>{fn drop(&mut self){self.gate.revoke();}}
#[must_use="the pending adapter operation owns this permission"]
pub struct Permit<'permit,'scope>{gate:&'permit PublicationGate<'scope>}
impl<'scope> Permit<'_,'scope>{
 pub fn scope(&self)->&'scope ApplicationKeyScope{self.gate.scope}
 pub async fn submit<F:Future>(self,future:F)->Result<F::Output,Error>{
  let mut future=core::pin::pin!(future);
  poll_fn(|cx|{
   if self.gate.revoked.get(){return Poll::Ready(Err(Error::Revoked));}
   self.gate.register(cx.waker());
   if self.gate.revoked.get(){return Poll::Ready(Err(Error::Revoked));}
   match future.as_mut().poll(cx){
    // Actual completion must be preserved even if a callback revokes ordinary
    // publication during this poll. Pending promises no hidden acceptance.
    Poll::Ready(value)=>Poll::Ready(Ok(value)),
    Poll::Pending if self.gate.revoked.get()=>Poll::Ready(Err(Error::Revoked)),
    Poll::Pending=>Poll::Pending,
   }
  }).await
 }
}
impl Drop for Permit<'_,'_>{fn drop(&mut self){self.gate.release();}}

#[cfg(test)]
mod tests{
 use super::*;
 use core::task::Context;
 fn install(scope:&mut ApplicationKeyScope)->PublicationGate<'_>{PublicationGate::new(scope.claim().unwrap().take_publication_gate().unwrap())}
 #[test]fn accepted_result_is_preserved_and_permission_can_be_reissued(){let mut scope=ApplicationKeyScope::new(1);let mut gate=install(&mut scope);let(mut issuer,_stop)=gate.split().unwrap();let future=issuer.begin().unwrap().submit(core::future::ready(73));let mut future=core::pin::pin!(future);let mut cx=Context::from_waker(Waker::noop());assert_eq!(future.as_mut().poll(&mut cx),Poll::Ready(Ok(73)));drop(future);}
 #[test]fn revocation_does_not_repoll_pending_adapter(){let mut scope=ApplicationKeyScope::new(2);let mut gate=install(&mut scope);let(mut issuer,stop)=gate.split().unwrap();let calls=Cell::new(0);let adapter=poll_fn(|_|{calls.set(calls.get()+1);Poll::<()>::Pending});let mut future=core::pin::pin!(issuer.begin().unwrap().submit(adapter));let mut cx=Context::from_waker(Waker::noop());assert!(future.as_mut().poll(&mut cx).is_pending());stop.revoke();assert_eq!(future.as_mut().poll(&mut cx),Poll::Ready(Err(Error::Revoked)));assert_eq!(calls.get(),1);}
 #[test]fn revoked_permission_never_polls_adapter(){let mut scope=ApplicationKeyScope::new(3);let mut gate=install(&mut scope);let(mut issuer,stop)=gate.split().unwrap();let calls=Cell::new(0);let permit=issuer.begin().unwrap();stop.revoke();let adapter=poll_fn(|_|{calls.set(calls.get()+1);Poll::Ready(())});let mut future=core::pin::pin!(permit.submit(adapter));let mut cx=Context::from_waker(Waker::noop());assert_eq!(future.as_mut().poll(&mut cx),Poll::Ready(Err(Error::Revoked)));assert_eq!(calls.get(),0);}
 #[test]fn dropping_stop_permanently_revokes_issuer(){let mut scope=ApplicationKeyScope::new(4);let mut gate=install(&mut scope);let(mut issuer,stop)=gate.split().unwrap();drop(stop);assert!(matches!(issuer.begin(),Err(Error::Revoked)));}
 std::thread_local! {static REVOKE_HOOK:RefCell<Option<std::boxed::Box<dyn Fn()>>>=RefCell::new(None);}
 struct RevokeOnDrop;
 impl std::task::Wake for RevokeOnDrop{fn wake(self:std::sync::Arc<Self>) {}}
 impl Drop for RevokeOnDrop{fn drop(&mut self){let hook=REVOKE_HOOK.with(|slot|slot.borrow_mut().take());if let Some(hook)=hook{hook();}}}
 #[test]fn reentrant_waker_drop_revokes_before_adapter_poll(){
  let scope=std::boxed::Box::leak(std::boxed::Box::new(ApplicationKeyScope::new(5)));
  let gate=std::boxed::Box::leak(std::boxed::Box::new(install(scope)));
  let(mut issuer,_stop)=gate.split().unwrap();let shared=issuer.gate;
  REVOKE_HOOK.with(|slot|*slot.borrow_mut()=Some(std::boxed::Box::new(move||shared.revoke())));
  *shared.waker.borrow_mut()=Some(Waker::from(std::sync::Arc::new(RevokeOnDrop)));
  let calls=Cell::new(0);let adapter=poll_fn(|_|{calls.set(calls.get()+1);Poll::Ready(())});
  let mut future=core::pin::pin!(issuer.begin().unwrap().submit(adapter));let mut cx=Context::from_waker(Waker::noop());
  assert_eq!(future.as_mut().poll(&mut cx),Poll::Ready(Err(Error::Revoked)));assert_eq!(calls.get(),0);
 }

}
