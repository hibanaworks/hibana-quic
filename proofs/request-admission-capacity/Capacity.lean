import Std
namespace RequestAdmissionCapacity
-- Queued, produced-but-not-queued, and active-response owners hold disjoint
-- admitted stream slots. Each owner is affine in the Rust integration.
theorem retained_request_always_has_space (queued producing active slots : Nat)
    (owners : queued + producing + active ≤ slots)
    (request : 1 ≤ producing) : queued < slots := by omega

theorem admission_never_needs_unbounded_queue (queued producing active slots : Nat)
    (owners : queued + producing + active ≤ slots) (bound : slots ≤ 64) :
    queued + producing ≤ 64 := by omega
end RequestAdmissionCapacity
