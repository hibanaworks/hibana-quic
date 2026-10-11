import Std.Tactic

namespace RsaEncoding
-- SHA-256 profiles only, RSA modulus widths supported by the Rust adapter.
def Width (n : Nat) : Prop := n = 256 ∨ n = 384 ∨ n = 512

theorem pkcs_padding_minimum (n : Nat) (h : Width n) : 8 ≤ n - 54 := by
  unfold Width at h
  omega

theorem pkcs_partition (n : Nat) (h : Width n) :
    2 + (n - 54) + 1 + 19 + 32 = n := by
  unfold Width at h
  omega

theorem pss_partition (n : Nat) (h : Width n) :
    (n - 66) + 1 + 32 + 32 + 1 = n := by
  unfold Width at h
  omega

theorem pss_offsets (n : Nat) (h : Width n) :
    0 < n - 33 ∧ n - 66 < n - 33 ∧ (n - 33) + 32 + 1 = n := by
  unfold Width at h
  omega

theorem mgf_counter_bound (n i : Nat) (h : Width n) (hi : i < n - 33) :
    i / 32 < 16 := by
  unfold Width at h
  omega

-- Exact byte-layout acceptance, relative to caller-supplied hash/encoding.
-- This does not assert SHA-256 collision resistance or Rust refinement.
def verifyBytes (actual expected : List UInt8) : Bool := actual == expected

theorem accepted_iff_exact_bytes (actual expected : List UInt8) :
    verifyBytes actual expected = true ↔ actual = expected := by
  simp [verifyBytes]

end RsaEncoding
