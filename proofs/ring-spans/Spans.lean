import Std
namespace RingSpans

def index (capacity head relative : Nat) : Nat :=
 if relative < capacity - head then head + relative else relative - (capacity - head)

theorem index_bound (c h r : Nat) (hh : h < c) (hr : r < c) :
 index c h r < c := by unfold index; split <;> omega

theorem split_index (c h r n : Nat) (hh : h < c)
    (hr : r + n < c) : index c h (r+n) = index c (index c h r) n := by
 unfold index
 split <;> split <;> split <;> omega
end RingSpans
