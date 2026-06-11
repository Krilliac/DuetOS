#include "env/neural_policy.h"

namespace duetos::env
{

AutoActionSet NeuralPolicyDecide(const AutoInputs& /*in*/)
{
    // STUB: Slice 1 has no learner. The fixed-point MLP (feature
    // extraction + forward pass + imitation-by-construction init) lands
    // in Slice 2. Returning an empty set makes ShieldApply pass the rule
    // floor through unchanged, so the autonomic engine's behaviour is
    // byte-identical to the pre-seam rule table.
    return AutoActionSet{};
}

} // namespace duetos::env
