#pragma once

/*
 * DuetOS — CSS engine internal interface (not part of the public API).
 *
 * Declares the declaration-application entry point shared between the
 * cascade driver (css.cpp) and the property-setter table (css_apply.cpp).
 * Split out so the large flat `value -> ComputedStyle field` dispatch
 * lives in its own translation unit instead of bloating the cascade
 * file. Nothing outside the CSS engine includes this.
 */

#include "web/css.h"

namespace duetos::web
{

/// Apply one `property: value` pair onto `cs`. Unknown / unparseable
/// properties are silently ignored. Defined in css_apply.cpp.
void ApplyDeclaration(ComputedStyle& cs, const char* prop, const char* val);

/// Apply a whole declaration list (in order; later wins) onto `cs`.
void ApplyDeclList(ComputedStyle& cs, const Declaration* d);

} // namespace duetos::web
