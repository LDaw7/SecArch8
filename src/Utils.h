#pragma once
#include <type_traits>

// Standardises Enum casting for the SecArch project
template <typename E>
constexpr auto to_idx(E e) noexcept {
    return static_cast<std::underlying_type_t<E>>(e);
}