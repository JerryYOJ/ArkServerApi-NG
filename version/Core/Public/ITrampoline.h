#pragma once

#include <API/Base.h>
#include <cstdint>
#include <cstddef>

namespace ArkApi {
	class ARK_API ITrampoline {
	public:
		virtual ~ITrampoline() = default;
		
		// Explicit virtual functions for common sizes
		virtual std::uintptr_t write_branch_5(std::uintptr_t a_src, std::uintptr_t a_dst) = 0;
		virtual std::uintptr_t write_branch_6(std::uintptr_t a_src, std::uintptr_t a_dst) = 0;
		virtual std::uintptr_t write_call_5(std::uintptr_t a_src, std::uintptr_t a_dst) = 0;
		virtual std::uintptr_t write_call_6(std::uintptr_t a_src, std::uintptr_t a_dst) = 0;
		
		// Template convenience functions (non-virtual)
		template <std::size_t N>
		std::uintptr_t write_branch(std::uintptr_t a_src, std::uintptr_t a_dst) {
			if constexpr (N == 5) {
				return write_branch_5(a_src, a_dst);
			} else if constexpr (N == 6) {
				return write_branch_6(a_src, a_dst);
			} else {
				static_assert(N == 5 || N == 6, "Only 5 and 6 byte branches supported");
			}
		}
		
		template <std::size_t N, class F>
		std::uintptr_t write_branch(std::uintptr_t a_src, F a_dst) {
			return write_branch<N>(a_src, reinterpret_cast<std::uintptr_t>(a_dst));
		}
		
		template <std::size_t N>
		std::uintptr_t write_call(std::uintptr_t a_src, std::uintptr_t a_dst) {
			if constexpr (N == 5) {
				return write_call_5(a_src, a_dst);
			} else if constexpr (N == 6) {
				return write_call_6(a_src, a_dst);
			} else {
				static_assert(N == 5 || N == 6, "Only 5 and 6 byte calls supported");
			}
		}
		
		template <std::size_t N, class F>
		std::uintptr_t write_call(std::uintptr_t a_src, F a_dst) {
			return write_call<N>(a_src, reinterpret_cast<std::uintptr_t>(a_dst));
		}

	};

	ARK_API ITrampoline& GetTrampoline();
}