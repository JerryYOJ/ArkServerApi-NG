#pragma once

#include "Trampoline.h"
#include <Logger/Logger.h>

namespace ArkApi {

	inline void Trampoline::create(std::size_t a_size, void* a_module)
	{
		if (a_size == 0) {
			Log::GetLog()->critical("cannot create a trampoline with a zero size");
			while (!IsDebuggerPresent());
			return;
		}

		if (!a_module) {
			// Get the base address of the current module and find the .text section end
			HMODULE hModule = GetModuleHandle(NULL);
			if (hModule) {
				IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
				IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::byte*>(hModule) + dosHeader->e_lfanew);
				
				// Find the .text section
				IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
				for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
					if (strncmp(reinterpret_cast<const char*>(sections[i].Name), ".text", 8) == 0) {
						// Place at the end of the .text section
						a_module = reinterpret_cast<std::byte*>(hModule) + sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
						break;
					}
				}
				
				// Fallback to end of image if .text section not found
				if (!a_module) {
					a_module = reinterpret_cast<std::byte*>(hModule) + ntHeaders->OptionalHeader.SizeOfImage;
				}
			}
			else {
				Log::GetLog()->critical("failed to find module base");
				while (!IsDebuggerPresent());
			}
		}

		auto mem = do_create(a_size, reinterpret_cast<std::uintptr_t>(a_module));
		if (!mem) {
			Log::GetLog()->critical("failed to create trampoline");
			while (!IsDebuggerPresent());
		}

		set_trampoline(mem, a_size, [](void* a_mem, std::size_t) {
			VirtualFree(a_mem, 0, MEM_RELEASE);
		});
	}

	inline void* Trampoline::do_create(std::size_t a_size, std::uintptr_t a_address)
	{
		constexpr std::size_t    gigabyte = static_cast<std::size_t>(1) << 30;
		constexpr std::size_t    minRange = gigabyte * 2;
		constexpr std::uintptr_t maxAddr = std::numeric_limits<std::uintptr_t>::max();

		SYSTEM_INFO si;
		GetSystemInfo(&si);
		const std::uint32_t granularity = si.dwAllocationGranularity;

		std::uintptr_t       min = a_address >= minRange ? detail::roundup(a_address - minRange, granularity) : 0;
		const std::uintptr_t max = a_address < (maxAddr - minRange) ? detail::rounddown(a_address + minRange, granularity) : maxAddr;

		MEMORY_BASIC_INFORMATION mbi;
		do {
			if (!VirtualQuery(reinterpret_cast<void*>(min), std::addressof(mbi), sizeof(mbi))) {
				Log::GetLog()->error("VirtualQuery failed with code: 0x{:08X}", GetLastError());
				return nullptr;
			}

			const auto baseAddr = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
			min = baseAddr + mbi.RegionSize;

			if (mbi.State == MEM_FREE) {
				const std::uintptr_t addr = detail::roundup(baseAddr, granularity);

				// if rounding didn't advance us into the next region and the region is the required size
				if (addr < min && (min - addr) >= a_size) {
					const auto mem = VirtualAlloc(
					reinterpret_cast<void*>(addr), a_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
					if (mem) {
						return mem;
					}
					Log::GetLog()->warn("VirtualAlloc failed with code: 0x{:08X}", GetLastError());
				}
			}
		} while (min < max);

		return nullptr;
	}

	inline void* Trampoline::do_allocate(std::size_t a_size)
	{
		// 先从空闲列表中查找合适的块
		for (auto it = _freeList.begin(); it != _freeList.end(); ++it) {
			if (it->size >= a_size) {
				void* mem = it->addr;
				_freeList.erase(it);
				return mem;
			}
		}

		// 空闲列表中没有合适的块，从末尾分配
		if (a_size > free_size()) {
			Log::GetLog()->critical("Failed to handle allocation request");
			while (!IsDebuggerPresent());
			return nullptr;
		}

		auto mem = _data + _size;
		_size += a_size;

		return mem;
	}

	inline void Trampoline::do_free(void* a_mem, std::size_t a_size)
	{
		// 用 INT3 填充已释放的内存
		constexpr auto INT3 = static_cast<std::uint8_t>(0xCC);
		std::memset(a_mem, INT3, a_size);

		// 添加到空闲列表
		_freeList.push_back({ static_cast<std::byte*>(a_mem), a_size });
	}

	inline bool Trampoline::unhook(std::uintptr_t a_src)
	{
		auto it = _hooks.find(a_src);
		if (it == _hooks.end()) {
			Log::GetLog()->warn("unhook: no hook found at address 0x{:X}", a_src);
			return false;
		}

		const auto& entry = it->second;

		DWORD oldProtect;
		if (!VirtualProtect(reinterpret_cast<void*>(a_src), entry.size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			Log::GetLog()->error("unhook: VirtualProtect failed with code: 0x{:08X}", GetLastError());
			return false;
		}

		std::memcpy(reinterpret_cast<void*>(a_src), entry.originalBytes.data(), entry.size);
		VirtualProtect(reinterpret_cast<void*>(a_src), entry.size, oldProtect, &oldProtect);

		// 释放 trampoline 内存供后续使用
		do_free(entry.trampolineAddr, entry.trampolineSize);

		_hooks.erase(it);

		Log::GetLog()->debug("unhook: successfully removed hook at address 0x{:X}", a_src);
		return true;
	}

	inline void Trampoline::write_5branch(std::uintptr_t a_src, std::uintptr_t a_dst, std::uint8_t a_opcode)
	{
#pragma pack(push, 1)
		struct SrcAssembly
		{
			std::uint8_t opcode;
			std::int32_t disp;
		};
		static_assert(sizeof(SrcAssembly) == 0x5);

		struct TrampolineAssembly
		{
			std::uint8_t  jmp;
			std::uint8_t  modrm;
			std::int32_t  disp;
			std::uint64_t addr;
		};
		static_assert(sizeof(TrampolineAssembly) == 0xE);
#pragma pack(pop)

		auto mem = allocate<TrampolineAssembly>();

		// 更新 hook 条目中的 trampoline 信息
		if (auto hookIt = _hooks.find(a_src); hookIt != _hooks.end()) {
			hookIt->second.trampolineAddr = reinterpret_cast<std::byte*>(mem);
			hookIt->second.trampolineSize = sizeof(TrampolineAssembly);
		}

		const auto disp =
			reinterpret_cast<const std::byte*>(mem) -
			reinterpret_cast<const std::byte*>(a_src + sizeof(SrcAssembly));
		if (!in_range(disp)) {
			Log::GetLog()->critical("displacement is out of range");
			while (!IsDebuggerPresent());
			return;
		}

		SrcAssembly assembly;
		assembly.opcode = a_opcode;
		assembly.disp = static_cast<std::int32_t>(disp);

		DWORD oldProtect;
		if (VirtualProtect(reinterpret_cast<void*>(a_src), sizeof(assembly), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			std::memcpy(reinterpret_cast<void*>(a_src), &assembly, sizeof(assembly));
			VirtualProtect(reinterpret_cast<void*>(a_src), sizeof(assembly), oldProtect, &oldProtect);
		}

		mem->jmp = static_cast<std::uint8_t>(0xFF);
		mem->modrm = static_cast<std::uint8_t>(0x25);
		mem->disp = static_cast<std::int32_t>(0);
		mem->addr = static_cast<std::uint64_t>(a_dst);
	}

	inline void Trampoline::write_6branch(std::uintptr_t a_src, std::uintptr_t a_dst, std::uint8_t a_modrm)
	{
#pragma pack(push, 1)
		struct Assembly
		{
			std::uint8_t opcode;
			std::uint8_t modrm;
			std::int32_t disp;
		};
		static_assert(sizeof(Assembly) == 0x6);
#pragma pack(pop)

		auto mem = allocate<std::uintptr_t>();

		// 更新 hook 条目中的 trampoline 信息
		if (auto hookIt = _hooks.find(a_src); hookIt != _hooks.end()) {
			hookIt->second.trampolineAddr = reinterpret_cast<std::byte*>(mem);
			hookIt->second.trampolineSize = sizeof(std::uintptr_t);
		}

		const auto disp =
			reinterpret_cast<const std::byte*>(mem) -
			reinterpret_cast<const std::byte*>(a_src + sizeof(Assembly));
		if (!in_range(disp)) {
			Log::GetLog()->critical("displacement is out of range");
			while (!IsDebuggerPresent());
		}

		Assembly assembly;
		assembly.opcode = static_cast<std::uint8_t>(0xFF);
		assembly.modrm = a_modrm;
		assembly.disp = static_cast<std::int32_t>(disp);

		DWORD oldProtect;
		if (VirtualProtect(reinterpret_cast<void*>(a_src), sizeof(assembly), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			std::memcpy(reinterpret_cast<void*>(a_src), &assembly, sizeof(assembly));
			VirtualProtect(reinterpret_cast<void*>(a_src), sizeof(assembly), oldProtect, &oldProtect);
		}

		*mem = a_dst;
	}

	inline void Trampoline::log_stats() const
	{
		const auto pct = (static_cast<double>(_size) / static_cast<double>(_capacity)) * 100.0;
		Log::GetLog()->debug("{} => {}B / {}B ({:05.2f}%)", _name, _size, _capacity, pct);
	}
}