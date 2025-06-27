
#include <API/Base.h>
#include "Trampoline.h"

#include "Logger/Logger.h"
#include <windows.h>
#include <memoryapi.h>
#include <sysinfoapi.h>

namespace detail
{
	[[nodiscard]] constexpr std::size_t roundup(std::size_t a_number, std::size_t a_multiple) noexcept
	{
		if (a_multiple == 0)
			return 0;

		const auto remainder = a_number % a_multiple;
		return (remainder == 0) ? a_number : (a_number + a_multiple - remainder);
	}

	[[nodiscard]] constexpr std::size_t rounddown(std::size_t a_number, std::size_t a_multiple) noexcept
	{
		if (a_multiple == 0)
			return 0;

		const auto remainder = a_number % a_multiple;
		return (remainder == 0) ? a_number : (a_number - remainder);
	}
}


ARK_API ArkApi::ITrampoline& ArkApi::GetTrampoline()
{
	return API::Trampoline::Get();
}

void API::Trampoline::create(std::size_t a_size, void* a_module)
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

void* API::Trampoline::do_create(std::size_t a_size, std::uintptr_t a_address)
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

void* API::Trampoline::do_allocate(std::size_t a_size)
{
	if (a_size > free_size()) {
		Log::GetLog()->critical("Failed to handle allocation request");
		while (!IsDebuggerPresent());
		return nullptr;
	}

	auto mem = _data + _size;
	_size += a_size;

	return mem;
}

void API::Trampoline::write_5branch(std::uintptr_t a_src, std::uintptr_t a_dst, std::uint8_t a_opcode)
{
#pragma pack(push, 1)
	struct SrcAssembly
	{
		// jmp/call [rip + imm32]
		std::uint8_t opcode;  // 0 - 0xE9/0xE8
		std::int32_t disp;    // 1
	};
	static_assert(offsetof(SrcAssembly, opcode) == 0x0);
	static_assert(offsetof(SrcAssembly, disp) == 0x1);
	static_assert(sizeof(SrcAssembly) == 0x5);

	// FF /4
	// JMP r/m64
	struct TrampolineAssembly
	{
		// jmp [rip]
		std::uint8_t  jmp;    // 0 - 0xFF
		std::uint8_t  modrm;  // 1 - 0x25
		std::int32_t  disp;   // 2 - 0x00000000
		std::uint64_t addr;   // 6 - [rip]
	};
	static_assert(offsetof(TrampolineAssembly, jmp) == 0x0);
	static_assert(offsetof(TrampolineAssembly, modrm) == 0x1);
	static_assert(offsetof(TrampolineAssembly, disp) == 0x2);
	static_assert(offsetof(TrampolineAssembly, addr) == 0x6);
	static_assert(sizeof(TrampolineAssembly) == 0xE);
#pragma pack(pop)

	TrampolineAssembly* mem = nullptr;
	if (const auto it = _5branches.find(a_dst); it != _5branches.end()) {
		mem = reinterpret_cast<TrampolineAssembly*>(it->second);
	}
	else {
		mem = allocate<TrampolineAssembly>();
		_5branches.emplace(a_dst, reinterpret_cast<std::byte*>(mem));
	}

	const auto disp =
		reinterpret_cast<const std::byte*>(mem) -
		reinterpret_cast<const std::byte*>(a_src + sizeof(SrcAssembly));
	if (!in_range(disp)) {  // the trampoline should already be in range, so this should never happen
		Log::GetLog()->critical("displacement is out of range");
		while (!IsDebuggerPresent());
		return;
	}

	SrcAssembly assembly;
	assembly.opcode = a_opcode;
	assembly.disp = static_cast<std::int32_t>(disp);
	// Safe write with memory protection handling
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

void API::Trampoline::write_6branch(std::uintptr_t a_src, std::uintptr_t a_dst, std::uint8_t a_modrm)
{
#pragma pack(push, 1)
	struct Assembly
	{
		// jmp/call [rip + imm32]
		std::uint8_t opcode;  // 0 - 0xFF
		std::uint8_t modrm;   // 1 - 0x25/0x15
		std::int32_t disp;    // 2
	};
	static_assert(offsetof(Assembly, opcode) == 0x0);
	static_assert(offsetof(Assembly, modrm) == 0x1);
	static_assert(offsetof(Assembly, disp) == 0x2);
	static_assert(sizeof(Assembly) == 0x6);
#pragma pack(pop)

	std::uintptr_t* mem = nullptr;
	if (const auto it = _6branches.find(a_dst); it != _6branches.end()) {
		mem = reinterpret_cast<std::uintptr_t*>(it->second);
	}
	else {
		mem = allocate<std::uintptr_t>();
		_6branches.emplace(a_dst, reinterpret_cast<std::byte*>(mem));
	}

	const auto disp =
		reinterpret_cast<const std::byte*>(mem) -
		reinterpret_cast<const std::byte*>(a_src + sizeof(Assembly));
	if (!in_range(disp)) {  // the trampoline should already be in range, so this should never happen
		Log::GetLog()->critical("displacement is out of range");
		while (!IsDebuggerPresent());
	}

	Assembly assembly;
	assembly.opcode = static_cast<std::uint8_t>(0xFF);
	assembly.modrm = a_modrm;
	assembly.disp = static_cast<std::int32_t>(disp);
	// Safe write with memory protection handling
	DWORD oldProtect;
	if (VirtualProtect(reinterpret_cast<void*>(a_src), sizeof(assembly), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		std::memcpy(reinterpret_cast<void*>(a_src), &assembly, sizeof(assembly));
		VirtualProtect(reinterpret_cast<void*>(a_src), sizeof(assembly), oldProtect, &oldProtect);
	}

	*mem = a_dst;
}

void API::Trampoline::log_stats() const
{
	const auto pct = (static_cast<double>(_size) / static_cast<double>(_capacity)) * 100.0;
	Log::GetLog()->debug("{} => {}B / {}B ({:05.2f}%)", _name, _size, _capacity, pct);
}
