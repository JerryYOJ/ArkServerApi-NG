#pragma once

#include <dia2.h>
#include <unordered_set>

#include "json.hpp"

#include <API/Fields.h>

namespace API
{
	class PdbReader
	{
	public:
		PdbReader() = default;
		~PdbReader() = default;

		void Read(const std::wstring& path, std::unordered_map<std::string, intptr_t>* offsets_dump,
		          std::unordered_map<std::string, BitField>* bitfields_dump);

	private:
		// Serialization methods for caching
		bool LoadFromCache(const std::wstring& cache_path, std::unordered_map<std::string, intptr_t>* offsets_dump,
		                   std::unordered_map<std::string, BitField>* bitfields_dump);
		void SaveToCache(const std::wstring& cache_path, const std::unordered_map<std::string, intptr_t>& offsets_dump,
		                 const std::unordered_map<std::string, BitField>& bitfields_dump);
		bool IsCacheValid(const std::wstring& pdb_path, const std::wstring& cache_path);

		
		static void LoadDataFromPdb(const std::wstring& /*path*/, IDiaDataSource** /*dia_source*/, IDiaSession**
		                            /*session*/, IDiaSymbol** /*symbol*/);

		void DumpStructs(IDiaSymbol* /*g_symbol*/);
		void DumpFunctions(IDiaSymbol* /*g_symbol*/);
		void DumpGlobalVariables(IDiaSymbol* /*g_symbol*/);
		void DumpType(IDiaSymbol* /*symbol*/, const std::string& /*structure*/, int /*indent*/) const;
		void DumpData(IDiaSymbol* /*symbol*/, const std::string& /*structure*/) const;

		static std::string GetSymbolNameString(IDiaSymbol* /*symbol*/);
		static uint32_t GetSymbolId(IDiaSymbol* /*symbol*/);
		static void Cleanup(IDiaSymbol* /*symbol*/, IDiaSession* /*session*/, IDiaDataSource* /*source*/);

		// Helper methods for serialization
		static std::wstring GetCachePath(const std::wstring& pdb_path);
		static std::time_t GetFileModificationTime(const std::wstring& file_path);

		std::unordered_map<std::string, intptr_t>* offsets_dump_{nullptr};
		std::unordered_map<std::string, BitField>* bitfields_dump_{nullptr};

		std::unordered_set<uint32_t> visited_;
	};
} // namespace API
