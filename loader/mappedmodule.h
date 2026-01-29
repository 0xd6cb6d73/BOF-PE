#pragma once

#include "Pe.hpp"
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <functional>

struct ImportHook {
	std::string Dll;
	std::string Import;
	FARPROC Hook;
};

typedef int (*Logger)(const char* fmt, ...);

class MappedModule {

private:

	Pe::PeNative _mappedPe;
	LPVOID _mappedImage;
	bool _loaded;
	Logger _logger;
  	std::unique_ptr<std::vector<std::byte>> _alloc;
	std::atomic<int32_t> _refs = 1;

public:
	MappedModule(Logger logger, const std::vector<std::byte>& peBytes);
	MappedModule(MappedModule&& other) noexcept;
	MappedModule& operator=(MappedModule&& other) noexcept {

		_mappedPe = std::move(other._mappedPe);
		_mappedImage = other._mappedImage;
		_loaded = other._loaded;
		_logger = other._logger;
		_alloc = std::move(other._alloc);
		_refs = other._refs.fetch_add(1);
		return *this;
	}
	~MappedModule();
	FARPROC GetProcAddress(const char* name) const;
	const Pe::PeNative& GetModule() const;
};