#pragma once

#include "Pe.hpp"
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

public:
	MappedModule(Logger logger, const std::vector<std::byte>& peBytes);
	~MappedModule();
	FARPROC GetProcAddress(const char* name) const;
	const Pe::PeNative& GetModule() const;
};