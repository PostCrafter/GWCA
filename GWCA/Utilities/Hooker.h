#pragma once

#include <Windows.h>

namespace GW {

	// v1 hooker by 4D 1
	class Hook {
		void* tramp;
		void* target;
		size_t length;

	public:
		static size_t CalculateDetourLength(void *source);
		void* Detour(void *source, void *detour, size_t length);
		void Retour();
	};
}
