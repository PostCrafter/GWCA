#include "..\..\Utilities\Hooker.h"

extern "C" {
#include "..\..\..\Dependencies\disasm\ld32.h"
}

#define REL_DIST(p1, p2) ((size_t)(((uintptr_t)p1) - ((uintptr_t)p2)))

void GW::Hook::Retour() {
	DWORD old_protection;

	VirtualProtect(target, length, PAGE_READWRITE, &old_protection);
	memcpy(target, tramp, length);
	VirtualProtect(target, length, old_protection, &old_protection);

	delete[] tramp;
}

void* GW::Hook::Detour(void *target, void *detour, size_t length) {
	DWORD old_protection;

	this->target = target;
	this->length = length;

    char *tramp = new char[length + 5];
    this->tramp = tramp;

	VirtualProtect(tramp, length + 5, PAGE_EXECUTE_READWRITE, &old_protection);
	memcpy(tramp, target, length);
	tramp += length;
	tramp[0] = (char)0xE9;
	*(DWORD*)(tramp + 1) = (DWORD)(REL_DIST(target, tramp) - 5);

	VirtualProtect(target, length, PAGE_EXECUTE_READWRITE, &old_protection);
    char *_target = (char*)target;
	_target[0] = (char)0xE9;
	*(DWORD*)(_target + 1) = (DWORD)(REL_DIST(detour, _target) - 5);

#ifndef NDEBUG
	for (DWORD i = 5; i < length; i++)
		_target[i] = (char)0x90;
#endif

	VirtualProtect(target, length, old_protection, &old_protection);
	return this->target;
}

size_t GW::Hook::CalculateDetourLength(void *source) {

	unsigned int len = 0;
	unsigned int current_op;
    char *src = (char*)source;

	do {
		current_op = length_disasm(src);
		if (current_op != 0) {
			len += current_op;
			src += current_op;
		}
	} while (len < 5);

	return len;
}
