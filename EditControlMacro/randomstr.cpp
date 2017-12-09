#include "stdafx.h"
#include "randomstr.h"

#include <random>
#include <functional>

#define WELLRANDOMLONG(x)  ((uint32)((double)WELLRNG512a() * 1000000000) % x)
#define WELLRANDOMLONG2(x) (uint32)((double)WELLRNG512a() * 1000000000)
uint8 GenRandomValueByte()
{
	std::random_device rd;
	std::mt19937 engine(rd());
	std::uniform_int_distribution<int> distribution(0, UCHAR_MAX);
	auto generator = bind(distribution, engine);
	uint32 init[16];
	for (uint32 i = 0; i < 16; i++)
		init[i] = generator();
	InitWELLRNG512a(init);
	try {
		return WELLRANDOMLONG(UCHAR_MAX);
	}
	catch (const std::exception& e) {
		return WELLRANDOMLONG2(UCHAR_MAX);
	}
}

uint16 GenRandomValueWord()
{
	std::random_device rd;
	std::mt19937 engine(rd());
	std::uniform_int_distribution<int> distribution(0, USHORT_MAX);
	auto generator = bind(distribution, engine);
	uint32 init[16];
	for (uint32 i = 0; i < 16; i++)
		init[i] = generator();
	InitWELLRNG512a(init);
	try {
		return WELLRANDOMLONG(USHORT_MAX);
	}
	catch (const std::exception& e) {
		return WELLRANDOMLONG2(USHORT_MAX);
	}
}

uint32 GenRandomValueDword()
{
	std::random_device rd;
	std::mt19937 engine(rd());
	std::uniform_int_distribution<int> distribution(0, UINT_MAX);
	auto generator = bind(distribution, engine);
	uint32 init[16];
	for (uint32 i = 0; i < 16; i++)
		init[i] = generator();
	InitWELLRNG512a(init);
	try {
		return WELLRANDOMLONG(UINT_MAX);
	}
	catch (const std::exception& e) {
		return WELLRANDOMLONG2(UINT_MAX);
	}
}

bool GenRandomString(uint8 * buf, const uint64 size)
{
	uint64 count = 0;
	uint8 remainder = 0;

	if (buf == NULL) {
		fprintf(stderr, "Invalid Address\n");
		return false;
	}
	if (size == 0) {
		fprintf(stderr, "Invalid Length\n");
		return false;
	}
	
	count = size / 4;
	remainder = size % 4;

	for (uint64 i = 0; i < count; i++) {
		*(uint32*)buf = GenRandomValueDword();
		buf += 4;
	}

	if (remainder == 0) return true;
	count = remainder / 2;
	remainder = remainder % 2;

	for (uint64 i = 0; i < count; i++) {
		*(uint16*)buf = GenRandomValueWord();
		buf += 2;
	}
	if (remainder == 0) return true;
	*buf = GenRandomValueByte();

	return true;
}
