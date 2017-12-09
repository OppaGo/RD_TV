#pragma once
#include "wellrandom.h"
#include "default.h"

static uint8 GenRandomValueByte();
static uint16 GenRandomValueWord();
static uint32 GenRandomValueDword();
extern bool GenRandomString(uint8* buf, const uint64 size);
