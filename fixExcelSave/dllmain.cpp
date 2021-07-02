#include <ctype.h>
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <string>
#include <map>
#include <ios>
#include <sstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <psapi.h>
#include <mutex>
#include "xlcall.h"
#include "detours.h"

/*
 * Bodge around poor implementation of parsing in excel 365 by adding a memoizer infront of the linear scan.
 * We retain pointers to addin functions, but do not own them.
 * 
 * see https://www.benf.org/excel/spill_performance/ for a description of the spill performance issue.
 * 
 * No guarantees are made that this will not corrupt internal state of excel.  
 * No guarantees are made that you will be happy.
 * Use at your own risk.
 * 
 * Don't load any addins without disabling and re-enabling. (which clears caches).
 */

#ifdef _WIN64
std::vector<std::vector<unsigned char>> needles { 
	{
	0x8b, 0xc2, 0x83, 0xe0, 0x02, 0x89, 0xff, 0xff,
	0x8b, 0xc2, 0x83, 0xe0, 0x04, 0x89, 0xff, 0xff,
	0x8b, 0xc2, 0x83, 0xe0, 0x08, 0x89, 0xff, 0xff,
	0x8b, 0xc2, 0x83, 0xe0, 0x10, 0x89, 0xff, 0xff,
	0x8b, 0xc2, 0x83, 0xe0, 0x40, 0x89 
	},
	{ // Older releases have a less optimised version?
	0x0f, 0xb6, 0xc2, 0x24, 0x01, 0xff, 0xff, 0xff,
	0xff, 0x0f, 0xb6, 0xc2, 0xd0, 0xe8, 0x24, 0x01, 
	0xff, 0xff, 0xff, 0xff, 0x0f, 0xb6, 0xc2, 0xc0, 
	0xe8, 0x02, 0x24, 0x01, 0xff, 0xff, 0xff, 0xff, 
	0x0f, 0xb6, 0xc2, 0xc0, 0xe8, 0x03, 0x24, 0x01
	}
};
std::vector<unsigned char> prelude {
	0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55
};
int scan_back = 1600;
#define PRFA1 __int64
#define PRFA7 __int16
#else
// ok, you want a 32 bit addin?  
std::vector<std::vector<unsigned char>> needles { {
	0x8b, 0xc1, 0x83, 0xe0, 0x02, 0x89, 0xff, 0xff, 0xff,
	0x8b, 0xc1, 0x83, 0xe0, 0x04, 0x89, 0xff, 0xff, 0xff,
	0x8b, 0xc1, 0x83, 0xe0, 0x08, 0x89, 0xff, 0xff, 0xff,
	0x8b, 0xc1, 0x83, 0xe0, 0x10, 0x89, 0xff, 0xff, 0xff,
} };
std::vector<unsigned char> prelude {
	0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x81, 0xEC, 0xCC, 0x00, 0x00, 0x00
};
int scan_back = 500;
#define PRFA1 int
#define PRFA7 int
#endif

/*
 * This is a very loose interpretation of the data structure, but it's good enough for our purposes.
 */
struct FuncListItem {
	int flags;
	FuncListItem* pNext;
	BSTR* pName;
};

int(__fastcall* pRealFuncScan)(PRFA1, FuncListItem*, FuncListItem**, FuncListItem**, wchar_t*, int, PRFA7) =
(int(__fastcall*)(PRFA1, FuncListItem*, FuncListItem**, FuncListItem**, wchar_t*, int, PRFA7))nullptr;

struct FsKey {
	const PRFA1 pMisc_; // not keying
	const FuncListItem* pInitFuncs_;
	const std::wstring name_;
	const PRFA7 flags_; // not keying

	FsKey(PRFA1 pMisc, FuncListItem* pInitFuncs, std::wstring name, PRFA7 flags)
		: pMisc_(pMisc), pInitFuncs_(pInitFuncs), name_(name), flags_(flags) { }

	bool operator==(const FsKey& other) const {
		return (pInitFuncs_ == other.pInitFuncs_ && name_ == other.name_ );
	}

	friend std::wostream& operator<<(std::wostream& os, const FsKey& obj);
};

std::wostream& operator<<(std::wostream& os, const FsKey& obj) {
	os << obj.name_;
	return os;
}

struct FsRes {
	FuncListItem* pResult_;
	FuncListItem* pLast_;
	int res_;

	FsRes() : pResult_(nullptr), pLast_(nullptr), res_(-1) {}
	FsRes(FuncListItem* pResult, FuncListItem* pLast, int res) : pResult_(pResult), pLast_(pLast), res_(res) {}
};

namespace std {
	template <>	struct hash<FsKey> {
		std::size_t operator()(const FsKey& k) const
		{
			using std::hash;
			using std::string;

			return (hash<wstring>()(k.name_));
		}
	};
}

struct CallStats {
	unsigned long totalCalls_;
	unsigned long cacheHits_;
	unsigned long cacheMisses_;
	unsigned long failures_;

public:
	CallStats() : totalCalls_(0), cacheHits_(0), cacheMisses_(0), failures_(0) {}
};

bool _debug = false;
bool _verify = false;
std::unordered_map<FsKey, FsRes> _known;
std::mutex _known_mutex;
CallStats _callStats = {};

int __fastcall myFuncScan(PRFA1 pMisc, FuncListItem* initFuncs_, FuncListItem** ppResult, FuncListItem** ppLast, wchar_t* name, int name_len, PRFA7 flags) {
	if (!(name_len < 128 && (FuncListItem*)name != initFuncs_ && initFuncs_ && initFuncs_->flags == 0x203)) {
		if (_debug) {
			OutputDebugStringA("Not checking cache");
		}
		return pRealFuncScan(pMisc, initFuncs_, ppResult, ppLast, name, name_len, flags);
	}

	// Don't bother tracking total calls if 
	InterlockedIncrement(&_callStats.totalCalls_);

	FsKey key(pMisc, initFuncs_, std::wstring(name, name_len), flags);

	if (_debug) {
		std::wstringstream ws;
		ws << L"Checking cache for " << key;
		OutputDebugStringW(ws.str().c_str());
	}
	auto prev = ([](const auto& k) {
		std::lock_guard<std::mutex> lg(_known_mutex);
		return _known.find(k); 
	})(key);
	
	if (prev != _known.end()) {
		if (_debug) {
			OutputDebugStringA("Cache hit");
		}
		const auto& res = prev->second;
		if (_verify) {
			auto test = pRealFuncScan(pMisc, initFuncs_, ppResult, ppLast, name, name_len, flags);
			if (test != res.res_ || *ppResult != res.pResult_ || *ppLast != res.pLast_) {
				if (test != res.res_) OutputDebugStringA("Mismatch on res");
				if (*ppResult != res.pResult_) OutputDebugStringA("Mismatch on pResult");
				if (*ppLast != res.pLast_) OutputDebugStringA("Mismatch on pLast");
				InterlockedIncrement(&_callStats.failures_);
				return test;
			}
		}
		*ppResult = res.pResult_;
		*ppLast = res.pLast_;
		InterlockedIncrement(&_callStats.cacheHits_);
		return res.res_;
	}

	InterlockedIncrement(&_callStats.cacheMisses_);
	if (_debug) {
		OutputDebugStringA("Cache miss - calling real lookup.");
	}

	int res = pRealFuncScan(pMisc, initFuncs_, ppResult, ppLast, name, name_len, flags);
	if (res != -1 && ppResult && *ppResult && ppLast && *ppLast) {
		FuncListItem* pRes = *ppResult;
		if (pRes->flags == 0x203) {
			if (pRes && pRes->pName) {
				if (_debug) {
					OutputDebugStringA("Storing cache entry.");
				}
				FsRes result(*ppResult, *ppLast, res);
				{
					std::lock_guard<std::mutex> lg(_known_mutex);
					_known[key] = result;
				}
				if (_debug) {
					std::stringstream ss;
					ss << "Cache size " << _known.size();
					OutputDebugStringA(ss.str().c_str());
				}
			}
			else if (_debug) {
				OutputDebugStringA("Miss, res did not have name.");
			}
		}
		else if (_debug) {
			OutputDebugStringA("Miss, res did not have 0x203");
		}
	}
	else {
		if (_debug) {
			if (res == -1) {
				OutputDebugStringA("Real func returned -1");
			}
			if (!(ppResult && *ppResult && ppLast && *ppLast)) {
				OutputDebugStringA("Return data looks bad");
			}
		}
	}
	return res;
}

// It's not worth linking in yara for something this simple (or even using a fast pattern search).
size_t mini_yara(const std::vector<unsigned char>& buffer, size_t start, size_t end, const std::vector<unsigned char>& needle) {
	if (buffer.size() <= needle.size() + start) return 0;
	auto fwd = end == 0 || start <= end;
	auto last = buffer.size() - needle.size();
	auto nsize = needle.size();
	if (fwd) {
		if (end && end < last) last = end;
		for (auto x = start; x < last; ++x) {
			for (auto y = static_cast<size_t>(0); y < nsize; ++y) {
				if (needle[y] == 0xff) continue;
				if (needle[y] != buffer[x + y]) goto cont;
			}
			return x;
		cont:
			continue;
		}
	} else {
		// going to search backwards for the prelude.
		for (auto x = start; x > end; --x) {
			for (auto y = static_cast<size_t>(0); y < nsize; ++y) {
				if (needle[y] == 0xff) continue;
				if (needle[y] != buffer[x + y]) goto cont2;
			}
			return x;
		cont2:
			continue;
		}
	}
	// it's never going to be at the start of the block. (famous last words).
	return 0;
}

void find_func() {
	HANDLE hProcess = GetCurrentProcess();
	unsigned char* p;
	MEMORY_BASIC_INFORMATION info;

	HMODULE hMods[1024];
	DWORD cbNeeded;
	HMODULE processModule = GetModuleHandleA(nullptr);

	HMODULE nextUp = 0;
	// We only need to search until the first module after our binary.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (auto i = static_cast<size_t>(0); i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (hMods[i] > processModule && (hMods[i] < nextUp || nextUp == 0)) {
				nextUp = hMods[i];
			}
		}
	}

	for (p = (unsigned char*)processModule;
		p < (unsigned char*)nextUp && VirtualQueryEx(hProcess, p, &info, sizeof(info)) != 0;
		p = (unsigned char*)info.BaseAddress + info.RegionSize) {

		std::vector<unsigned char> buffer;
		if (!(info.State == MEM_COMMIT && info.RegionSize)) continue;

		SIZE_T bytes_read;
		buffer.resize(info.RegionSize);
		ReadProcessMemory(hProcess, p, &buffer[0], info.RegionSize, &bytes_read);
		if (!bytes_read) continue;
		buffer.resize(bytes_read);

		size_t locn = 0;
		for (const auto& needle : needles) {
			locn = mini_yara(buffer, 0, 0, needle);
			if (locn != 0) break;
		}
		if (locn == 0) continue;

		OutputDebugStringA("Found needle");
		auto locn2 = mini_yara(buffer, locn, locn - scan_back, prelude);
		if (locn2 == 0) {
			OutputDebugStringA("Didn't find prelude.");
			continue;
		}
		if (locn2 > locn) {
			OutputDebugStringA("Found prelude after data!!");
			continue;
		}
		auto tgt = (size_t)info.BaseAddress + locn2;

		OutputDebugStringA("Found target function.");
		pRealFuncScan = (int(__fastcall*)(PRFA1, FuncListItem*, FuncListItem**, FuncListItem**, wchar_t*, int, PRFA7))tgt;
		return;
	}
	OutputDebugStringA("Finished reading mem, but didn't find needle.");
}

extern "C" __declspec(dllexport) int statsSpillSave() {
	std::stringstream ss;
	ss << "calls : " << _callStats.totalCalls_ << std::endl;
	ss << "hits  : " << _callStats.cacheHits_ << std::endl;
	ss << "misses: " << _callStats.cacheMisses_ << std::endl;
	// We only track panics if we verify.
	ss << "panics: " << _callStats.failures_ << std::endl;
	OutputDebugStringA(ss.str().c_str());
	return 1;
}

extern "C" __declspec(dllexport) int fixSpillSave(int enable, int debug, int verify) {

	if (!enable && pRealFuncScan) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		OutputDebugStringA("Removing memoizer.");
		DetourDetach(&(PVOID&)pRealFuncScan, myFuncScan);
		DetourTransactionCommit();
		pRealFuncScan = nullptr;
		return 1;
	}
	if (enable && pRealFuncScan == nullptr) {
		find_func();
		if (pRealFuncScan != nullptr) {
			{ // ok, that's paranoid.		
				std::lock_guard<std::mutex> lg(_known_mutex);
				_known.clear();
			}
			_debug = false;
			_verify = false;

			if (debug) {
				_debug = true;
				OutputDebugStringA("Enabling debug info");
			}
			if (verify) {
				_verify = true;
				OutputDebugStringA("Verifying results (slow)");
			}
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			OutputDebugStringA("Adding memoizer.");
			DetourAttach(&(PVOID&)pRealFuncScan, myFuncScan);
			DetourTransactionCommit();

			return 1;
		}
	}
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hInstance);
	}
	return TRUE;
}

// Even hackier version of tempstr12 - just use malloc, and don't bother to free ;)
LPXLOPER12 TempStr12(const std::wstring& str)
{
	const wchar_t* lpstr = str.c_str();
	int len = lstrlenW(lpstr);
	LPXLOPER12 lpx = (LPXLOPER12)malloc(sizeof(XLOPER12) + (len + 1) * 2);
	if (!lpx) return 0;
	XCHAR* lps = (XCHAR*)((CHAR*)lpx + sizeof(XLOPER12));

	lps[0] = (BYTE)len;
	wmemcpy_s(lps + 1, len + 1, lpstr, len);
	lpx->xltype = xltypeStr;
	lpx->val.str = lps;

	return lpx;
}

extern "C" __declspec(dllexport) int xlAutoOpen(void)
{
	static XLOPER12 xDLL;
	Excel12(xlGetName, &xDLL, 0);
	// Not even gonna put help in there ;)
	Excel12(xlfRegister, 0, 4, (LPXLOPER12)&xDLL, (LPXLOPER12)TempStr12(L"fixSpillSave"),   (LPXLOPER12)TempStr12(L"IIII"),  (LPXLOPER12)TempStr12(L"_spillFix"));
	Excel12(xlfRegister, 0, 4, (LPXLOPER12)&xDLL, (LPXLOPER12)TempStr12(L"statsSpillSave"), (LPXLOPER12)TempStr12(L"I"),     (LPXLOPER12)TempStr12(L"_spillFixStats"));
	Excel12(xlFree, 0, 1, (LPXLOPER12)&xDLL);
	return 1;
}