package main

import (
	"bytes"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/winlabs/gowin32"
)

func abort(funcname string, err error) {
	panic(fmt.Sprintf("%s failed: %v", funcname, err))
}

var (
	kernel32, _               = syscall.LoadLibrary("kernel32.dll")
	AmW, _                    = syscall.LoadLibrary("Api-ms-win-core-version-l1-1-0.dll")
	updateResource, _         = syscall.GetProcAddress(kernel32, "UpdateResourceW")
	beginUpdateResource, _    = syscall.GetProcAddress(kernel32, "BeginUpdateResourceW")
	endUpdateResource, _      = syscall.GetProcAddress(kernel32, "EndUpdateResourceW")
	findResource, _           = syscall.GetProcAddress(kernel32, "FindResourceW")
	loadLibrary, _            = syscall.GetProcAddress(kernel32, "LoadLibraryW")
	loadResource, _           = syscall.GetProcAddress(kernel32, "LoadResource")
	lockResource, _           = syscall.GetProcAddress(kernel32, "LockResource")
	freeLibrary, _            = syscall.GetProcAddress(kernel32, "FreeLibrary")
	sizeofResource, _         = syscall.GetProcAddress(kernel32, "SizeofResource")
	getSystemDefaultLangID, _ = syscall.GetProcAddress(kernel32, "GetUserDefaultLangID")
	getFileVersionInfoSize, _ = syscall.GetProcAddress(AmW, "GetFileVersionInfoSizeW")
	getFileVersionInfo, _     = syscall.GetProcAddress(AmW, "GetFileVersionInfoW")
)

const (
	FALSE           uint32 = 0
	TURE            uint32 = 1
	LANG_NEUTRAL           = 0x00
	SUBLANG_NEUTRAL        = 0x00
)

func GetFileVersionInfo(filename string, dwhand uint32, ledwlen uint32, lpdata *byte) uintptr {
	var nargs uintptr = 4
	r, _, callErr := syscall.SyscallN(uintptr(getFileVersionInfo),
		nargs,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(filename))),
		uintptr(dwhand),
		uintptr(ledwlen),
		uintptr(unsafe.Pointer(lpdata)),
	)
	if callErr != 0 {
		abort("Call GetFileVersionInfo", callErr)
	}
	return r
}

func GetFileVersionInfoSize(filename string, dwhandle *uint32) uint32 {
	var nargs uintptr = 2
	size, _, callErr := syscall.Syscall(uintptr(getFileVersionInfoSize),
		nargs,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(filename))),
		uintptr(unsafe.Pointer(dwhandle)),
		0,
	)
	fmt.Println("-------------------------------")
	if callErr != 0 {
		abort("Call GetFileVersionInfoSize", callErr)
	}
	return uint32(size)
}
func GetSystemDefaultLangID() uint16 {
	var nargs uintptr = 0
	gid, _, callErr := syscall.Syscall(uintptr(getSystemDefaultLangID),
		nargs,
		0,
		0,
		0,
	)
	if callErr != 0 {
		abort("Call GetSystemDefaultLangID", callErr)
	}
	return uint16(gid)
}
func SizeofResource(hModule, hResInfo uintptr) uintptr {
	var nargs uintptr = 2
	size, _, callErr := syscall.Syscall(uintptr(sizeofResource),
		nargs,
		hModule,
		hResInfo,
		0,
	)
	if callErr != 0 {
		abort("Call SizeofResource", callErr)
	}
	return size
}
func FreeLibrary(hLibModule uintptr) {
	var nargs uintptr = 1
	_, _, callErr := syscall.Syscall(uintptr(freeLibrary),
		nargs,
		hLibModule,
		0,
		0,
	)
	if callErr != 0 {
		abort("Call FreeLibrary", callErr)
	}
}
func LockResource(hResData uintptr) uintptr {
	var nargs uintptr = 1
	HMODLE, _, callErr := syscall.Syscall(uintptr(lockResource),
		nargs,
		hResData,
		0,
		0,
	)
	if callErr != 0 {
		abort("Call LoadResource", callErr)
	}
	return HMODLE
}
func LoadResource(HMODLE, HRSRC uintptr) uintptr {
	var nargs uintptr = 2
	HMODLE, _, callErr := syscall.Syscall(uintptr(loadResource),
		nargs,
		HMODLE,
		HRSRC,
		0,
	)
	if callErr != 0 {
		abort("Call LoadResource", callErr)
	}
	return HMODLE
}
func LoadLibrary(file string) uintptr {
	var nargs uintptr = 1
	HMODLE, _, callErr := syscall.Syscall(uintptr(loadLibrary),
		nargs,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(file))),
		0,
		0,
	)
	if callErr != 0 {
		abort("Call LoadLibrary", callErr)
	}
	return HMODLE
}
func UpdateResource(handle uintptr, lpType, lpName *uint16, wLanguage uint16, data *byte, cb uintptr) uintptr {
	var nargs uintptr = 6
	R, _, callErr := syscall.Syscall6(uintptr(updateResource),
		nargs,
		handle,
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(wLanguage),
		uintptr(unsafe.Pointer(data)),
		cb)
	if callErr != 0 {
		fmt.Println(callErr)
	}
	return R
}
func BeginUpdateResource(pFileName string, bDeleteExistingResources uint32) uintptr {
	var nargs uintptr = 2
	handle, _, callErr := syscall.Syscall(uintptr(beginUpdateResource),
		nargs,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(pFileName))),
		uintptr(unsafe.Pointer(&bDeleteExistingResources)),
		0,
	)
	if callErr != 0 {
		abort("Call UpdateResource", callErr)
	}
	return handle
}

func FindResource(handle uintptr, lpName, lpType *uint16) uintptr {
	var nargs uintptr = 3
	HRSRC, _, callErr := syscall.Syscall(uintptr(findResource),
		nargs,
		handle,
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpType)),
	)
	if callErr != 0 {
		abort("Call FindResource", callErr)
	}
	return HRSRC
}

func EndUpdateResource(handle uintptr, fDiscard uint32) {
	var nargs uintptr = 2
	_, _, callErr := syscall.Syscall(uintptr(endUpdateResource),
		nargs,
		handle,
		uintptr(unsafe.Pointer(&fDiscard)),
		0,
	)
	if callErr != 0 {
		abort("Call UpdateResource", callErr)
	}
}
func MAKEINTRESOURCE(id uintptr) *uint16 {
	return (*uint16)(unsafe.Pointer(id))
}

func MyReadSource(file string, lpname uintptr, lptype uintptr) []byte {
	HMODLE := LoadLibrary(file)
	HRSRC := FindResource(HMODLE, MAKEINTRESOURCE(lpname), MAKEINTRESOURCE(lptype))

	hGlobal := LoadResource(HMODLE, HRSRC)
	lockdata := LockResource(hGlobal)
	size := SizeofResource(HMODLE, HRSRC)
	q := (*byte)(unsafe.Pointer(lockdata))
	var buff *[64]byte
	var part [64]byte
	var result []byte
	for i := 0; i < (int(size)/64)+1; i++ {
		buff = (*[64]byte)(unsafe.Pointer(uintptr(unsafe.Pointer(q)) + uintptr(i*64)))
		part = *buff
		result = BytesCombine(result, part[:])
	}

	FreeLibrary(HMODLE)
	return result[0:int(size)]
}

func Str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

func Bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
func BytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}

func MAKELANGID(low8, hight8 int) uint16 {
	low := low8 & 0x00ff
	hight := hight8 >> 8
	number := hight
	number <<= 8
	number |= low
	return uint16(number)
}
func MyUpdate(file string, data []byte, lptype gowin32.ResourceType, lpname gowin32.ResourceId) {

	fileVsion, err := gowin32.GetFileVersion(file)
	if err != nil {
		fmt.Println("err 错误")
		fmt.Println(err)
	}
	Translations, err1 := fileVsion.GetTranslations()
	if err1 != nil {
		fmt.Println("err1 错误")
		fmt.Println(err1)
	}
	ResourceUpdate, err2 := gowin32.NewResourceUpdate(file, false)
	if err2 != nil {
		fmt.Println("err2 错误")
		fmt.Println(err2)
	}

	err3 := ResourceUpdate.Update(lptype, lpname, Translations[0].Language, data)
	if err3 != nil {
		fmt.Println(err3)
	}
	ResourceUpdate.Save()

}
