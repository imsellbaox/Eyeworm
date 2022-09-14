package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"runtime"

	"github.com/akavel/rsrc/binutil"
	"github.com/akavel/rsrc/coff"
	"github.com/akavel/rsrc/ico"
	"github.com/josephspurrier/goversioninfo"
)

const (
	MANIFEST  = 24
	GROUPICON = 14
	ICON      = 3
	MYCONFIG  = 55
)

type gRPICONDIR struct {
	ico.ICONDIR
	Entries []gRPICONDIRENTRY
}
type gRPICONDIRENTRY struct {
	ico.IconDirEntryCommon
	ID uint16
}

//go:generate go run PackSource.go
func main() {
	InitSyso()
}
func InitSyso() {
	osch := Ostrich{}
	ReadConfig(&osch)
	osch.IconPath = "main.ico"
	osch.ManifestPath = "main.manifest"
	osch.ConfigSource = "EyeConfig.json"
	osch.Build()
	osch.Walk()
	err := osch.WriteSyso("../resource.syso", runtime.GOARCH)
	if err != nil {
		fmt.Errorf("this err:", err)
	}
}

type Ostrich struct {
	goversioninfo.VersionInfo //匿名字段（嵌入）
	ConfigSource              string
}

func ReadConfig(vi *Ostrich) {
	configFile := "versioninfo.json"
	var err error
	var input = io.ReadCloser(os.Stdin)
	if input, err = os.Open(configFile); err != nil {
		log.Printf("Cannot open %q: %v", configFile, err)
		os.Exit(1)
	}
	jsonBytes, err := ioutil.ReadAll(input)
	input.Close()
	if err != nil {
		log.Printf("Error reading %q: %v", configFile, err)
		os.Exit(1)
	}
	// Parse the config.
	if err := vi.ParseJSON(jsonBytes); err != nil {
		log.Printf("Could not parse the .json file: %v", err)
		os.Exit(2)
	}
}

func (vi *Ostrich) WriteSyso(filename string, arch string) error {

	// Channel for generating IDs
	newID := make(chan uint16)
	go func() {
		for i := uint16(1); ; i++ {
			newID <- i
		}
	}()

	// Create a new RSRC section
	rsrc := coff.NewRSRC()

	// Set the architecture
	err := rsrc.Arch(arch)
	if err != nil {
		return err
	}

	// ID 16 is for Version Information
	rsrc.AddResource(16, 1, goversioninfo.SizedReader{bytes.NewBuffer(vi.Buffer.Bytes())})

	// If manifest is enabled
	if vi.ManifestPath != "" {

		manifest, err := binutil.SizedOpen(vi.ManifestPath)
		if err != nil {
			return err
		}
		defer manifest.Close()

		id := <-newID
		rsrc.AddResource(MANIFEST, id, manifest)
	}

	// If icon is enabled
	if vi.IconPath != "" {
		if err := addIcon(rsrc, vi.IconPath, newID); err != nil {
			return err
		}
	}

	if vi.ConfigSource != "" {

		config, err := binutil.SizedOpen(vi.ConfigSource)
		if err != nil {
			return err
		}
		defer config.Close()

		rsrc.AddResource(MYCONFIG, 16, config)
	}
	rsrc.Freeze()

	// Write to file
	return writeCoff(rsrc, filename)
}

func addIcon(coff *coff.Coff, fname string, newID <-chan uint16) error {
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	icons, err := ico.DecodeHeaders(f)
	if err != nil {
		return err
	}

	if len(icons) > 0 {
		// RT_ICONs
		group := gRPICONDIR{ICONDIR: ico.ICONDIR{
			Reserved: 0, // magic num.
			Type:     1, // magic num.
			Count:    uint16(len(icons)),
		}}
		gid := <-newID
		for _, icon := range icons {
			id := <-newID
			buff, err := bufferIcon(f, int64(icon.ImageOffset), int(icon.BytesInRes))
			if err != nil {
				return err
			}
			coff.AddResource(ICON, id, buff)
			group.Entries = append(group.Entries, gRPICONDIRENTRY{IconDirEntryCommon: icon.IconDirEntryCommon, ID: id})
		}
		coff.AddResource(GROUPICON, gid, group)
	}

	return nil
}

func bufferIcon(f *os.File, offset int64, size int) (*bytes.Reader, error) {
	data := make([]byte, size)
	_, err := f.ReadAt(data, offset)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

func (group gRPICONDIR) Size() int64 {
	return int64(binary.Size(group.ICONDIR) + len(group.Entries)*binary.Size(group.Entries[0]))
}
func writeCoff(coff *coff.Coff, fnameout string) error {
	out, err := os.Create(fnameout)
	if err != nil {
		return err
	}
	if err = writeCoffTo(out, coff); err != nil {
		return fmt.Errorf("error writing %q: %v", fnameout, err)
	}
	return nil
}
func writeCoffTo(w io.WriteCloser, coff *coff.Coff) error {
	bw := binutil.Writer{W: w}

	// write the resulting file to disk
	binutil.Walk(coff, func(v reflect.Value, path string) error {
		if binutil.Plain(v.Kind()) {
			bw.WriteLE(v.Interface())
			return nil
		}
		vv, ok := v.Interface().(binutil.SizedReader)
		if ok {
			bw.WriteFromSized(vv)
			return binutil.WALK_SKIP
		}
		return nil
	})

	err := bw.Err
	if closeErr := w.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	return err
}
