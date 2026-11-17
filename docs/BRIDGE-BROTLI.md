# Bridge: a fixed Brotli inside Pillow or opencv-python, before they ship one

**Wardlatch never does this for you.** It only reads, and it points here when the check finds a copy of Brotli's
decoder without the fix (CVE-2026-111497) inside a Python package whose own fixed release does not exist yet. What
follows is an opt-in step you take by hand, if you choose. It can be undone, and the package's next release or
reinstall replaces it.

## When this applies

`npx wardlatch@latest --incident brotli-2026-10` printed an EXPOSED line for a file like

```
EXPOSED  pillow 13.0.0  …/site-packages/PIL/.dylibs/libbrotlidec.1.2.0.dylib
EXPOSED  opencv-python 5.0.0.93  …/site-packages/cv2/.dylibs/libbrotlidec.1.1.0.dylib
```

and its fix says no fixed release of the package exists. Brotli's own fix (1.2.1, 21 Oct 2026) is out. The package
bundles its own copy of the library (delocate puts it in `<package>/.dylibs` on a Mac), so updating Brotli elsewhere
does not change it. The real fix is the package's next release. Until then, you can put a fixed Brotli in place of
the bundled copy.

**macOS only.** The steps below are for a Mac, where the copy is a `.dylib` in a `.dylibs` folder. On Linux the copies
are in `<dist>.libs` with renamed files, and the steps differ; they are not written here.

**Is it worth it?** The bundled decoder is used when the package decodes Brotli data: for example a WOFF2 font that
Pillow's FreeType reads, or an image codec that opencv loads. If nothing on this machine opens such files from
sources you do not trust, waiting for the release is reasonable.

## What you need

- Homebrew's Brotli at 1.2.1 or later: `brew install brotli` (or `brew upgrade brotli`), then check with
  `npx wardlatch@latest --incident brotli-2026-10`: the Homebrew brotli line must say SAFE.
- The folder Wardlatch named, the `.dylibs` folder holding the `libbrotli*.dylib` files.
- Xcode's Command Line Tools (`install_name_tool`, `codesign`; `xcode-select --install`).

## The swap (back up first)

Set `DIR` to the folder Wardlatch printed, without the file name. Close any program that uses this Python environment
first.

```bash
DIR='/path/to/site-packages/PIL/.dylibs'      # the .dylibs folder Wardlatch named
NEW="$(brew --prefix brotli)/lib"             # Homebrew's fixed Brotli
cd "$DIR" || exit 1

# 1. Back up every bundled Brotli library, next to it.
for f in libbrotli*.dylib; do cp -p "$f" "$f.wardlatch-backup"; done

# 2. Put Homebrew's library in place under each bundled name. It is made to load its partner from this folder, then
#    signed again (ad hoc), as macOS requires after any change to a library.
common=$(ls libbrotlicommon.*.dylib)
for f in libbrotli*.dylib; do
  part=${f%%.*}                                    # libbrotlidec, libbrotlicommon or libbrotlienc
  cp "$NEW/$part.1.dylib" "$f.new"
  chmod u+w "$f.new"
  install_name_tool -id "@loader_path/$f" "$f.new"
  install_name_tool -change @rpath/libbrotlicommon.1.dylib "@loader_path/$common" "$f.new"
  codesign --force --sign - "$f.new"
  mv "$f.new" "$f"
done
```

`install_name_tool` warns that its changes invalidate the code signature. That is expected: the `codesign` line
after it signs the file again.

## Check it

```bash
for f in libbrotli*.dylib; do otool -L "$f" | sed -n '2,4p'; codesign -v "$f" && echo "$f: signature ok"; done
npx wardlatch@latest --incident brotli-2026-10    # the line for this folder must now say SAFE
'/path/to/env/bin/python3' -c 'import PIL.ImageFont'   # or: -c 'import cv2'; the package still loads
```

Every `libbrotli*` line from `otool -L` must name `@loader_path/…` files that are in this folder, and
`/usr/lib/libSystem.B.dylib`, and nothing from `/opt/homebrew`. If the package fails to load, undo at once.

## Undo

```bash
cd "$DIR" || exit 1
for b in libbrotli*.dylib.wardlatch-backup; do mv "$b" "${b%.wardlatch-backup}"; done
```

This puts back the package's own files, byte for byte.

## A reinstall reverts it

`pip install --upgrade`, `pip install --force-reinstall`, `uv sync`, a new virtual environment, or any reinstall of
the package writes its own bundled copy again, without the fix, until the package ships a release with a fixed Brotli.
Run Wardlatch again after any of them. When the package's fixed release is out, upgrade to it and delete the
`.wardlatch-backup` files.

pip's record of the package (its `RECORD` file) still lists the original files' hashes, so a tool that verifies an
installed package against it reports these files as changed. That is this swap, and it is another reason to remove
it once the release is out.

## How this was checked

On 17 Nov 2026 the steps above were run, word for word, on copies of the `.dylibs` folders of Pillow 13.0.0 and
opencv-python 5.0.0.93 from a Mac, never on the installed packages. Then the undo was run. The checks:
`otool -L` showed the links above, `codesign -v` accepted every file, and the undo gave the original files back
byte for byte. On that Mac, Wardlatch's check already read both packages' bundled decoders as having the fix. So the
trial proved the mechanics (names, links, signatures, undo), not a change from unfixed to fixed. Wardlatch's check
after the swap is what tells you the copy now has the fix.
