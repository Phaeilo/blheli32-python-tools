# BLHeli32 Python Tools

This repository contains Python scripts designed for working with BLHeli32
ESCs. The primary purpose is to dump firmware and configuration data from these
ESCs and decrypt it for analysis or modification. Future plans include adding
functionality to write or flash firmware back to the ESCs, restoring their
usability. These tools aim to breathe new life into BLHeli32 ESCs, which have
been rendered abandonware following the cessation of official support, ensuring
they remain functional and avoid becoming e-waste.

Validated so far on HAKRC_35A and HAKRC_AT421 and TEKKO_32_F4.

## Available Scripts

### `decrypt_hex.py`
Decrypts Intel HEX files containing BLHeli32 firmware.
Depending on the memory region, the appropriate key is used.
The decrypted firmware is written to a file with a `.decrypted` extension.

```bash
./decrypt_hex.py <hexfile1> [<hexfile2> ...]
```

### `dump_fw.py`
Extracts firmware from a BLHeli32 ESC by brute-forcing individual byte values using the `VERIFY` (0x40) command.
A guess strategy based on common prefixes/sequences is applied to make guessing and extraction more efficient.
```bash
./dump_fw.py -p <port> -n <esc-id> -o <offset> -l <length> -w <output_file>
```


### `flash_fw.py`
Writes new firmware from an unencrypted, binary file to an ESC. First, the flash contents are removed, then
the new firmware is uploaded, and finally the written data is verified. The configuration section is also replaced
with data from the binary file, hence existing ESC configuration is reset. Lastly, the header/license section is
populated with the correct serial number. It is not possible to overwrite or delete the bootloader, so if something
goes wrong the device shouldn't be bricked. This script is still pretty rough.


### `generate_guesses.py`
Reads binary data from `stdin` and generates a guessing strategy base on observed patterns.
Outputs a JSON document to `stdout` which can later be used to make `dump_fw.py` more efficient.
```bash
cat firmware.bin | ./generate_guesses.py > guess.json
```

### `read_cfg.py`
Reads and decrypts the configuration of a BLHeli32 ESC, as well as serial numbers and some other metadata.
It does not yet support parsing the actual configuration values, but the format is pretty straightforward
and also documented/reverse-engineered elsewhere.
```bash
./read_cfg.py -p <port> -n <esc-id> -v
```


### `fake_server.py`
Emulates some APIs of the blheli.org web server which are used by the official configurator.


## Planned Features
- Script to flash firmware, either BLHeli32 or FOSS alternatives
- Configuration parsing for `read_cfg.py`
- Improved guessing algorithms for `dump_fw.py`.

## Disclaimer
Use these tools at your own risk, improper use may result in bricked flash,
physical damage to hardware, or possibly severe injury. **Remove propellers
before sending commands to an ESC!** These tools are intended for research and
educational purposes, to learn more about BLHeli32. They are also intended to
"jailbreak" ESCs and either re-flash them with newer BLHeli32 versions or
easily convert them to FOSS firmwares without attaching a programmer.

## License
This project is licensed under the [GNU General Public License v3.0 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.html), see `LICENSE`. 
