<!--
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
-->

# Locking your KasSigner with your own key

Step by step, from nothing. No experience with terminals is assumed.

## Tested on

| Unit | Chip | System and tool | Date | Result |
| --- | --- | --- | --- | --- |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | ESP32-P4, revision v1.3 | macOS, esptool 4.13.0 | 15 November 2026 | Every step run: locked from blank, Verified OK; updated with signed firmware; unsigned firmware refused; brought back with the signed firmware |
| M5Stack CoreS3 | ESP32-S3 | macOS, esptool 4.13.0 | 15 November 2026 | On a unit locked earlier: step 10b, and an update with signed firmware (1.2 MB in 18 seconds, in one go). Locking from blank (steps 8 and 9) not run with this guide |
| Waveshare ESP32-S3-Touch-LCD-2 | ESP32-S3 | macOS, esptool 4.13.0 | 15 November 2026 | On a unit locked earlier: step 10b, and an update with signed firmware (1.2 MB in 21 seconds, in one go). Locking from blank (steps 8 and 9) not run with this guide |

Steps 4 to 6 (the key, signing, checking) touch no unit and are the same
for all three. Step 10b and the update have been run on all three units.
For the two S3 units, locking from blank (steps 7 to 9) is written from
the tools' and the chip's source: it is the same bootloader code that
locked the P4, in the S3's own build.

Each step says what you should see. **If you see something else, stop there
and do not go on.**

## What this does, in plain words

A new unit runs any firmware anyone writes to it over USB. Locking changes
that for good:

- You make a **key**: a small file that only you have.
- You **sign** two release files with it. Signing adds your mark to a file
  without changing what the file does.
- You write the signed files to the unit and restart it once.
- On that restart the chip records your key's fingerprint in itself and
  closes its doors. From then on it runs only firmware signed with your
  key.

Three things to understand before you start:

| | |
| --- | --- |
| **It cannot be undone.** | The chip is changed physically. There is no reset, no factory mode, no way back. |
| **Lose the key and the unit is frozen.** | It keeps working with the firmware it has, and can never take an update. |
| **Anyone with a copy of the key can make firmware your unit will run.** | Keep it offline and private, like a seed. |

The key is **not** your wallet seed and has nothing to do with your coins.
It only decides which firmware your unit accepts.

Time needed: about 30 minutes the first time.

## What you need

- Your unit, **already working** with the release firmware, installed as in
  [INSTALL.md](INSTALL.md) steps 1 to 3, and showing the orange **Not provisioned**
  screen at start. Lock a unit only after you have seen it work.
- **No seed in it.** A unit keeps nothing when switched off, so this is
  true of any unit you have just restarted.
- A USB cable that carries data, plugged straight into the computer, not
  through a hub.
- Optional: an offline storage device, to keep a copy of the key.
- A charged unit (M5) or a steady USB port (Waveshare). Power must not drop
  during step 8.
- Three files from the KasSigner 1.1.1 release (next section).

## The release files

Everything comes from one page, the KasSigner 1.1.1 release:

**https://github.com/InKasWeRust/KasSigner/releases/tag/v1.1.1**

Scroll down to **Assets**. The release holds these files:

| File | What it is | Needed to lock? |
| --- | --- | --- |
| `kassigner-1.1.1-esp32s3-secure-bootloader.bin` | The Secure Boot bootloader for the two S3 units, unsigned | **yes**, M5 and Waveshare |
| `kassigner-1.1.1-partition-table.bin` | The flash layout for the two S3 units | **yes**, M5 and Waveshare |
| `kassigner-1.1.1-m5stack.bin` | The firmware for the M5Stack CoreS3 | **yes**, M5 only |
| `kassigner-1.1.1-waveshare.bin` | The firmware for the Waveshare ESP32-S3-Touch-LCD-2 | **yes**, Waveshare only |
| `kassigner-1.1.1-m5stack-full.bin` | Everything in one file, for a first install on a new M5 | no |
| `kassigner-1.1.1-waveshare-full.bin` | The same for the Waveshare | no |
| `kassigner-1.1.1-esp32p4-secure-bootloader.bin` | The Secure Boot bootloader for the P4, unsigned | **yes**, P4 only |
| `kassigner-1.1.1-partition-table-p4-secure.bin` | The flash layout for a locked P4 | **yes**, P4 only |
| `kassigner-1.1.1-p4.bin` | The firmware for the P4 | **yes**, P4 only |
| `kassigner-1.1.1-p4-full.bin` | Everything in one file, for a first install on a new P4 | no |
| `SHA256SUMS` | The list of every file's SHA-256 | to check the downloads |
| `KasSg111.txt` | That list's signature, made on a KasSigner | to check the list |
| `COPYING`, `THIRD_PARTY_NOTICES` | The licenses | no |

**Download three files**: the bootloader, the partition table, and the
firmware for your unit.

| Your unit | The three files |
| --- | --- |
| M5Stack CoreS3 | `kassigner-1.1.1-esp32s3-secure-bootloader.bin`, `kassigner-1.1.1-partition-table.bin`, `kassigner-1.1.1-m5stack.bin` |
| Waveshare ESP32-S3-Touch-LCD-2 | `kassigner-1.1.1-esp32s3-secure-bootloader.bin`, `kassigner-1.1.1-partition-table.bin`, `kassigner-1.1.1-waveshare.bin` |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | `kassigner-1.1.1-esp32p4-secure-bootloader.bin`, `kassigner-1.1.1-partition-table-p4-secure.bin`, `kassigner-1.1.1-p4.bin` |

The P4's bootloader and partition table are **not** the S3's. Each chip
takes only its own.

Mind the names: the firmware you need is the one **without** `-full`. The
`-full` file is for a first install only and must not be signed or used
here.

**Check them before you use them.** Download `SHA256SUMS` and
`KasSg111.txt` too, and follow [INSTALL.md](INSTALL.md) step 1: it shows
how to check the list's signature and each file's SHA-256 against the list.
Do not sign a file you have not checked.

---

## Step 1. Make a folder and put the files in it

1. On your Desktop, make a new folder named `kassigner-lock`.
2. Copy your three checked release files into it.

Nothing else goes in this folder.

## Step 2. Open a terminal in that folder

A terminal is a window where you type a command and press Enter. Every
command in this guide is typed there. Copy and paste each one exactly as it
is written.

| System | How |
| --- | --- |
| macOS | Open **Finder**. In the menu bar at the top choose **Go**, then **Utilities**. Double-click **Terminal**. In the window that opens, type `cd` and a space, then drag the `kassigner-lock` folder from your Desktop into that window, then press Enter. |
| Windows | Open the `kassigner-lock` folder. Click the address bar at the top, type `powershell`, press Enter. |
| Linux | Right-click inside the `kassigner-lock` folder and choose **Open in Terminal**. |

Check you are in the right place. Type this and press Enter:

| System | Command |
| --- | --- |
| macOS, Linux | `ls` |
| Windows | `dir` |

**You should see** the names of your three files. If not, you are in the
wrong folder: close the window and do this step again.

Keep this window open until the end. If you close it, come back to it with
this step, then run the line marked "every time" in step 3.

## Step 3. Install the tools

The tools are `esptool` and `espsecure`, made by Espressif, the company
that makes the chip. They run on Python, a free program.

**3a. Check that Python is there.**

| System | Command |
| --- | --- |
| macOS, Linux | `python3 --version` |
| Windows | `py --version` |

**You should see** `Python 3.` followed by a number of 7 or more, for
example `Python 3.9.6` or `Python 3.12.4`. Any of those is fine.

If not:

| System | What to do |
| --- | --- |
| macOS | A window may offer to install the "command line developer tools". Accept, wait for it to finish, and run the command again. |
| Windows | Install Python from python.org. In the installer, tick **Add python.exe to PATH**. Close the terminal, open it again (step 2), run the command again. |
| Linux | Install `python3` and `python3-venv` with your system's package manager. |

**3b. Make a private place for the tools**, inside your folder, so nothing
else on the computer is changed. Once only:

| System | Command |
| --- | --- |
| macOS, Linux | `python3 -m venv tools` |
| Windows | `py -m venv tools` |

It prints nothing. A folder named `tools` appears.

**3c. Switch that place on. Every time you open a new terminal:**

| System | Command |
| --- | --- |
| macOS, Linux | `source tools/bin/activate` |
| Windows | `tools\Scripts\Activate.ps1` |

**You should see** `(tools)` at the start of the line you type on.

On Windows, if it answers that running scripts is disabled, run this once
and then the command again:

```
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**3d. Install the tools.** Once only. This needs the internet. Two
commands, one after the other:

```
python -m pip install --upgrade pip
```

```
python -m pip install esptool==4.13.0
```

**You should see** lines scrolling and, at the end of the second,
`Successfully installed` with `esptool-4.13.0` in the list. Yellow lines
starting `WARNING` about a newer version of pip do not matter.

From now on the commands start with `python`, not `python3` or `py`: with
`(tools)` showing, `python` is the one inside your `tools` folder, on every
system.

**3e. Check them:**

```
python -m esptool version
```

**You should see** `esptool.py v4.13.0` and `4.13.0`.

From here on the computer can be offline. If you have a computer that never
touches the internet, steps 4 to 6 are best done on that one.

## Step 4. Make your key

Once in your life, for all your units:

```
python -m espsecure generate_signing_key --version 2 --scheme rsa3072 my-kassigner-key.pem
```

**You should see:**

```
RSA 3072 private key in PEM format written to my-kassigner-key.pem
```

A file named `my-kassigner-key.pem` is now in the folder. That file is your
key.

If you see `Key file my-kassigner-key.pem already exists`, you already made
one. **Do not delete it and make another** unless you are sure no unit was
locked with it.

**Now, before anything else:**

1. Decide where the key will live. It is one small file, and where you keep
   it is your choice.
2. Optional: copy `my-kassigner-key.pem` to an offline storage device and
   keep that device somewhere safe. If this computer's disk fails and there
   is no copy, the key is gone.
3. Never email it, never put it in a cloud folder, never give it to anyone,
   the KasSigner project included. Nobody ever needs it but you.

## Step 5. Sign the two files

**5a. The bootloader.** Use the line for your unit only.

M5Stack CoreS3 and Waveshare ESP32-S3-Touch-LCD-2:

```
python -m espsecure sign_data --version 2 --keyfile my-kassigner-key.pem --output bootloader-signed.bin kassigner-1.1.1-esp32s3-secure-bootloader.bin
```

Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5:

```
python -m espsecure sign_data --version 2 --keyfile my-kassigner-key.pem --output bootloader-signed.bin kassigner-1.1.1-esp32p4-secure-bootloader.bin
```

**You should see** lines like these:

```
1 signing key(s) found.
Signed 24576 bytes of data from kassigner-1.1.1-esp32s3-secure-bootloader.bin. Signature sector now has 1 signature blocks.
```

The number of bytes may differ. A line about "Padding data contents" may
come first. Both are normal.

**5b. The firmware.** Use the line for your unit only.

M5Stack CoreS3:

```
python -m espsecure sign_data --version 2 --keyfile my-kassigner-key.pem --output firmware-signed.bin kassigner-1.1.1-m5stack.bin
```

Waveshare ESP32-S3-Touch-LCD-2:

```
python -m espsecure sign_data --version 2 --keyfile my-kassigner-key.pem --output firmware-signed.bin kassigner-1.1.1-waveshare.bin
```

Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5:

```
python -m espsecure sign_data --version 2 --keyfile my-kassigner-key.pem --output firmware-signed.bin kassigner-1.1.1-p4.bin
```

**You should see** `1 signing key(s) found.` and a `Signed … bytes` line.
A line about "Padding data contents" may come first. That is normal.

Two new files are now in the folder: `bootloader-signed.bin` and
`firmware-signed.bin`. The release files are untouched.

## Step 6. Check both signatures

This proves each file carries a mark made by **your** key.

```
python -m espsecure verify_signature --version 2 --keyfile my-kassigner-key.pem bootloader-signed.bin
```

```
python -m espsecure verify_signature --version 2 --keyfile my-kassigner-key.pem firmware-signed.bin
```

**For each, you should see** this line:

```
Signature block 0 verification successful using the supplied key (RSA).
```

Lines saying `Signature block 1 invalid. Skipping.` and the same for
block 2 are normal: there is one signature, in block 0.

**Stop if you see** `Signature could not be verified with the provided key`
or `Invalid datafile`. Go back to step 5 and sign again.

**Check the signed bootloader's size:**

| System | Command |
| --- | --- |
| macOS, Linux | `ls -l bootloader-signed.bin` |
| Windows | `dir bootloader-signed.bin` |

**You should see** a number in the line. Compare it with your unit's row:

| Unit | Expected | Must not be more than |
| --- | --- | --- |
| M5Stack CoreS3, Waveshare ESP32-S3-Touch-LCD-2 | 28672 | 32768 |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | 32768 | 40960 |

If it is more than the last column, stop: the file would overwrite what
comes after it on the unit.

## Step 7. Connect the unit and look at it

Nothing is written in this step.

1. Unplug every other USB device that is a board, a serial adapter or a
   3D printer, so the tool finds only your unit.
2. Plug the unit in and switch it on.
3. Run the line for your unit.

M5Stack CoreS3 and Waveshare ESP32-S3-Touch-LCD-2:

```
python -m esptool --chip esp32s3 get_security_info
```

Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5:

```
python -m esptool --chip esp32p4 --no-stub get_security_info
```

**You should see**, among other lines:

- a line starting `Chip is` with `ESP32-S3`, or `ESP32-P4`
- on a P4, a revision in that same line: it must be **v1.3**
- `Secure Boot: Disabled`

and **no** mention of `Secure Download Mode`.

That means the tool can talk to your unit, and the unit is not locked yet.

If it cannot connect, put the unit in download mode by hand and run the
command again. Download mode is entered the same way on all three units:

1. Switch the unit off and unplug it.
2. Press the BOOT button and keep it pressed.
3. Plug the USB cable in.
4. Release the BOOT button.

Do not judge by the screen: it does not tell you whether the unit is in
download mode. The tool's answer does.

Where the buttons and the port are:

| Unit | BOOT button | Reset button | USB port to use |
| --- | --- | --- | --- |
| M5Stack CoreS3 | The one close to the USB port | The other one | Its only one |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | On the side, the one close to the green light | The middle one | The one **far** from the green light |
| Waveshare ESP32-S3-Touch-LCD-2 | The one marked **RST**, close to the red light, not the blue | The same one | Its only one |

On the Waveshare ESP32-S3-Touch-LCD-2 one button does both jobs. Wherever
this guide says BOOT or reset, it is the button marked RST: held while you
plug the cable in, it gives download mode; pressed briefly while the unit
is on, it restarts it.

**Stop if you see** `Secure Boot: Enabled` or `Secure Download Mode`: this
unit is already locked, with some key. Do not go on.

**Stop if a P4 shows any revision but v1.3.** The firmware does not run on
other revisions.

## Step 8. Write the files

**This step can still be undone.** It writes the three files and leaves the
unit waiting. Nothing is locked until step 9.

One command, on one line. `--after no_reset` is what makes the unit wait:
do not remove it.

M5Stack CoreS3 and Waveshare ESP32-S3-Touch-LCD-2:

```
python -m esptool --chip esp32s3 --after no_reset write_flash 0x0 bootloader-signed.bin 0x8000 kassigner-1.1.1-partition-table.bin 0x10000 firmware-signed.bin
```

Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5:

```
python -m esptool --chip esp32p4 --no-stub --after no_reset write_flash 0x2000 bootloader-signed.bin 0xC000 kassigner-1.1.1-partition-table-p4-secure.bin 0x10000 firmware-signed.bin
```

The three numbers (`0x0`, `0x8000`, `0x10000`, or the P4's `0x2000`,
`0xC000`, `0x10000`) are the places in the unit's memory where each file
goes. They are different for the two chips. Use your unit's line as it is.

How long it takes depends on the unit. On the P4 the firmware alone takes
about two minutes. Let it finish.

**You should see**, three times, one for each file, a line starting
`Wrote` and then `Hash of data verified.` The last two lines are
`Leaving...` and `Staying in bootloader.`

A line saying `WARNING: In case of failure, please set a specific
--flash_size.` near the start is normal.

**Stop if** the write fails, loses the connection or does not show
`Hash of data verified` three times. Nothing is locked. Unplug, plug in
again, and repeat step 7 and this step.

Whatever the unit's screen shows now, leave it. The unit is waiting.

## Step 9. The restart that locks the unit

**This is the one step that cannot be undone.** Read the list first.

- [ ] Step 6 showed `verification successful` for **both** files.
- [ ] Step 8 showed `Hash of data verified` **three** times.
- [ ] You know where your key is kept.
- [ ] The unit is charged or on a steady USB port, and nobody will unplug
      it in the next minute.

If every box is ticked, restart the unit:

| Unit | How |
| --- | --- |
| M5Stack CoreS3 | Press the reset button once, briefly: the one that is **not** close to the USB port. |
| Waveshare ESP32-S3-Touch-LCD-2 | Press the button marked RST once, briefly. |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | Press the reset button once, briefly: the **middle** one. |

Then **do not touch it**. Do not unplug it, do not press anything, until
the screen comes on. It takes a few seconds.

**You should see** the unit start, and its verification screen say
**Verified OK**, in teal, with the firmware's hash.

That is it: the unit is locked with your key.

## Step 10. Check the lock

**10a. On the unit.** The hash on the verification screen shows the first 8
and the last 8 characters of the firmware's SHA-256. Compare them with the
line for your unit's firmware file (`kassigner-1.1.1-m5stack.bin`,
`kassigner-1.1.1-waveshare.bin` or `kassigner-1.1.1-p4.bin`) in the
release's `SHA256SUMS`. They must match. Signing does not change this hash.

**10b. From the computer.** M5 and Waveshare S3: put the unit in download
mode by hand (as in step 7). P4: no need; the tool reaches it by itself.
Then the same line as in step 7. **Use the line for your unit only.**

M5Stack CoreS3 and Waveshare ESP32-S3-Touch-LCD-2:

```
python -m esptool --chip esp32s3 get_security_info
```

Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5:

```
python -m esptool --chip esp32p4 --no-stub get_security_info
```

**You should see** a `Chip is` line ending `in Secure Download Mode` and
the line `Secure Boot: Enabled`. This is what a locked P4 printed, and what
each line means:

| Line | Meaning |
| --- | --- |
| `Chip is ESP32-P4 in Secure Download Mode` | The chip only takes writes now. It cannot be read or reconfigured over USB. |
| `BLOCK_KEY0 - SECURE_BOOT_DIGEST0` | Your key's fingerprint is recorded in the chip. |
| `Secure Boot: Enabled` | The chip runs only what your key signed. |
| `Secure Boot Key1 is Revoked`, `Secure Boot Key2 is Revoked` | The two spare places for a key are closed. No other key can ever be added. |
| `Flash Encryption: Disabled` | As intended. KasSigner does not use it. |
| `JTAG: Permanently Disabled` | The chip's debug port is closed. |

**Is that fingerprint your key's?** The tool cannot show it once the chip is
locked. The unit itself is the proof: at every start the chip checks the
bootloader you signed against the recorded fingerprint, and starts only if
they match, so a unit that reaches **Verified OK** holds your key's. And
step 7, before you began, showed `Secure Boot: Disabled`: no other key was
there.

The tool's last line is `Hard resetting via RTS pin...`: it restarts the
unit, which starts normally again. If yours does not, press its reset
button.

**10c. Tidy up.**

1. Delete `my-kassigner-key.pem` from the `kassigner-lock` folder **only
   after** you have seen it in the place where you keep it.
2. Keep `bootloader-signed.bin`. You may need it again (see "If the screen
   stays black").
3. Write down, on paper, which units you locked with this key.

---

## If a command seems stuck, or you ran the wrong unit's line

Nothing is harmed. `get_security_info` only asks the chip a question.

- If the tool keeps printing `Connecting...` with rows of dots, or lists
  ports that are not your unit (`debug-console`, the name of a headset),
  press **Ctrl+C** (hold the Control key and press C). It stops and gives
  you the line to type on again.
- If you see `This chip is ESP32-P4, not ESP32-S3. Wrong --chip argument?`
  (or the other way round), you used the other unit's line. The message
  itself is good news: the unit answered, so it **is** in download mode.
  Press Ctrl+C if the tool is still going, then run your unit's line.
- To leave download mode, press the unit's reset button.

## If the screen stays black after step 9

With a lock in progress the unit prints no messages, so a black screen is
all it can show. Do not panic and do not keep pressing reset. Find out what
state it is in:

1. M5 and Waveshare S3: put the unit in download mode by hand (as in
   step 7). P4: no need; the tool reaches it by itself even when its
   screen is black.
2. Run the line from step 7 for your unit.

| What it says | What happened | What to do |
| --- | --- | --- |
| `Secure Boot: Disabled` | Nothing was locked. The chip refused because the two files were not both signed with the same key, or one was written wrongly. | Start again from step 5. Nothing is lost. |
| `Secure Boot: Enabled` and `Secure Download Mode` | The unit is locked with your key, but what is in it does not start. | Write your signed files again with the command in "Updating a locked unit", adding the bootloader and the table: see below. |

To write all three files again to a **locked** unit, M5 or Waveshare S3:

```
python -m esptool --chip esp32s3 --no-stub write_flash 0x0 bootloader-signed.bin 0x8000 kassigner-1.1.1-partition-table.bin 0x10000 firmware-signed.bin
```

P4:

```
python -m esptool --chip esp32p4 --no-stub write_flash 0x2000 bootloader-signed.bin 0xC000 kassigner-1.1.1-partition-table-p4-secure.bin 0x10000 firmware-signed.bin
```

then press reset. A locked unit always comes back with files signed by its
own key. That is why the key must never be lost.

## Updating a locked unit

When a new release comes out:

1. Download and check the new firmware file for your unit, as in
   [INSTALL.md](INSTALL.md) step 1. Put it in the `kassigner-lock` folder.
2. Put your key back in the folder from where you keep it.
3. Open the terminal there (step 2) and switch the tools on (step 3c).
4. Sign it, as in step 5b, with the new file's name. Check it, as in
   step 6.
5. M5 and Waveshare S3: put the unit in download mode by hand (as in
   step 7). P4: no need, leave it switched on and plugged in; the tool
   gets it there by itself.
6. Write it. M5 or Waveshare S3:

```
python -m esptool --chip esp32s3 --no-stub write_flash 0x10000 firmware-signed.bin
```

P4:

```
python -m esptool --chip esp32p4 --no-stub write_flash 0x10000 firmware-signed.bin
```

7. If the unit does not start by itself when the write ends, press its
   reset button. **You should see** Verified OK and the new firmware's
   hash.
8. Remove the key from the folder again.

Three things are different on a locked unit, all normal:

- The tool does **not** say `Hash of data verified`. A locked chip does not
  let the computer read back what it wrote. The unit's own screen is the
  proof.
- A line saying `WARNING: Security features enabled, so not changing any
  flash settings.`
- Only firmware signed with **your** key starts. The release's `-full`
  file, or any unsigned file, gives a black screen. Writing your signed
  file again fixes it.

How long the write takes, on a locked unit:

| Unit | 1.2 MB of firmware |
| --- | --- |
| M5Stack CoreS3 | about 18 seconds |
| Waveshare ESP32-S3-Touch-LCD-2 | about 21 seconds |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | about 2 minutes |

## If you lose the key, or think someone copied it

| | |
| --- | --- |
| **Lost** | The unit keeps working with its present firmware and can never be updated. There is no recovery and nobody can help, the project included. |
| **Copied** | Whoever has it can write firmware your unit will accept, if they also have the unit in their hands. Treat the unit as no longer trustworthy for a seed. The key cannot be changed on a locked unit. |

## The P4

The first P4 was locked with this guide on 15 November 2026: a Waveshare
ESP32-P4-WIFI6-Touch-LCD-3.5, chip revision v1.3. What that run showed:

| What | Result |
| --- | --- |
| The tool finds the unit by itself and reads `Chip is ESP32-P4 (revision v1.3)` | yes |
| The signed bootloader's size | 32768, as expected |
| Writing with `--no-stub` | Works, and says `Hash of data verified.` for each of the three files |
| The firmware's write | About two minutes |
| The first restart | The unit locked and started |
| The verification screen | **Verified OK** |
| Step 10b on the locked unit | Secure Download Mode, Secure Boot enabled, one key recorded, the two spare places revoked, JTAG disabled |
| Updating the locked unit with signed firmware | Works. With the unit switched on and showing Home, the tool connected by itself, no button pressed. |
| Unsigned firmware on the locked unit | **Refused**: black screen, the unit does not start. |
| Signed firmware written again | The unit starts again, Verified OK. The tool connected by itself to the black unit, no button pressed. |
| Long writes to the locked unit | Three of about 114 seconds each, none dropped. |

Every step of this guide has now been run on a P4.

The differences from the S3 units, all already in the steps above:

| | S3 units | P4 |
| --- | --- | --- |
| `--chip` | `esp32s3` | `esp32p4`, with `--no-stub` |
| Chip revision | any | v1.3 only |
| Bootloader file | `…-esp32s3-secure-bootloader.bin` | `…-esp32p4-secure-bootloader.bin` |
| Table file | `…-partition-table.bin` | `…-partition-table-p4-secure.bin` |
| Firmware file | `…-m5stack.bin`, `…-waveshare.bin` | `…-p4.bin` |
| Places in the write command | `0x0`, `0x8000`, `0x10000` | `0x2000`, `0xC000`, `0x10000` |
| Signed bootloader's size | 28672 expected, 32768 at most | 32768 expected, 40960 at most |

## Every command in this guide, and what it does

| Command | What it does | Touches your key? | Touches the unit? |
| --- | --- | --- | --- |
| `python3 -m venv tools` | Makes a private folder for the tools | no | no |
| `python -m pip install esptool==4.13.0` | Downloads Espressif's tools into it | no | no |
| `python -m espsecure generate_signing_key` | Makes your key file | makes it | no |
| `python -m espsecure sign_data` | Adds your key's mark to a copy of a file | reads it | no |
| `python -m espsecure verify_signature` | Checks a file's mark against your key | reads it | no |
| `python -m esptool get_security_info` | Asks the chip whether it is locked | no | reads |
| `python -m esptool write_flash` | Writes files to the unit | no | writes |

Nothing here is KasSigner's own program. Every command is Espressif's.
