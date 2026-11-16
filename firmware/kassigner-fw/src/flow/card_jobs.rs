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

//! Settings' SD Card screen and Format, and the card jobs: what each asks of
//! the card and what it came to.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// Settings' SD Card: what the probe found, and two buttons shown only
    /// while a card is in.
    pub(super) fn on_card(&mut self, event: Event<'_>) -> Option<Command> {
        match event {
            Event::Card(outcome) => {
                self.card = match outcome {
                    Outcome::Present(kind) => card::Status::Present(kind),
                    _ => card::Status::Absent,
                };
                None
            }
            Event::Tap { x, y } => match sd_card::target(self.scale, self.card, x, y)? {
                sd_card::Target::Nav(Nav::Home) => {
                    self.state = State::Home;
                    None
                }
                sd_card::Target::Nav(_) => {
                    self.state = self.settings_at(Setting::SdCard);
                    None
                }
                sd_card::Target::Format => {
                    self.state = State::CardFormat {
                        armed: false,
                        held_since: None,
                    };
                    None
                }
                sd_card::Target::Test => {
                    self.state = State::CardBusy(Job::Test);
                    Some(Command::Card(Job::Test))
                }
            },
            _ => None,
        }
    }

    /// Format asks as Delete does: a tap arms it, a finger held for
    /// [`HOLD_US`] formats, and lifting or sliding off first cancels.
    pub(super) fn on_card_format(
        &mut self,
        event: Event<'_>,
        armed: bool,
        held_since: Option<u64>,
    ) -> Option<Command> {
        match self.hold(event, armed, held_since) {
            Hold::Nothing => {}
            Hold::Cancel => self.state = State::Card,
            Hold::Home => self.state = State::Home,
            Hold::Arm => {
                self.state = State::CardFormat {
                    armed: true,
                    held_since: None,
                }
            }
            Hold::Down => {
                self.state = State::CardFormat {
                    armed,
                    held_since: Some(self.now_us),
                }
            }
            Hold::Done => {
                self.state = State::CardBusy(Job::Format);
                return Some(Command::Card(Job::Format));
            }
        }
        None
    }

    /// What a card job came to: shown, or a save's next step.
    pub(super) fn on_card_job(&mut self, job: Job, outcome: Outcome) -> Option<Command> {
        // A card that stopped answering is gone.
        if outcome == Outcome::Absent {
            self.card = card::Status::Absent;
        }
        // The file a save would write over, read to be checked.
        if job == Job::Read && core::mem::take(&mut self.replacing) {
            return match outcome {
                Outcome::Read(n) => self.start_replacing(n),
                other => {
                    self.replace_failed(other);
                    None
                }
            };
        }
        match (job, outcome) {
            // The pattern and the next free number, to keep or change.
            (Job::NextName, Outcome::NextName(n)) => {
                self.typed.clear();
                for c in self.saving.pattern().0 {
                    self.typed.insert(c);
                }
                for div in [1000, 100, 10, 1] {
                    self.typed.insert(b'0' + ((n / div) % 10) as u8);
                }
                self.state = State::BackupName { page: 0 };
            }
            (Job::Exists, Outcome::Exists(true)) => self.state = State::BackupOverwrite,
            (Job::Exists, Outcome::Exists(false)) => return self.named(),
            // An empty list is not a failure: said in teal, then back to
            // [`Self::list_exit`], not to the list a delete emptied.
            (Job::ListText, Outcome::Listed { count: 0, .. }) => {
                self.card_exit = self.list_exit();
                self.since_us = self.now_us;
                self.state = State::CardDone { job, outcome };
            }
            (Job::ListText, Outcome::Listed { count, extra }) => {
                self.listed = usize::from(count).min(RESTORE_MAX);
                self.extra = extra;
                self.state = State::RestoreList { page: 0 };
            }
            (
                Job::List | Job::ListGroups | Job::ListAddresses | Job::ListCards | Job::ListPhotos,
                Outcome::Listed { count: 0, .. },
            ) => {
                self.card_exit = self.list_exit();
                self.since_us = self.now_us;
                self.state = State::CardDone { job, outcome };
            }
            (
                Job::List | Job::ListGroups | Job::ListAddresses | Job::ListCards | Job::ListPhotos,
                Outcome::Listed { count, extra },
            ) => {
                self.listed = usize::from(count).min(RESTORE_MAX);
                self.extra = extra;
                self.state = State::RestoreList { page: 0 };
            }
            (Job::Read, Outcome::Read(n)) if self.listing == Listing::Captions => {
                self.caption_read(n);
            }
            (Job::Read, Outcome::Read(n)) if self.listing == Listing::Photos => {
                self.photo_len = n;
                if self.stego_import {
                    self.state = State::StegoReading;
                } else {
                    self.photo_chosen();
                }
            }
            (Job::Write, Outcome::Written) if self.saving == Saving::Stego => {
                // The seed in use now has a backup, in a photo.
                self.mark_backed();
                self.stego_over();
                self.state = State::StegoDone;
            }
            (Job::Read, Outcome::Read(n)) => {
                self.file_len = n;
                self.start_opening();
            }
            // Deleted: the list again, by its own pattern, to show what is
            // left.
            (Job::Delete, Outcome::Deleted) => {
                let list = self.list_job();
                self.backup_name = self.list_pattern();
                self.state = State::CardBusy(list);
                return Some(Command::Card(list));
            }
            _ => {
                if self.stego_live && matches!(job, Job::Write | Job::Read) {
                    // An import keeps its descriptor for the keyboard it
                    // goes back to.
                    if self.stego_import {
                        self.unhide_over();
                    } else {
                        self.stego_over();
                    }
                }
                // The seed in use now has a backup.
                if job == Job::Write
                    && matches!(outcome, Outcome::Written)
                    && self.saving == Saving::Backup
                {
                    self.mark_backed();
                }
                if matches!(job, Job::Write | Job::Read) {
                    // A signed transaction, descriptor or card's line went
                    // from the request's buffer.
                    if job == Job::Write
                        && matches!(
                            self.saving,
                            Saving::Reply | Saving::Descriptor | Saving::Card
                        )
                    {
                        let n = self.file_len.min(self.buffers.request.len());
                        wipe::wipe(&mut self.buffers.request[..n]);
                    }
                    wipe::wipe(&mut self.file);
                    self.file_len = 0;
                    self.first.clear();
                }
                // A read for a delete fails as a delete.
                let job = if self.deleting && job == Job::Read {
                    Job::Delete
                } else {
                    job
                };
                self.since_us = self.now_us;
                self.state = State::CardDone { job, outcome };
            }
        }
        None
    }

    /// What a card job names, writes, reads or lists.
    pub fn card_request(&mut self) -> Request<'_> {
        // Message and transaction files: read whole into the request's
        // buffer, whose size bounds the list.
        let text = matches!(
            self.listing,
            Listing::Messages | Listing::Captions | Listing::Transactions
        ) && matches!(self.state, State::CardBusy(Job::Read | Job::ListText));
        // Descriptor files and cards' lines: read into the request's buffer,
        // up to the largest.
        let group = matches!(self.listing, Listing::Groups | Listing::Cards)
            && matches!(self.state, State::CardBusy(Job::Read | Job::ListGroups));
        // A signed message is written from the document, sealed or not; a
        // signed transaction from the request's buffer.
        let writing = matches!(self.state, State::CardBusy(Job::Write));
        // A photo is read into its buffer, and one with a backup in it
        // written from its own.
        let photo = self.listing == Listing::Photos
            && matches!(self.state, State::CardBusy(Job::Read | Job::ListPhotos));
        let stego =
            self.saving == Saving::Stego && matches!(self.state, State::CardBusy(Job::Write));
        // The file a save would overwrite is read into the save's buffer,
        // still empty.
        let old = self.replacing && matches!(self.state, State::CardBusy(Job::Read));
        let record = self.saving == Saving::Signature && writing;
        // A descriptor or card's line, sealed, outgrows the flow's file: it
        // goes from the request's buffer.
        let reply = matches!(
            self.saving,
            Saving::Reply | Saving::Descriptor | Saving::Card
        ) && writing;
        // Listing photos keeps each long name past the payloads in the photo
        // output buffer.
        if self.listing == Listing::Photos && self.state == State::CardBusy(Job::ListPhotos) {
            return Request {
                name: self.backup_name,
                file: &mut *self.buffers.photo,
                len: self.file_len,
                names: &mut self.backups,
                long: &mut self.buffers.photo_out[LONG_AT..LONG_AT + LONG_BYTES],
            };
        }
        Request {
            name: self.backup_name,
            file: if old {
                match self.saving {
                    Saving::Signature => &mut *self.buffers.document,
                    Saving::Reply | Saving::Descriptor | Saving::Card => &mut *self.buffers.request,
                    Saving::Backup
                    | Saving::Kpub(_)
                    | Saving::Address
                    | Saving::GroupAddress
                    | Saving::Stego => &mut self.file,
                }
            } else if group {
                let end = GROUP_FILE_MAX.min(self.buffers.request.len());
                &mut self.buffers.request[..end]
            } else if photo {
                &mut *self.buffers.photo
            } else if stego {
                &mut *self.buffers.photo_out
            } else if text || reply {
                &mut *self.buffers.request
            } else if record {
                &mut *self.buffers.document
            } else {
                &mut self.file
            },
            len: self.file_len,
            names: &mut self.backups,
            long: &mut [],
        }
    }
}
