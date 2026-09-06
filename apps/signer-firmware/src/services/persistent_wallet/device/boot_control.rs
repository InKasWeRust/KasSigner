//! Bootloader handoff and owner-firmware plaintext staging.
//!
//! Irreversible eFuse operations remain bootloader-owned. Production application
//! secure-provisioning application code can only arm a checksummed one-shot command and restart.
//! Normal production and development builds do not compile these mutating entry points.

#[cfg(feature="secure-provisioning-core")]
use sha2::{Digest, Sha256};
#[cfg(feature="secure-provisioning-core")]
use super::super::{flash::{AlignedBytes, SECTOR_SIZE}, PersistError, PersistentWallet};

#[cfg(feature="secure-provisioning-core")]
const BOOTCTL_BASE:u32=0x0061_0000;
#[cfg(feature="secure-provisioning-core")]
const OWNER_STAGE_BASE:u32=0x0041_0000;
#[cfg(feature="secure-provisioning-core")]
const OWNER_STAGE_SIZE:usize=0x0020_0000;
#[cfg(feature="secure-provisioning-core")]
const RECORD_SIZE:usize=128;
#[cfg(feature="secure-provisioning-core")]
const MAGIC:&[u8;8]=b"KSBCTL01";

#[cfg(feature="secure-provisioning-core")]
impl PersistentWallet<'_> {
    pub fn request_pop_it(&mut self) -> Result<(), PersistError> { self.write_boot_control(1,0,&[0;32],&[0;32]) }
    pub fn request_owner_enrollment(&mut self, digest:&[u8;32]) -> Result<(), PersistError> { self.write_boot_control(2,0,digest,&[0;32]) }
    pub fn stage_owner_firmware(&mut self, image:&[u8]) -> Result<[u8;32], PersistError> {
        if image.is_empty() || image.len()>OWNER_STAGE_SIZE { return Err(PersistError::OwnerFirmwareInvalid); }
        let digest:[u8;32]=Sha256::digest(image).into();
        let sectors=(image.len()+SECTOR_SIZE as usize-1)/SECTOR_SIZE as usize;
        for sector in 0..sectors {
            let mut block=AlignedBytes::<4096>::zeroed(); block.0.fill(0xff);
            let start=sector*4096; let end=core::cmp::min(start+4096,image.len());
            block.0[..end-start].copy_from_slice(&image[start..end]);
            self.flash.replace_sector(OWNER_STAGE_BASE+(sector as u32)*SECTOR_SIZE,&block)?;
        }
        Ok(digest)
    }
    pub fn request_owner_install(&mut self, size:u32, digest:&[u8;32]) -> Result<(), PersistError> {
        if size==0 || size as usize>OWNER_STAGE_SIZE { return Err(PersistError::OwnerFirmwareInvalid); }
        self.write_boot_control(3,size,&[0;32],digest)
    }
    fn write_boot_control(&mut self, op:u8, image_size:u32, owner_digest:&[u8;32], image_digest:&[u8;32]) -> Result<(), PersistError> {
        let mut record=AlignedBytes::<RECORD_SIZE>::zeroed();
        record.0[..8].copy_from_slice(MAGIC); record.0[8]=1; record.0[9]=op;
        record.0[12..16].copy_from_slice(&image_size.to_le_bytes());
        record.0[16..48].copy_from_slice(owner_digest); record.0[48..80].copy_from_slice(image_digest);
        let checksum:[u8;32]=Sha256::digest(&record.0[..96]).into(); record.0[96..128].copy_from_slice(&checksum);
        self.flash.replace_sector(BOOTCTL_BASE,&record)?; Ok(())
    }
}
