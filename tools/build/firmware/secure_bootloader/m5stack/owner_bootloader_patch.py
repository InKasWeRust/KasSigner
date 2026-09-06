"""Source templates for KasSigner CoreS3 Secure Boot authority integration.

The templates are injected only into the repository-pinned ESP-IDF bootloader
sources.  Application firmware can request an operation through a dedicated,
checksummed plaintext boot-control sector, but all eFuse mutation and OTA
selection remain bootloader-owned.
"""
from __future__ import annotations

UTILITY_HELPER_ANCHOR = "static bool ota_has_initial_contents;\n"
LOAD_BOOT_ANCHOR = "void bootloader_utility_load_boot_image(const bootloader_state_t *bs, int start_index)\n{\n"
def digest_initializer(digest: bytes) -> str:
    if len(digest) != 32:
        raise SystemExit(
            f"Secure Boot v2 public-key digest must be 32 bytes, got {len(digest)}"
        )
    rows: list[str] = []
    for offset in range(0, len(digest), 8):
        rows.append(
            "    " + ", ".join(f"0x{value:02x}" for value in digest[offset : offset + 8]) + ","
        )
    return "\n".join(rows)


UTILITY_HELPERS_TEMPLATE = r'''

/* KasSigner owner-authority boot-control and OTA handoff.
 *
 * kassigner_bootctl is a dedicated plaintext one-sector partition.  Records
 * are accepted only after a software reset and only when their SHA-256 checksum
 * and operation-specific reserved fields are canonical.  The request is erased
 * before any irreversible eFuse operation or owner OTA activation.
 */
#define KASSIGNER_BOOTCTL_BASE 0x00610000U
#define KASSIGNER_BOOTCTL_RECORD_SIZE 128U
#define KASSIGNER_OWNER_STAGE_BASE 0x00410000U
#define KASSIGNER_OWNER_STAGE_SIZE 0x00200000U
#define KASSIGNER_BOOTCTL_VERSION 1U
#define KASSIGNER_BOOTCTL_OP_POP_IT 1U
#define KASSIGNER_BOOTCTL_OP_ENROLL_OWNER 2U
#define KASSIGNER_BOOTCTL_OP_INSTALL_OWNER 3U

#define KASSIGNER_OWNER_ONLY_AUTHORITY __KASSIGNER_OWNER_ONLY__

static const uint8_t kassigner_expected_provisioning_sbv2_digest[32] = {
__KASSIGNER_EXPECTED_DIGEST__
};

typedef struct {
    uint8_t operation;
    uint32_t image_size;
    uint8_t owner_digest[32];
    uint8_t image_digest[32];
} kassigner_bootctl_record_t;

esp_err_t kassigner_secure_boot_v2_authority_preflight(const esp_image_metadata_t *image_data);
esp_err_t kassigner_secure_boot_v2_verify_key_digest(
    uint32_t flash_offset, uint32_t image_len, const uint8_t expected[32]);

static uint32_t kassigner_read_le_u32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0])
           | ((uint32_t)bytes[1] << 8)
           | ((uint32_t)bytes[2] << 16)
           | ((uint32_t)bytes[3] << 24);
}

static bool kassigner_all_value(const uint8_t *bytes, size_t len, uint8_t value)
{
    for (size_t i = 0; i < len; ++i) {
        if (bytes[i] != value) {
            return false;
        }
    }
    return true;
}

static bool kassigner_bootctl_read(kassigner_bootctl_record_t *out)
{
    static const uint8_t magic[8] = { 'K', 'S', 'B', 'C', 'T', 'L', '0', '1' };
    uint8_t record[KASSIGNER_BOOTCTL_RECORD_SIZE];
    if (esp_rom_get_reset_reason(0) != RESET_REASON_CORE_SW
        || bootloader_flash_read(KASSIGNER_BOOTCTL_BASE, record, sizeof(record), false) != ESP_OK
        || memcmp(record, magic, sizeof(magic)) != 0
        || record[8] != KASSIGNER_BOOTCTL_VERSION
        || !kassigner_all_value(&record[10], 2, 0)
        || !kassigner_all_value(&record[80], 16, 0)) {
        return false;
    }

    uint8_t checksum[32];
    bootloader_sha256_handle_t sha = bootloader_sha256_start();
    if (sha == NULL) {
        return false;
    }
    bootloader_sha256_data(sha, record, 96);
    bootloader_sha256_finish(sha, checksum);
    if (memcmp(checksum, &record[96], sizeof(checksum)) != 0) {
        return false;
    }

    out->operation = record[9];
    out->image_size = kassigner_read_le_u32(&record[12]);
    memcpy(out->owner_digest, &record[16], sizeof(out->owner_digest));
    memcpy(out->image_digest, &record[48], sizeof(out->image_digest));

    bool owner_empty = kassigner_all_value(out->owner_digest, 32, 0);
    bool image_empty = kassigner_all_value(out->image_digest, 32, 0);
    bool owner_erased = kassigner_all_value(out->owner_digest, 32, 0xff);
    bool image_erased = kassigner_all_value(out->image_digest, 32, 0xff);
    switch (out->operation) {
    case KASSIGNER_BOOTCTL_OP_POP_IT:
        return out->image_size == 0U && owner_empty && image_empty;
    case KASSIGNER_BOOTCTL_OP_ENROLL_OWNER:
        return out->image_size == 0U && !owner_empty && !owner_erased && image_empty;
    case KASSIGNER_BOOTCTL_OP_INSTALL_OWNER:
        return out->image_size > 0U && out->image_size <= KASSIGNER_OWNER_STAGE_SIZE
               && owner_empty && !image_empty && !image_erased;
    default:
        return false;
    }
}

static bool kassigner_bootctl_consume(void)
{
    esp_err_t err = bootloader_flash_erase_sector(KASSIGNER_BOOTCTL_BASE / FLASH_SECTOR_SIZE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "KasSigner: could not consume boot-control request (0x%x)", err);
        return false;
    }
    uint8_t probe[16];
    if (bootloader_flash_read(KASSIGNER_BOOTCTL_BASE, probe, sizeof(probe), false) != ESP_OK
        || !kassigner_all_value(probe, sizeof(probe), 0xff)) {
        ESP_LOGE(TAG, "KasSigner: boot-control erase verification failed");
        return false;
    }
    return true;
}

static bool kassigner_bootctl_take(uint8_t operation, kassigner_bootctl_record_t *record)
{
    return kassigner_bootctl_read(record) && record->operation == operation && kassigner_bootctl_consume();
}

static bool kassigner_digest_for_purpose(
    esp_efuse_purpose_t purpose, unsigned revoke_index, uint8_t out[32])
{
    esp_efuse_block_t block;
    if (esp_efuse_get_digest_revoke(revoke_index)
        || !esp_efuse_find_purpose(purpose, &block)
        || esp_efuse_read_block(block, out, 0, 256) != ESP_OK) {
        return false;
    }
    return true;
}

static esp_err_t kassigner_burn_digest_if_missing(
    esp_efuse_purpose_t purpose, unsigned revoke_index, const uint8_t expected[32])
{
    uint8_t existing[32];
    if (kassigner_digest_for_purpose(purpose, revoke_index, existing)) {
        return memcmp(existing, expected, 32) == 0 ? ESP_OK : ESP_ERR_INVALID_STATE;
    }
    if (esp_efuse_get_digest_revoke(revoke_index)) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_efuse_block_t block = esp_efuse_find_unused_key_block();
    if (block == EFUSE_BLK_KEY_MAX) {
        return ESP_ERR_NOT_ENOUGH_UNUSED_KEY_BLOCKS;
    }
    return esp_efuse_write_key(block, purpose, expected, 32);
}

static bool kassigner_authority_state_matches(const uint8_t owner_digest[32])
{
#if KASSIGNER_OWNER_ONLY_AUTHORITY
    uint8_t owner[32];
    return kassigner_digest_for_purpose(ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0, 0, owner)
           && memcmp(owner, owner_digest, 32) == 0
           && memcmp(owner, kassigner_expected_provisioning_sbv2_digest, 32) == 0
           && esp_efuse_get_write_protect_of_digest_revoke(0)
           && esp_efuse_get_digest_revoke(1)
           && esp_efuse_get_digest_revoke(2);
#else
    uint8_t vendor[32];
    uint8_t owner[32];
    return kassigner_digest_for_purpose(ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0, 0, vendor)
           && kassigner_digest_for_purpose(ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, 1, owner)
           && memcmp(vendor, kassigner_expected_provisioning_sbv2_digest, 32) == 0
           && memcmp(owner, owner_digest, 32) == 0
           && esp_efuse_get_write_protect_of_digest_revoke(0)
           && esp_efuse_get_write_protect_of_digest_revoke(1)
           && esp_efuse_get_digest_revoke(2);
#endif
}

static esp_err_t kassigner_enroll_owner_digest(const uint8_t owner_digest[32])
{
    if (esp_secure_boot_enabled()) {
        return ESP_ERR_INVALID_STATE;
    }
#if KASSIGNER_OWNER_ONLY_AUTHORITY
    if (memcmp(owner_digest, kassigner_expected_provisioning_sbv2_digest, 32) != 0) {
        ESP_LOGE(TAG, "KasSigner: OWNERKEY.KAS does not match this owner-only build");
        return ESP_ERR_INVALID_ARG;
    }
    /* Never convert an already-authorized alternate key into owner-only by
     * silently revoking it. Sole-owner enrollment is permitted only when the
     * unused authority slots are genuinely empty or already revoked. */
    esp_efuse_block_t alternate_block;
    if ((!esp_efuse_get_digest_revoke(1)
         && esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, &alternate_block))
        || (!esp_efuse_get_digest_revoke(2)
            && esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2, &alternate_block))) {
        ESP_LOGE(TAG, "KasSigner: owner-only enrollment refuses an existing alternate Secure Boot authority");
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = kassigner_burn_digest_if_missing(
        ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0, 0, owner_digest);
    if (err == ESP_OK && !esp_efuse_get_digest_revoke(1)) {
        err = esp_efuse_set_digest_revoke(1);
    }
    if (err == ESP_OK && !esp_efuse_get_digest_revoke(2)) {
        err = esp_efuse_set_digest_revoke(2);
    }
    if (err == ESP_OK && !esp_efuse_get_write_protect_of_digest_revoke(0)) {
        err = esp_efuse_set_write_protect_of_digest_revoke(0);
    }
    if (err != ESP_OK || !kassigner_authority_state_matches(owner_digest)) {
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }
    ESP_LOGI(TAG, "KasSigner: owner-only Secure Boot authority enrolled; vendor authority absent");
    return ESP_OK;
#else
    esp_err_t err = kassigner_burn_digest_if_missing(
        ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0, 0, kassigner_expected_provisioning_sbv2_digest);
    if (err == ESP_OK) {
        err = kassigner_burn_digest_if_missing(
            ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, 1, owner_digest);
    }
    if (err != ESP_OK) {
        return err;
    }

    /* Permanently preserve both authorities and close the unused third slot. */
    if (!esp_efuse_get_digest_revoke(2)) {
        err = esp_efuse_set_digest_revoke(2);
    }
    if (err == ESP_OK && !esp_efuse_get_write_protect_of_digest_revoke(0)) {
        err = esp_efuse_set_write_protect_of_digest_revoke(0);
    }
    if (err == ESP_OK && !esp_efuse_get_write_protect_of_digest_revoke(1)) {
        err = esp_efuse_set_write_protect_of_digest_revoke(1);
    }
    if (err != ESP_OK || !kassigner_authority_state_matches(owner_digest)) {
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }
    ESP_LOGI(TAG, "KasSigner: official and owner Secure Boot authorities enrolled");
    return ESP_OK;
#endif
}

static bool kassigner_hash_stage(uint32_t length, uint8_t digest[32])
{
    uint8_t buffer[1024];
    bootloader_sha256_handle_t sha = bootloader_sha256_start();
    if (sha == NULL) {
        return false;
    }
    for (uint32_t offset = 0; offset < length; offset += sizeof(buffer)) {
        uint32_t chunk = MIN((uint32_t)sizeof(buffer), length - offset);
        if (bootloader_flash_read(KASSIGNER_OWNER_STAGE_BASE + offset, buffer, chunk, false) != ESP_OK) {
            uint8_t ignored[32];
            bootloader_sha256_finish(sha, ignored);
            return false;
        }
        bootloader_sha256_data(sha, buffer, chunk);
    }
    bootloader_sha256_finish(sha, digest);
    return true;
}

static esp_err_t kassigner_copy_stage_to_ota(const esp_partition_pos_t *target, uint32_t length)
{
    if (target == NULL || target->offset == 0 || target->size < length) {
        return ESP_ERR_INVALID_SIZE;
    }
    for (uint32_t offset = 0; offset < target->size; offset += FLASH_SECTOR_SIZE) {
        esp_err_t err = bootloader_flash_erase_sector((target->offset + offset) / FLASH_SECTOR_SIZE);
        if (err != ESP_OK) {
            return err;
        }
    }

    bool encrypted = esp_efuse_is_flash_encryption_enabled();
    uint8_t buffer[1024] __attribute__((aligned(16)));
    for (uint32_t offset = 0; offset < length; offset += sizeof(buffer)) {
        uint32_t chunk = MIN((uint32_t)sizeof(buffer), length - offset);
        if ((chunk & 0x0fU) != 0U) {
            return ESP_ERR_INVALID_SIZE;
        }
        esp_err_t err = bootloader_flash_read(KASSIGNER_OWNER_STAGE_BASE + offset, buffer, chunk, false);
        if (err == ESP_OK) {
            err = bootloader_flash_write(target->offset + offset, buffer, chunk, encrypted);
        }
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}

static esp_err_t kassigner_select_ota(const bootloader_state_t *bs, int target_index)
{
    if (bs->app_count != 2U || target_index < 0 || target_index >= (int)bs->app_count
        || bs->ota_info.offset == 0) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_ota_select_entry_t entries[2];
    if (bootloader_common_read_otadata(&bs->ota_info, entries) != ESP_OK) {
        return ESP_FAIL;
    }
    int active = bootloader_common_get_active_otadata(entries);
    uint32_t max_seq = 0;
    for (unsigned i = 0; i < 2; ++i) {
        if (bootloader_common_ota_select_valid(&entries[i]) && entries[i].ota_seq > max_seq) {
            max_seq = entries[i].ota_seq;
        }
    }
    if (max_seq >= UINT32_MAX - 2U) {
        return ESP_ERR_INVALID_STATE;
    }
    uint32_t seq = max_seq + 1U;
    while (((seq - 1U) % bs->app_count) != (uint32_t)target_index) {
        ++seq;
    }
    esp_ota_select_entry_t next;
    memset(&next, 0xff, sizeof(next));
    next.ota_seq = seq;
    next.ota_state = ESP_OTA_IMG_VALID;
    next.crc = bootloader_common_ota_select_crc(&next);
    unsigned destination = active == 0 ? 1U : 0U;
    bool encrypted = esp_efuse_is_flash_encryption_enabled();
    return write_otadata(&next, bs->ota_info.offset + destination * FLASH_SECTOR_SIZE, encrypted);
}

static bool kassigner_process_owner_boot_control(const bootloader_state_t *bs, int start_index)
{
    kassigner_bootctl_record_t record;
    if (!kassigner_bootctl_read(&record)) {
        return false;
    }

    if (record.operation == KASSIGNER_BOOTCTL_OP_ENROLL_OWNER) {
        if (esp_secure_boot_enabled() || start_index < 0 || start_index >= (int)bs->app_count) {
            return false;
        }
        esp_image_metadata_t image_data = { 0 };
        if (!try_load_partition(&bs->ota[start_index], &image_data)
            || kassigner_secure_boot_v2_authority_preflight(&image_data) != ESP_OK
            || !kassigner_bootctl_consume()) {
            return false;
        }
        esp_err_t err = kassigner_enroll_owner_digest(record.owner_digest);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "KasSigner: owner-key enrollment failed (%d)", err);
            return false;
        }
        bootloader_reset();
        return true;
    }

    if (record.operation != KASSIGNER_BOOTCTL_OP_INSTALL_OWNER || !esp_secure_boot_enabled()
        || start_index < 0 || start_index >= (int)bs->app_count || bs->app_count != 2U) {
        return false;
    }
    uint8_t owner_digest[32];
#if KASSIGNER_OWNER_ONLY_AUTHORITY
    if (!kassigner_digest_for_purpose(
            ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0, 0, owner_digest)
        || !esp_efuse_get_write_protect_of_digest_revoke(0)) {
        return false;
    }
#else
    if (!kassigner_digest_for_purpose(
            ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, 1, owner_digest)
        || !esp_efuse_get_write_protect_of_digest_revoke(1)) {
        return false;
    }
#endif
    uint8_t staged_digest[32];
    if (!kassigner_hash_stage(record.image_size, staged_digest)
        || memcmp(staged_digest, record.image_digest, 32) != 0
        || !kassigner_bootctl_consume()) {
        return false;
    }

    int target_index = start_index == 0 ? 1 : 0;
    const esp_partition_pos_t *target = &bs->ota[target_index];
    esp_err_t err = kassigner_copy_stage_to_ota(target, record.image_size);
    esp_image_metadata_t target_data = { 0 };
    if (err != ESP_OK || !check_anti_rollback(target) || !try_load_partition(target, &target_data)) {
        ESP_LOGE(TAG, "KasSigner: staged owner firmware did not pass standard boot verification");
        return false;
    }
    err = kassigner_secure_boot_v2_verify_key_digest(
        target_data.start_addr, target_data.image_len, owner_digest);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "KasSigner: staged firmware is not signed by enrolled owner key");
        return false;
    }
    err = kassigner_select_ota(bs, target_index);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "KasSigner: verified owner firmware could not be selected (%d)", err);
        return false;
    }
    ESP_LOGI(TAG, "KasSigner: owner firmware verified and selected in OTA slot %d", target_index);
    bootloader_reset();
    return true;
}
'''
