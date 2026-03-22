#include "kfirmware.h"

unsigned short cached_firmware;

int streq(const char *s1, const char *s2) {
    while (*s1 == *s2 && *s1) {
        s1++;
        s2++;
    }

    return *s1 == *s2;
}

typedef struct {
    unsigned short version;
    uint64_t offset;
} fw_entry_t;

unsigned short kget_firmware_from_base(uint64_t kernbase) {
    if (cached_firmware) {
        return cached_firmware;
    }

    const char *firmwareString = "firmware";

    static const fw_entry_t fw_table[] = {
        { 505, 0x7C7350},
        { 672, 0x827FB9},
        { 702, 0x827145},
        { 900, 0x7E1127},
        {1100, 0x8011AE},
        {1202, 0x7EB33E},
        {1250, 0x7EB3FE},
        {1300, 0x7EB57E}
    };

    for (int i = 0; i < sizeof(fw_table) / sizeof(fw_table[0]); i++) {
        char *addr = (char *)(kernbase + fw_table[i].offset);

        if (streq(addr, firmwareString)) {
            cached_firmware = fw_table[i].version;
            return fw_table[i].version;
        }
    }

    return 0;
}