/*
 * console_scan.h — Stateless console scan system (from ps4debug v1.1.19)
 *
 * Adds these commands alongside the existing Frame4 scanner:
 *
 *   CMD_CONSOLE_SCAN_START  (0xBDAACC01) — Full-featured scan, streams offset+value
 *   CMD_CONSOLE_SCAN_RESCAN (0xBDAACC02) — Rescan/narrow previous results
 *   CMD_CONSOLE_SCAN_GETRES (0xBDAACC03) — Read values at matched addresses
 *   CMD_CONSOLE_SCAN_DISC   (0xBDAACC06) — Disconnect ack
 *
 * The existing CMD_PROC_SCAN (0xBDAA0009) and its file-based result handlers
 * (0xBDAA000D, 0xBDAA000E) remain unchanged for backward compatibility.
 *
 * All scan code is stateless — no globals, no file I/O, thread-safe.
 */

#ifndef _CONSOLE_SCAN_H
#define _CONSOLE_SCAN_H

#include <ps4.h>
#include "kdbg.h"
#include "net.h"
#include "proc.h"
#include "protocol.h"

/* ========================================================================
 * Constants
 * ======================================================================== */

#define SCAN_TERMINATOR 0xFFFFFFFFFFFFFFFFULL

/* Value types — must match protocol.h cmd_proc_scan_valuetype */
#define CS_VALTYPE_UINT8    0
#define CS_VALTYPE_INT8     1
#define CS_VALTYPE_UINT16   2
#define CS_VALTYPE_INT16    3
#define CS_VALTYPE_UINT32   4
#define CS_VALTYPE_INT32    5
#define CS_VALTYPE_UINT64   6
#define CS_VALTYPE_INT64    7
#define CS_VALTYPE_FLOAT    8
#define CS_VALTYPE_DOUBLE   9
#define CS_VALTYPE_BYTES    10

/* Compare types — must match protocol.h cmd_proc_scan_comparetype */
#define CS_CMP_EXACT            0
#define CS_CMP_FUZZY            1
#define CS_CMP_BIGGER_THAN      2
#define CS_CMP_SMALLER_THAN     3
#define CS_CMP_BETWEEN          4
#define CS_CMP_INCREASED        5
#define CS_CMP_INCREASED_BY     6
#define CS_CMP_DECREASED        7
#define CS_CMP_DECREASED_BY     8
#define CS_CMP_CHANGED          9
#define CS_CMP_UNCHANGED        10
#define CS_CMP_UNKNOWN_INIT     11
#define CS_CMP_DECREASED_RANGE  12

static const uint64_t cs_value_type_sizes[10] = { 1, 1, 2, 2, 4, 4, 8, 8, 4, 8 };

/* Lookup tables for 0xBDAACC01/02 protocol flow control */
static const uint8_t cs_cmptype_needs_value[13]    = { 1,1,1,1,1, 0,1,0,1, 0,0,0, 1 };
static const uint8_t cs_cmptype_needs_extra[13]    = { 0,0,0,0,1, 0,0,0,0, 0,0,0, 0 };
static const uint8_t cs_cmptype_needs_previous[13] = { 0,0,0,0,0, 1,1,1,1, 1,1,0, 0 };

/* First-scan bitmask: bits 0,1,2,3,6,8,12. Mode 4 (BETWEEN) has explicit bypass. */
#define CS_FIRST_SCAN_BITMASK 0x114F

#define CS_FUZZY_FLOAT_EPSILON  1.0f
#define CS_FUZZY_DOUBLE_EPSILON 1.0

/* Buffer sizes */
#define CS_SIMPLE_READ_BUF    0x4000   /* 16KB — simple scan */
#define CS_START_READ_BUF     0x8000   /* 32KB — full scan */
#define CS_START_SEND_BUF     0x10000  /* 64KB — send buffer */
#define CS_FLUSH_THRESHOLD    0xFFE8
#define CS_RESCAN_READ_BUF    0x8000   /* 32KB — rescan */
#define CS_RESCAN_RESULT_BUF  0x8000   /* 32KB — rescan result buffer */
#define CS_GETRES_BUF_SIZE    0x10000  /* 64KB — get-results */

/* ========================================================================
 * Packet structures for new commands
 * ======================================================================== */

/* CMD_CONSOLE_SCAN_START (0xBDAACC01) — 23 bytes */
struct cs_scan_request_full {
    uint32_t pid;             /* +0x00 */
    uint64_t start_addr;      /* +0x04 */
    uint32_t scan_length;     /* +0x0C */
    uint8_t  value_type;      /* +0x10 */
    uint8_t  cmp_type;        /* +0x11 */
    uint8_t  scan_step;       /* +0x12 */
    uint32_t data_len;        /* +0x13 */
} __attribute__((packed));

/* CMD_CONSOLE_SCAN_RESCAN (0xBDAACC02) — 18 bytes */
struct cs_scan_request_rescan {
    uint32_t pid;             /* +0x00 */
    uint64_t base_addr;       /* +0x04 */
    uint8_t  value_type;      /* +0x0C */
    uint8_t  cmp_type;        /* +0x0D */
    uint32_t data_len;        /* +0x0E */
} __attribute__((packed));

/* ========================================================================
 * Comparison engine
 *
 * Fixes applied vs the original reference:
 *   - CMP_EXACT: value_size == 0 (was <= 1, broke 1-byte scans)
 *   - CMP_INCREASED_BY double: DBL(search_val) (was FLT, lost precision)
 *   - CMP_DECREASED_BY: added float/double cases (were missing entirely)
 * ======================================================================== */

static inline int cs_scan_compare(uint8_t cmp_type, uint8_t value_type,
                                  uint64_t value_size,
                                  const void *search_val,
                                  const void *mem_val,
                                  const void *extra_val)
{
    #define U8(p)   (*(const uint8_t  *)(p))
    #define S8(p)   (*(const int8_t   *)(p))
    #define U16(p)  (*(const uint16_t *)(p))
    #define S16(p)  (*(const int16_t  *)(p))
    #define U32(p)  (*(const uint32_t *)(p))
    #define S32(p)  (*(const int32_t  *)(p))
    #define U64(p)  (*(const uint64_t *)(p))
    #define S64(p)  (*(const int64_t  *)(p))
    #define FLT(p)  (*(const float    *)(p))
    #define DBL(p)  (*(const double   *)(p))

    switch (cmp_type) {
    case CS_CMP_EXACT:
        /* FIX: was (value_size <= 1) which broke uint8/int8 exact scans */
        if (value_size == 0) return 0;
        return memcmp(search_val, mem_val, value_size) == 0;

    case CS_CMP_FUZZY: {
        if (value_type == CS_VALTYPE_FLOAT) {
            float diff = FLT(search_val) - FLT(mem_val);
            if (diff < 0) diff = -diff;
            return diff < CS_FUZZY_FLOAT_EPSILON;
        }
        if (value_type == CS_VALTYPE_DOUBLE) {
            double diff = DBL(search_val) - DBL(mem_val);
            if (diff < 0) diff = -diff;
            return diff < CS_FUZZY_DOUBLE_EPSILON;
        }
        return 0;
    }

    case CS_CMP_BIGGER_THAN:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  return U8(mem_val)  > U8(search_val);
        case CS_VALTYPE_INT8:   return S8(mem_val)  > S8(search_val);
        case CS_VALTYPE_UINT16: return U16(mem_val) > U16(search_val);
        case CS_VALTYPE_INT16:  return S16(mem_val) > S16(search_val);
        case CS_VALTYPE_UINT32: return U32(mem_val) > U32(search_val);
        case CS_VALTYPE_INT32:  return S32(mem_val) > S32(search_val);
        case CS_VALTYPE_UINT64: return U64(mem_val) > U64(search_val);
        case CS_VALTYPE_INT64:  return S64(mem_val) > S64(search_val);
        case CS_VALTYPE_FLOAT:  return FLT(mem_val) > FLT(search_val);
        case CS_VALTYPE_DOUBLE: return DBL(mem_val) > DBL(search_val);
        default: return 0;
        }

    case CS_CMP_SMALLER_THAN:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  return U8(mem_val)  < U8(search_val);
        case CS_VALTYPE_INT8:   return S8(mem_val)  < S8(search_val);
        case CS_VALTYPE_UINT16: return U16(mem_val) < U16(search_val);
        case CS_VALTYPE_INT16:  return S16(mem_val) < S16(search_val);
        case CS_VALTYPE_UINT32: return U32(mem_val) < U32(search_val);
        case CS_VALTYPE_INT32:  return S32(mem_val) < S32(search_val);
        case CS_VALTYPE_UINT64: return U64(mem_val) < U64(search_val);
        case CS_VALTYPE_INT64:  return S64(mem_val) < S64(search_val);
        case CS_VALTYPE_FLOAT:  return FLT(mem_val) < FLT(search_val);
        case CS_VALTYPE_DOUBLE: return DBL(mem_val) < DBL(search_val);
        default: return 0;
        }

    case CS_CMP_BETWEEN: {
        #define BETWEEN_CHECK(cast) do {                          \
            cast lo = *(const cast *)(search_val);                \
            cast hi = *(const cast *)(extra_val);                 \
            cast mv = *(const cast *)(mem_val);                   \
            if (hi > lo) return (mv >= lo) && (mv <= hi);         \
            else         return (mv <= lo) && (mv >= hi);         \
        } while(0)
        switch (value_type) {
        case CS_VALTYPE_UINT8:  BETWEEN_CHECK(uint8_t);
        case CS_VALTYPE_INT8:   BETWEEN_CHECK(int8_t);
        case CS_VALTYPE_UINT16: BETWEEN_CHECK(uint16_t);
        case CS_VALTYPE_INT16:  BETWEEN_CHECK(int16_t);
        case CS_VALTYPE_UINT32: BETWEEN_CHECK(uint32_t);
        case CS_VALTYPE_INT32:  BETWEEN_CHECK(int32_t);
        case CS_VALTYPE_UINT64: BETWEEN_CHECK(uint64_t);
        case CS_VALTYPE_INT64:  BETWEEN_CHECK(int64_t);
        case CS_VALTYPE_FLOAT:  BETWEEN_CHECK(float);
        case CS_VALTYPE_DOUBLE: BETWEEN_CHECK(double);
        default: return 0;
        }
        #undef BETWEEN_CHECK
    }

    case CS_CMP_INCREASED:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  return U8(mem_val)  > U8(extra_val);
        case CS_VALTYPE_INT8:   return S8(mem_val)  > S8(extra_val);
        case CS_VALTYPE_UINT16: return U16(mem_val) > U16(extra_val);
        case CS_VALTYPE_INT16:  return S16(mem_val) > S16(extra_val);
        case CS_VALTYPE_UINT32: return U32(mem_val) > U32(extra_val);
        case CS_VALTYPE_INT32:  return S32(mem_val) > S32(extra_val);
        case CS_VALTYPE_UINT64: return U64(mem_val) > U64(extra_val);
        case CS_VALTYPE_INT64:  return S64(mem_val) > S64(extra_val);
        case CS_VALTYPE_FLOAT:  return FLT(mem_val) > FLT(extra_val);
        case CS_VALTYPE_DOUBLE: return DBL(mem_val) > DBL(extra_val);
        default: return 0;
        }

    case CS_CMP_INCREASED_BY:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  return U8(extra_val)  + U8(search_val)  == U8(mem_val);
        case CS_VALTYPE_INT8:   return S8(extra_val)  + S8(search_val)  == S8(mem_val);
        case CS_VALTYPE_UINT16: return U16(extra_val) + U16(search_val) == U16(mem_val);
        case CS_VALTYPE_INT16:  return S16(extra_val) + S16(search_val) == S16(mem_val);
        case CS_VALTYPE_UINT32: return U32(extra_val) + U32(search_val) == U32(mem_val);
        case CS_VALTYPE_INT32:  return S32(extra_val) + S32(search_val) == S32(mem_val);
        case CS_VALTYPE_UINT64: return U64(extra_val) + U64(search_val) == U64(mem_val);
        case CS_VALTYPE_INT64:  return S64(extra_val) + S64(search_val) == S64(mem_val);
        case CS_VALTYPE_FLOAT:  return FLT(extra_val) + FLT(search_val) == FLT(mem_val);
        /* FIX: was (double)FLT(search_val) — lost precision casting through float */
        case CS_VALTYPE_DOUBLE: return DBL(extra_val) + DBL(search_val) == DBL(mem_val);
        default: return 0;
        }

    case CS_CMP_DECREASED:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  return U8(mem_val)  < U8(extra_val);
        case CS_VALTYPE_INT8:   return S8(mem_val)  < S8(extra_val);
        case CS_VALTYPE_UINT16: return U16(mem_val) < U16(extra_val);
        case CS_VALTYPE_INT16:  return S16(mem_val) < S16(extra_val);
        case CS_VALTYPE_UINT32: return U32(mem_val) < U32(extra_val);
        case CS_VALTYPE_INT32:  return S32(mem_val) < S32(extra_val);
        case CS_VALTYPE_UINT64: return U64(mem_val) < U64(extra_val);
        case CS_VALTYPE_INT64:  return S64(mem_val) < S64(extra_val);
        case CS_VALTYPE_FLOAT:  return FLT(mem_val) < FLT(extra_val);
        case CS_VALTYPE_DOUBLE: return DBL(mem_val) < DBL(extra_val);
        default: return 0;
        }

    case CS_CMP_DECREASED_BY:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  return U8(extra_val)  - U8(search_val)  == U8(mem_val);
        case CS_VALTYPE_INT8:   return S8(extra_val)  - S8(search_val)  == S8(mem_val);
        case CS_VALTYPE_UINT16: return U16(extra_val) - U16(search_val) == U16(mem_val);
        case CS_VALTYPE_INT16:  return S16(extra_val) - S16(search_val) == S16(mem_val);
        case CS_VALTYPE_UINT32: return U32(extra_val) - U32(search_val) == U32(mem_val);
        case CS_VALTYPE_INT32:  return S32(extra_val) - S32(search_val) == S32(mem_val);
        case CS_VALTYPE_UINT64: return U64(extra_val) - U64(search_val) == U64(mem_val);
        case CS_VALTYPE_INT64:  return S64(extra_val) - S64(search_val) == S64(mem_val);
        /* FIX: these two cases were missing entirely in the reference */
        case CS_VALTYPE_FLOAT:  return FLT(extra_val) - FLT(search_val) == FLT(mem_val);
        case CS_VALTYPE_DOUBLE: return DBL(extra_val) - DBL(search_val) == DBL(mem_val);
        default: return 0;
        }

    case CS_CMP_CHANGED:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  case CS_VALTYPE_INT8:  return U8(mem_val)  != U8(extra_val);
        case CS_VALTYPE_UINT16: case CS_VALTYPE_INT16: return U16(mem_val) != U16(extra_val);
        case CS_VALTYPE_UINT32: case CS_VALTYPE_INT32: return U32(mem_val) != U32(extra_val);
        case CS_VALTYPE_UINT64: case CS_VALTYPE_INT64: return U64(mem_val) != U64(extra_val);
        case CS_VALTYPE_FLOAT:  return FLT(mem_val) != FLT(extra_val);
        case CS_VALTYPE_DOUBLE: return DBL(mem_val) != DBL(extra_val);
        default: return 0;
        }

    case CS_CMP_UNCHANGED:
        switch (value_type) {
        case CS_VALTYPE_UINT8:  case CS_VALTYPE_INT8:  return U8(mem_val)  == U8(extra_val);
        case CS_VALTYPE_UINT16: case CS_VALTYPE_INT16: return U16(mem_val) == U16(extra_val);
        case CS_VALTYPE_UINT32: case CS_VALTYPE_INT32: return U32(mem_val) == U32(extra_val);
        case CS_VALTYPE_UINT64: case CS_VALTYPE_INT64: return U64(mem_val) == U64(extra_val);
        case CS_VALTYPE_FLOAT:  return FLT(mem_val) == FLT(extra_val);
        case CS_VALTYPE_DOUBLE: return DBL(mem_val) == DBL(extra_val);
        default: return 0;
        }

    case CS_CMP_UNKNOWN_INIT:
    case CS_CMP_DECREASED_RANGE:
        return 1;

    default:
        return 0;
    }

    #undef U8
    #undef S8
    #undef U16
    #undef S16
    #undef U32
    #undef S32
    #undef U64
    #undef S64
    #undef FLT
    #undef DBL
}

/* ========================================================================
 * Handler declarations
 * ======================================================================== */

int console_scan_start_handle(int fd, struct cmd_packet *packet);
int console_scan_rescan_handle(int fd, struct cmd_packet *packet);
int console_scan_get_results_handle(int fd, struct cmd_packet *packet);

#endif /* _CONSOLE_SCAN_H */
