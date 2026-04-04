#include "console_scan.h"

/* ========================================================================
 * Helper: flush accumulated result bytes to client
 * ======================================================================== */

static void cs_flush_results(int fd, void *send_buf, uint64_t *accum_bytes)
{
    if (*accum_bytes == 0) return;
    memcpy(send_buf, accum_bytes, 8);
    net_send_data(fd, send_buf, (int)(*accum_bytes + 8));
    *accum_bytes = 0;
}

/* ========================================================================
 * CMD_CONSOLE_SCAN_START (0xBDAACC01) — Full-featured initial scan
 *
 * Protocol:
 *   C->S: packet header + cs_scan_request_full (23 bytes)
 *   S->C: SUCCESS #1
 *   C->S: search_value (if cmptype_needs_value[cmp_type])
 *   C->S: mask (if value_type == BYTES)
 *   S->C: SUCCESS #2
 *   S->C: [u64 packed_byte_count][u32 offset + u8[N] value]... (chunked)
 *   S->C: [u64 0xFFFFFFFFFFFFFFFF] (terminator)
 *   S->C: SUCCESS #3 (final)
 * ======================================================================== */

int console_scan_start_handle(int fd, struct cmd_packet *packet)
{
    struct cs_scan_request_full *req = (struct cs_scan_request_full *)packet->data;

    if (!req) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    uint8_t  cmp_type   = req->cmp_type;
    uint8_t  value_type = req->value_type;
    uint32_t data_len   = req->data_len;
    uint8_t  scan_step  = req->scan_step;

    if (cmp_type > 12) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    int is_between = (cmp_type == CS_CMP_BETWEEN);
    if (!is_between && !((1 << cmp_type) & CS_FIRST_SCAN_BITMASK)) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    uint64_t value_size;
    if (value_type <= 9) {
        value_size = cs_value_type_sizes[value_type];
        if (value_size == 0) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }
    } else if (value_type == CS_VALTYPE_BYTES) {
        value_size = data_len;
    } else {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if (data_len == 0 && cs_cmptype_needs_value[cmp_type]) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    void *search_buf = NULL, *mask_buf = NULL, *extra_val = NULL;

    if (value_type == CS_VALTYPE_BYTES) {
        search_buf = pfmalloc(value_size);
        if (!search_buf) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }
        net_send_status(fd, CMD_SUCCESS);  /* SUCCESS #1 */
        net_recv_data(fd, search_buf, value_size, 1);
        mask_buf = pfmalloc(value_size);
        if (mask_buf)
            net_recv_data(fd, mask_buf, value_size, 1);
    } else if (cs_cmptype_needs_value[cmp_type] || cs_cmptype_needs_extra[cmp_type]) {
        search_buf = pfmalloc(data_len);
        if (!search_buf) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }
        net_send_status(fd, CMD_SUCCESS);  /* SUCCESS #1 */
        net_recv_data(fd, search_buf, data_len, 1);
        if (is_between)
            extra_val = (uint8_t *)search_buf + value_size;
    } else {
        net_send_status(fd, CMD_SUCCESS);  /* SUCCESS #1 */
    }

    /* Align read buffer size to value_size */
    uint64_t read_buf_size = CS_START_READ_BUF;
    {
        uint64_t rem = read_buf_size % value_size;
        if (rem)
            read_buf_size = (read_buf_size / value_size) * value_size;
    }

    void *read_buf = pfmalloc(read_buf_size);
    void *send_buf = pfmalloc(CS_START_SEND_BUF);
    if (!read_buf || !send_buf) {
        if (read_buf) free(read_buf);
        if (send_buf) free(send_buf);
        if (search_buf) free(search_buf);
        if (mask_buf) free(mask_buf);
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);  /* SUCCESS #2 */

    uint64_t flush_thresh = CS_FLUSH_THRESHOLD - value_size;
    uint64_t accum_bytes  = 0;
    uint64_t max_inner    = read_buf_size - value_size;

    /* Chunk advancement with overlap at boundaries */
    uint64_t chunk_advance = read_buf_size + scan_step - value_size;

    uint64_t remaining = req->scan_length;
    uint64_t cur_addr  = req->start_addr;

    while (remaining > 0) {
        int is_last_chunk = (remaining <= read_buf_size);
        uint64_t chunk_size = is_last_chunk ? remaining : read_buf_size;

        memset(read_buf, 0, read_buf_size);
        sys_proc_rw(req->pid, cur_addr, read_buf, chunk_size, 0);

        uint64_t inner_max = is_last_chunk ? (chunk_size - value_size) : max_inner;

        for (uint64_t off = 0; off <= inner_max; off += scan_step) {
            uint8_t *mem_ptr = (uint8_t *)read_buf + off;
            int match;

            if (value_type == CS_VALTYPE_BYTES && mask_buf) {
                match = 1;
                for (uint64_t b = 0; b < value_size; b++) {
                    if (((uint8_t *)mask_buf)[b] &&
                        ((uint8_t *)search_buf)[b] != mem_ptr[b]) {
                        match = 0;
                        break;
                    }
                }
            } else {
                match = cs_scan_compare(cmp_type, value_type, value_size,
                                        search_buf, mem_ptr, extra_val);
            }

            if (match) {
                if (accum_bytes > flush_thresh)
                    cs_flush_results(fd, send_buf, &accum_bytes);
                uint32_t result_offset = (uint32_t)((cur_addr + off) - req->start_addr);
                uint64_t wp = accum_bytes + 8;
                memcpy((uint8_t *)send_buf + wp, &result_offset, 4);
                memcpy((uint8_t *)send_buf + wp + 4, mem_ptr, value_size);
                accum_bytes += 4 + value_size;
            }
        }

        if (is_last_chunk)
            break;

        cur_addr  += chunk_advance;
        remaining -= chunk_advance;
    }

    cs_flush_results(fd, send_buf, &accum_bytes);
    uint64_t term = SCAN_TERMINATOR;
    net_send_data(fd, &term, 8);

    if (search_buf) free(search_buf);
    if (mask_buf) free(mask_buf);
    free(read_buf);
    free(send_buf);

    net_send_status(fd, CMD_SUCCESS);  /* SUCCESS #3 */
    return 0;
}

/* ========================================================================
 * CMD_CONSOLE_SCAN_RESCAN (0xBDAACC02) — Rescan/narrow previous results
 *
 * Interleaved protocol:
 *   C->S: packet header + cs_scan_request_rescan (18 bytes)
 *   S->C: SUCCESS
 *   C->S: search_value (if cmptype_needs_value)
 *   C->S: mask (if value_type == BYTES)
 *   LOOP {
 *       C->S: uint32 chunk_size
 *       if chunk_size == 0xFFFFFFFF -> break
 *       C->S: chunk_data (chunk_size bytes of [u32 offset][value]... entries)
 *       Server re-reads memory, compares, streams back matches
 *       S->C: [u64 packed_byte_count][u32 offset + value]... (0+ flushes)
 *       S->C: [u64 0xFFFFFFFFFFFFFFFF] (per-chunk terminator)
 *   }
 *   S->C: SUCCESS (final)
 * ======================================================================== */

int console_scan_rescan_handle(int fd, struct cmd_packet *packet)
{
    struct cs_scan_request_rescan *req = (struct cs_scan_request_rescan *)packet->data;

    if (!req) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    uint8_t  cmp_type   = req->cmp_type;
    uint8_t  value_type = req->value_type;
    uint32_t data_len   = req->data_len;

    if (cmp_type > 12) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    uint8_t needs_value    = cs_cmptype_needs_value[cmp_type];
    uint8_t needs_extra    = cs_cmptype_needs_extra[cmp_type];
    uint8_t needs_previous = cs_cmptype_needs_previous[cmp_type];
    uint8_t needs_recv     = needs_value | needs_extra;

    uint64_t value_size;
    if (value_type <= 9) {
        value_size = cs_value_type_sizes[value_type];
        if (value_size == 0) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }
    } else if (value_type == CS_VALTYPE_BYTES) {
        value_size = data_len;
    } else {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    void *search_buf = NULL, *mask_buf = NULL, *extra_val = NULL;

    if (value_type == CS_VALTYPE_BYTES) {
        search_buf = pfmalloc(value_size);
        if (!search_buf) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }
    }

    void *result_buf = pfmalloc(CS_RESCAN_RESULT_BUF);
    if (!result_buf) {
        if (search_buf) free(search_buf);
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    /* Receive search/delta value if needed */
    if (needs_recv && data_len > 0) {
        if (!search_buf)
            search_buf = pfmalloc(data_len);
        if (search_buf)
            net_recv_data(fd, search_buf, data_len, 1);
    }

    /* Receive mask for BYTES type */
    if (value_type == CS_VALTYPE_BYTES) {
        mask_buf = pfmalloc(value_size);
        if (mask_buf)
            net_recv_data(fd, mask_buf, value_size, 1);
    }

    if (needs_extra && search_buf)
        extra_val = (uint8_t *)search_buf + value_size;

    uint64_t entry_stride = needs_previous ? (4 + value_size) : 4;
    uint64_t flush_thresh = CS_RESCAN_RESULT_BUF - 16 - (value_size + 4) * 2;

    void *read_buf = pfmalloc(CS_RESCAN_READ_BUF);
    if (!read_buf) {
        free(result_buf);
        if (search_buf) free(search_buf);
        if (mask_buf) free(mask_buf);
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    uint64_t result_accum = 0;

    /* Sliding window state for memory reads */
    uint64_t window_start = 0, window_end = 0;
    int window_valid = 0;

    /* === Main interleaved loop === */
    while (1) {
        uint32_t chunk_size;
        net_recv_data(fd, &chunk_size, 4, 1);
        if (chunk_size == 0xFFFFFFFF)
            break;

        void *chunk_data = pfmalloc(chunk_size);
        if (!chunk_data)
            break;
        net_recv_data(fd, chunk_data, chunk_size, 1);

        uint64_t pos = 0;
        uint64_t base_addr = req->base_addr;

        while (pos + entry_stride <= chunk_size) {
            uint32_t entry_offset = *(uint32_t *)((uint8_t *)chunk_data + pos);
            void *prev_val = needs_previous ? ((uint8_t *)chunk_data + pos + 4) : NULL;
            uint64_t target_addr = base_addr + entry_offset;

            /* Sliding window: only re-read when address falls outside cache */
            if (!window_valid ||
                target_addr < window_start ||
                target_addr + value_size > window_end) {
                window_start = target_addr;
                memset(read_buf, 0, CS_RESCAN_READ_BUF);
                sys_proc_rw(req->pid, window_start, read_buf, CS_RESCAN_READ_BUF, 0);
                window_end   = window_start + CS_RESCAN_READ_BUF;
                window_valid = 1;
            }

            uint8_t *mem_ptr = (uint8_t *)read_buf + (target_addr - window_start);

            void *cmp_extra = NULL;
            if (needs_previous && prev_val)
                cmp_extra = prev_val;
            else if (needs_extra && extra_val)
                cmp_extra = extra_val;

            int match;
            if (value_type == CS_VALTYPE_BYTES && mask_buf) {
                match = 1;
                for (uint64_t b = 0; b < value_size; b++) {
                    if (((uint8_t *)mask_buf)[b] &&
                        ((uint8_t *)search_buf)[b] != mem_ptr[b]) {
                        match = 0;
                        break;
                    }
                }
            } else {
                match = cs_scan_compare(cmp_type, value_type, value_size,
                                        search_buf, mem_ptr, cmp_extra);
            }

            if (match) {
                if (result_accum > flush_thresh)
                    cs_flush_results(fd, result_buf, &result_accum);
                uint64_t wp = result_accum + 8;
                memcpy((uint8_t *)result_buf + wp, &entry_offset, 4);
                memcpy((uint8_t *)result_buf + wp + 4, mem_ptr, value_size);
                result_accum += 4 + value_size;
            }

            pos += entry_stride;
        }

        free(chunk_data);

        if (result_accum > 0)
            cs_flush_results(fd, result_buf, &result_accum);

        /* Per-chunk terminator */
        uint64_t term = SCAN_TERMINATOR;
        net_send_data(fd, &term, 8);
    }

    free(read_buf);
    free(result_buf);
    if (search_buf) free(search_buf);
    if (mask_buf) free(mask_buf);

    net_send_status(fd, CMD_SUCCESS);
    return 0;
}

/* ========================================================================
 * CMD_CONSOLE_SCAN_GETRES (0xBDAACC03) — Read values at matched addresses
 *
 * Protocol:
 *   C->S: packet header + { uint32 pid, uint32 num_entries }
 *   S->C: SUCCESS
 *   C->S: num_entries x { uint64 address, uint32 length } (12 bytes each)
 *   For each entry:
 *     S->C: [length bytes of memory] (in 64KB chunks)
 *   S->C: [u64 0xFFFFFFFFFFFFFFFF] (terminator)
 * ======================================================================== */

int console_scan_get_results_handle(int fd, struct cmd_packet *packet)
{
    uint32_t *data = (uint32_t *)packet->data;
    if (!data) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    uint32_t pid         = data[0];
    uint32_t num_entries = data[1];

    uint32_t entries_size = num_entries * 12;
    void *entries = pfmalloc(entries_size);
    if (!entries) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    net_recv_data(fd, entries, entries_size, 1);

    void *xfer_buf = pfmalloc(CS_GETRES_BUF_SIZE);
    if (!xfer_buf) {
        free(entries);
        return 1;
    }

    for (uint32_t i = 0; i < num_entries; i++) {
        uint8_t *entry = (uint8_t *)entries + (i * 12);
        uint64_t addr   = *(uint64_t *)(entry + 0);
        uint32_t length = *(uint32_t *)(entry + 8);

        uint64_t remaining = length;
        uint64_t cur_addr  = addr;

        while (remaining > CS_GETRES_BUF_SIZE) {
            memset(xfer_buf, 0, CS_GETRES_BUF_SIZE);
            sys_proc_rw(pid, cur_addr, xfer_buf, CS_GETRES_BUF_SIZE, 0);
            net_send_data(fd, xfer_buf, CS_GETRES_BUF_SIZE);
            cur_addr  += CS_GETRES_BUF_SIZE;
            remaining -= CS_GETRES_BUF_SIZE;
        }

        if (remaining > 0) {
            memset(xfer_buf, 0, remaining);
            sys_proc_rw(pid, cur_addr, xfer_buf, remaining, 0);
            net_send_data(fd, xfer_buf, (int)remaining);
        }
    }

    uint64_t term = SCAN_TERMINATOR;
    net_send_data(fd, &term, 8);

    free(xfer_buf);
    free(entries);
    return 0;
}
