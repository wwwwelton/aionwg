#include <assert.h>
#include <string.h>
#include "shugo-map.h"

int main(void) {
    const uint32_t games[] = {10}, mirrors[] = {20};
    const uint32_t loop = 0x0100007f, port = 0x1034;
    shugo_row original[] = {
        {5, 0x0101a8c0, 123, 0x010200c0, port, 10},
        {5, loop, port, loop, 123, 20},
        {5, 0x0101a8c0, 124, 0x010200c0, port, 30},
        {5, 0x0101a8c0, 125, 0x010200c0, port, 10},
        {5, 0x0101a8c0, 123, 0x010200c0, 0xbb01, 10}
    }, rows[5];
    memcpy(rows, original, sizeof(rows));
    assert(shugo_map_rows(rows, 5, games, 1, mirrors, 1) == 1);
    assert(rows[0].local_addr == loop && rows[0].remote_addr == loop);
    assert(rows[0].pid == 10 && rows[0].state == 5 && rows[0].local_port == 123 && rows[0].remote_port == port);
    assert(!memcmp(rows + 1, original + 1, sizeof(rows) - sizeof(rows[0])));
    assert(shugo_map_rows(rows, 5, games, 1, mirrors, 1) == 0);
    memcpy(rows, original, sizeof(rows));
    rows[1].pid = 30; /* A different app's loopback must not qualify. */
    assert(shugo_map_rows(rows, 5, games, 1, mirrors, 1) == 0);
    memcpy(rows, original, sizeof(rows));
    rows[1].state = 2;
    assert(shugo_map_rows(rows, 5, games, 1, mirrors, 1) == 0);
    memcpy(rows, original, sizeof(rows));
    rows[1].local_port = 123;
    rows[1].remote_port = port;
    assert(shugo_map_rows(rows, 5, games, 1, mirrors, 1) == 1);
    memcpy(rows, original, sizeof(rows));
    rows[0].state = 8;
    assert(shugo_map_rows(rows, 5, games, 1, mirrors, 1) == 0);
    return 0;
}
