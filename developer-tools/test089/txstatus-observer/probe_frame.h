#ifndef TEST089_PROBE_FRAME_H
#define TEST089_PROBE_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define T089_RADIOTAP_LENGTH 10U
#define T089_MPDU_LENGTH 96U
#define T089_PACKET_LENGTH (T089_RADIOTAP_LENGTH + T089_MPDU_LENGTH)

/* Byte-identical Test086/Test088 single-frame probe, sequence slot zero. */
void t089_build_probe(uint8_t packet[T089_PACKET_LENGTH]);

#endif
