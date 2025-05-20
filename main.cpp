#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "thread.h"
#include "xtimer.h"
#include "net/loramac.h"
#include "semtech_loramac.h"

#define RECORD_INTERVAL (30 * 1000 * 1000U)

#define MAX_PACKETS 10
#define MAX_PACKET_SIZE 64

typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    size_t size;
    uint32_t fcnt;
} packet_t;

static packet_t captured_packets[MAX_PACKETS];
static uint8_t packet_count = 0;

static semtech_loramac_t loramac;

#define SENDER_PRIO         (THREAD_PRIORITY_MAIN - 1)
static kernel_pid_t sender_pid;
static char sender_stack[THREAD_STACKSIZE_MAIN];

typedef enum {
    MODE_RECORD,
    MODE_REPLAY
} device_mode_t;

static device_mode_t current_mode = MODE_RECORD;

void analyze_packet(const uint8_t *packet, size_t size)
{
    if (size < 8) {
        return;
    }
    
    if (packet_count < MAX_PACKETS) {
        memcpy(captured_packets[packet_count].data, packet, size);
        captured_packets[packet_count].size = size;
        
        captured_packets[packet_count].fcnt = 
            (packet[7] << 8) | packet[6];
        
        printf("Captured packet #%d, size %zu, FCnt %lu\n", 
                packet_count, size, (unsigned long)captured_packets[packet_count].fcnt);
        
        if (size >= 12) {
            if (memcmp(&packet[8], "open", 4) == 0) {
                printf("Found potential 'open' command!\n");
            }
        }
        
        packet_count++;
    }
}

void sniff_packets(void)
{
    printf("Started packet sniffer\n");
    
    while (current_mode == MODE_RECORD) {
        uint8_t fake_packet[12] = {
            0x40,
            0x01, 0x02, 0x03, 0x04,
            0x00,
            (uint8_t)(packet_count),
            0x00,
            'o', 'p', 'e', 'n'
        };
        
        analyze_packet(fake_packet, sizeof(fake_packet));
        
        xtimer_usleep(RECORD_INTERVAL);
    }
}

void replay_packets(void)
{
    printf("Starting replay attack...\n");
    
    for (int i = 0; i < packet_count; i++) {
        printf("Replaying packet #%d, size %zu, FCnt %lu\n", 
                i, captured_packets[i].size, (unsigned long)captured_packets[i].fcnt);
        
        printf("Attempting to send raw packet (demo only)\n");
        
        xtimer_usleep(5 * 1000 * 1000);
    }
    
    printf("Replay attack completed\n");
}

void demonstrate_vulnerability(void)
{
    printf("\n=== Demonstrating LoRaWAN Replay Attack ===\n");
    printf("This shows why a properly implemented LoRaWAN device\n");
    printf("would NOT be vulnerable to replay attacks\n\n");
    
    printf("CASE 1: Properly implemented LoRaWAN lock (secure)\n");
    printf("- Each message has a unique FCnt value\n");
    printf("- Message integrity is verified with MIC\n");
    printf("- Server rejects messages with duplicate FCnt values\n");
    printf("→ Replay attack will FAIL\n\n");
    
    printf("CASE 2: Improperly implemented lock (vulnerable)\n");
    printf("- Device acts on LoRa messages without proper LoRaWAN checks\n");
    printf("- Payloads are not encrypted or authentication is bypassed\n");
    printf("- No verification of FCnt or sender identity\n");
    printf("→ Replay attack could SUCCEED\n\n");
    
    current_mode = MODE_RECORD;
    printf("Phase 1: Recording packets...\n");
    sniff_packets();
    
    current_mode = MODE_REPLAY;
    printf("\nPhase 2: Replaying packets...\n");
    replay_packets();
    
    printf("\nConclusion:\n");
    printf("- A standard-compliant LoRaWAN device will reject replayed messages\n");
    printf("- Only improperly implemented devices could be vulnerable\n");
}

static void *sender(void *arg)
{
    (void)arg;
    
    xtimer_sleep(1);
    
    demonstrate_vulnerability();
    
    return NULL;
}

int main(void)
{
    printf("LoRaWAN Replay Attack Demonstration\n");
    printf("This demonstrates why standard-compliant LoRaWAN\n");
    printf("is NOT vulnerable to simple replay attacks\n");
    
    semtech_loramac_init(&loramac);
    
    sender_pid = thread_create(sender_stack, sizeof(sender_stack),
                              SENDER_PRIO, 0, sender, NULL, "sender");
    
    return 0;
}
