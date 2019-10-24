/*
    Generates data frames at every MCS value across 20 and 40mhz
    for testing tx and rx.

    Allows tagging packets with location info for site surveys.

    Packets are sent as beacons encoded at different MCS rates; 
    beacons SHOULD bypass the triggering of CTS/RTS frame control.

    Packets are sent with 2 custom IE tags:

    ie 10, length 14
        Packed byte field encoding:

            Byte 0 - MCS rate and flags, where
                Bit 7 indicates HT40 mode
                Bit 6 indicates ShortGI mode
                Bits 0-3 indicate MCS values 0-15
            Byte 1 - Location code (0-255)
            Bytes 2-5
                32 bit current packet count
            Bytes 6-9
                32 bit maximum packet count
            Bytes 10-13
                32 bit random session id

    ie 11, length 64
        Text field containing a text description of the packed field
*/

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <lorcon2/lorcon.h>
#include <lorcon2/lorcon_packasm.h>

/* MCS only goes 0-15 or 4 bits, so we use bits 6 and 7 to indicate if we
 * are sending HT40 and GI */
#define HT_FLAG_40  (1 << 7)
#define HT_FLAG_GI  (1 << 6)

#define PAYLOAD_LEN 64

void usage(char *argv[]) {
    printf("\t-i <interface>        Radio interface\n");
    printf("\t-c <channel>          Channel (should be HT40)\n");
    printf("\t-l <location #>       Arbitrary location # added to packets\n");
    printf("\t-L <location name>    Arbitrary location name added to packets\n");
    printf("\t-n <count>            Number of packets at each MCS to send\n");
    printf("\t-d <delay>            Interframe delay\n");

	printf("\nExample:\n");
	printf("\t%s -i wlan0 -c 6HT40+ -l 1 -L 'Top Floor' -n 1000\n\n", argv[0]);
}
int main(int argc, char *argv[]) {
	char *interface = NULL, *lname = NULL;
    unsigned int lcode = 0;
    unsigned int npackets = 100;

	int c;
    lorcon_channel_t channel;
    const char *channel_str;

	lorcon_driver_t *drvlist, *driver;
	lorcon_t *context;

	lcpa_metapack_t *metapack;
	lorcon_packet_t *txpack;

    /* delay interval */
    unsigned int interval = 1;

    /* Iterations through HT and GI */
    int mcs_iter = 0;
    int ht_iter = 0;
    int gi_iter = 0;
	unsigned int count = 0;

    unsigned int totalcount = 1;

    uint8_t *smac;

    uint8_t *bmac = "\x00\xDE\xAD\xBE\xEF\x00";

    uint8_t encoded_payload[14];
    uint32_t *encoded_counter = (uint32_t *) (encoded_payload + 2);
    uint32_t *encoded_max = (uint32_t *) (encoded_payload + 6);
    uint32_t *encoded_session = (uint32_t *) (encoded_payload + 10);

    uint8_t payload[PAYLOAD_LEN];

	// Timestamp
    struct timeval time; 
    uint64_t timestamp; 

	// Beacon Interval
	int beacon_interval = 100;

	// Capabilities
	int capabilities = 0x0421;

    // Session ID
    uint32_t session_id;
    FILE *urandom;

	printf ("%s - 802.11 MCS Sweeper\n", argv[0]);
	printf ("-----------------------------------------------------\n\n");

	while ((c = getopt(argc, argv, "hi:c:l:L:n:d:")) != EOF) {
		switch (c) {
			case 'i': 
				interface = strdup(optarg);
				break;
			case 'c':
                if (lorcon_parse_ht_channel(optarg, &channel) == 0) {
                    printf("ERROR: Unable to parse channel\n");
                    return -1;
                }
                channel_str = strdup(optarg);
				break;
            case 'l':
                if (sscanf(optarg, "%u", &lcode) != 1) {
                    printf("ERROR: Unable to parse location code\n");
                    return -1;
                }
                
                if (lcode > 254) {
                    printf("ERROR: Location code must be 0-254\n");
                    return -1;
                }

                break;
                
            case 'L':
                lname = strdup(optarg);
                break;

            case 'n':
                if (sscanf(optarg, "%u", &npackets) != 1) {
                    printf("ERROR: Unable to parse number of packets\n");
                    return -1;
                }
                break;

            case 'd':
                if (sscanf(optarg, "%u", &interval) != 1) {
                    printf("ERROR: Unable to parse interframe interval\n");
                    return -1;
                }
                break;

			case 'h':
				usage(argv);
                return -1;
				break;

			default:
				usage(argv);
                return -1;
				break;
			}
	}

	if ( interface == NULL) { 
		printf ("ERROR: Interface, or channel not set (see -h for more info)\n");
		return -1;
	}

    if ((urandom = fopen("/dev/urandom", "rb")) == NULL) {
        printf("ERROR:  Could not open urandom for session id: %s\n", strerror(errno));
        return -1;
    }

    fread(&session_id, 4, 1, urandom);
    fclose(urandom);

	printf("[+] Using interface %s\n",interface);
	
	if ((driver = lorcon_auto_driver(interface)) == NULL) {
		printf("[!] Could not determine the driver for %s\n", interface);
		return -1;
	} else {
		printf("[+]\t Driver: %s\n",driver->name);
	}

    if ((context = lorcon_create(interface, driver)) == NULL) {
        printf("[!]\t Failed to create context");
        return -1; 
    }

	// Create Monitor Mode Interface
	if (lorcon_open_injmon(context) < 0) {
		printf("[!]\t Could not create Monitor Mode interface!\n");
		return -1;
	} else {
		printf("[+]\t Monitor Mode VAP: %s\n",lorcon_get_vap(context));
		lorcon_free_driver_list(driver);
	}

    // Get the MAC of the radio
    if (lorcon_get_hwmac(context, &smac) <= 0) {
        printf("[!]\t Could not get hw mac address\n");
        return -1;
    }

	// Set the channel we'll be injecting on
	lorcon_set_complex_channel(context, &channel);

	printf("[+]\t Using channel: %s (%d center %d type %d\n\n", channel_str,
            channel.channel, channel.center_freq_1, channel.type);

    printf("\n[.]\tNon-MCS Calibration\n");
    for (count = 0; count < npackets; count++) {
        memset(encoded_payload, 0, 14);

        *encoded_counter = htonl(count);
        *encoded_max = htonl(npackets);
        *encoded_session = htonl(session_id);

        encoded_payload[0] = 0xFF;
        encoded_payload[1] = lcode & 0xFF;

        snprintf((char *) payload, PAYLOAD_LEN, "Non-MCS Calibration Packet %u of %u Location %u Name %s Session %u",
                count,
                npackets,
                lcode,
                lname == NULL ? "n/a" : lname,
                session_id);

        metapack = lcpa_init();

		// Create timestamp
		gettimeofday(&time, NULL);
		timestamp = time.tv_sec * 1000000 + time.tv_usec;

        lcpf_beacon(metapack, smac, bmac, 
                0x00, 0x00, 0x00, 0x00, 
                timestamp, beacon_interval, capabilities);
        lcpf_add_ie(metapack, 0, strlen("MCS_TEST"), "MCS_TEST");

        lcpf_add_ie(metapack, 10, 14, encoded_payload);
        lcpf_add_ie(metapack, 11, strlen((char *) payload), payload);

        // Convert the LORCON metapack to a LORCON packet for sending
        txpack = (lorcon_packet_t *) lorcon_packet_from_lcpa(context, metapack);

        if (lorcon_inject(context,txpack) < 0 ) 
            return -1;

        usleep(interval * 1000);

        printf("\033[K\r");
        printf("[+] Sent %d frames, Hit CTRL + C to stop...", totalcount);
        fflush(stdout);
        totalcount++;

        lcpa_free(metapack); 
    }

    // For each MCS at 20 and 40mhz
    for (mcs_iter = 0; mcs_iter <= 15; ) {
        printf("\n[.]\tMCS %u %s %s\n",
                mcs_iter, ht_iter ? "40mhz" : "20mhz",
                gi_iter ? "short-gi" : "");

        for (count = 0; count < npackets; count++) {
            memset(payload, 0, PAYLOAD_LEN);
            memset(encoded_payload, 0, 14);

            // Set MCS count
            encoded_payload[0] = mcs_iter;
            if (gi_iter)
                encoded_payload[0] |= HT_FLAG_GI;
            if (ht_iter)
                encoded_payload[0] |= HT_FLAG_40;

            // set the location code
            encoded_payload[1] = lcode & 0xFF;

            *encoded_counter = htonl(count);
            *encoded_max = htonl(npackets);
            *encoded_session = htonl(session_id);

            snprintf((char *) payload, PAYLOAD_LEN, "MCS %u %s%s Packet %u of %u Location %u Name %s Session %u",
                    mcs_iter,
                    ht_iter ? "40MHz" : "20MHz",
                    gi_iter ? " short-gi": "",
                    count,
                    npackets,
                    lcode,
                    lname == NULL ? "n/a" : lname,
                    session_id);


            metapack = lcpa_init();

            // Create timestamp
            gettimeofday(&time, NULL);
            timestamp = time.tv_sec * 1000000 + time.tv_usec;

            lcpf_beacon(metapack, smac, bmac, 
                    0x00, 0x00, 0x00, 0x00, 
                    timestamp, beacon_interval, capabilities);
            lcpf_add_ie(metapack, 0, strlen("MCS_TEST"), "MCS_TEST");

            lcpf_add_ie(metapack, 10, 14, encoded_payload);
            lcpf_add_ie(metapack, 11, strlen((char *) payload), payload);

            // Convert the LORCON metapack to a LORCON packet for sending
            txpack = (lorcon_packet_t *) lorcon_packet_from_lcpa(context, metapack);

            lorcon_packet_set_mcs(txpack, 1, mcs_iter, gi_iter, ht_iter);
		
            if (lorcon_inject(context,txpack) < 0 ) 
                return -1;

            usleep(interval * 1000);

            printf("\033[K\r");
            printf("[+] Sent %d frames, Hit CTRL + C to stop...", totalcount);
            fflush(stdout);
            totalcount++;

            lcpa_free(metapack); 
        }

        // Toggle GI per MCS
        if (gi_iter == 0) {
            gi_iter = 1;
            continue;
        }

        // Toggle HT per MCS
        if (ht_iter == 0) {
            ht_iter = 1;
            gi_iter = 0;
            continue;
        }

        // If we've gotten here we've set both GI and HT, so
        // reset them and increment the mcs
        gi_iter = 0;
        ht_iter = 0;
        mcs_iter++;
    }

	// Close the interface
	lorcon_close(context);

	// Free the LORCON Context
	lorcon_free(context);	
	
	return 0;
}

