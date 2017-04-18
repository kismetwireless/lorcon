/*
    Generates data frames at every MCS value across 20 and 40mhz
    for testing tx and rx.

    Allows tagging packets with location info for site surveys.

    Packets are sent from a custom mac address which repurposes the 
    source mac to embed data about the test:

    Byte 0 - Fixed at 0x00 for MAC standards
    Byte 1 - MCS rate and flags, where:
        Bit 7 indicates HT40 mode
        Bit 6 indicates ShortGI mode
        Bits 0-3 indicate MCS value 0-15
    Byte 2 - Location code (0-255) provided by the user for this
        location
    Bytes 3-6 - 24bit packet count
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

	printf("\nExample:\n");
	printf("\t%s -i wlan0 -c 6HT40+ -l 1 -L 'Top Floor' -n 1000\n\n", argv[0]);
}
int main(int argc, char *argv[]) {
	char *interface = NULL, *lname = NULL;
    unsigned int lcode = 0;
    unsigned int npackets = 100;

	int c;
    int channel, ch_flags;

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

	/* BSSID and source MAC address */
	uint8_t mac[6] = "\x00\x01\x02\x03\x04\x05";
    /* Pointer into last 4 bits, of which we use 3 and then override
       the rest */
    uint32_t *mac_counter = (uint32_t *) (mac + 2);
    
    uint8_t dmac[6] = "\x00\xDE\xAD\xBE\xEF\x00";

    uint8_t payload[PAYLOAD_LEN];

	printf ("%s - 802.11 MCS Sweeper\n", argv[0]);
	printf ("-----------------------------------------------------\n\n");

	while ((c = getopt(argc, argv, "hi:c:l:L:n:")) != EOF) {
		switch (c) {
			case 'i': 
				interface = strdup(optarg);
				break;
			case 'c':
                if (lorcon_parse_ht_channel(optarg, &channel, &ch_flags) == 0) {
                    printf("ERROR: Unable to parse channel\n");
                    return -1;
                }
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

	// Set the channel we'll be injecting on
	lorcon_set_ht_channel(context, channel, ch_flags);

	printf("[+]\t Using channel: %d flags %d\n\n", channel, ch_flags);

    printf("\n[.]\tNon-MCS Calibration\n");
    for (count = 0; count < npackets; count++) {
        memset(mac, 0, 6);

        // Fixed header for calibration
        mac[0] = 0x00; mac[1] = 0xDE; mac[2] = 0xAD;
        mac[3] = 0xBE; mac[4] = 0xEF; mac[5] = 0xFF;

        // set the location code
        mac[5] = lcode & 0xFF;

        snprintf((char *) payload, PAYLOAD_LEN, "Non-MCS Calibration Packet %u of %u Location %u Name %s",
                count,
                npackets,
                lcode,
                lname == NULL ? "n/a" : lname);

        metapack = lcpa_init();

        lcpf_qos_data(metapack, 0x42, 100 * PAYLOAD_LEN, dmac, mac, mac, NULL, 0, count);
        lcpf_qosheaders(metapack, 0, 0, 0);
        lcpa_append(metapack, "PAYLOAD", PAYLOAD_LEN, payload);

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

            // Set the packet # to network-endian, then we clobber the
            // first 8 bits with the location code
            *mac_counter = htonl(count);

            // Set MCS count
            mac[1] = mcs_iter;
            if (gi_iter)
                mac[1] |= HT_FLAG_GI;
            if (ht_iter)
                mac[1] |= HT_FLAG_40;

            // set the location code
            mac[2] = lcode & 0xFF;

            memset(payload, 0, PAYLOAD_LEN);

            snprintf((char *) payload, PAYLOAD_LEN, "MCS %u %s%s Packet %u of %u Location %u Name %s",
                    mcs_iter,
                    ht_iter ? "40MHz" : "20MHz",
                    gi_iter ? " short-gi": "",
                    count,
                    npackets,
                    lcode,
                    lname == NULL ? "n/a" : lname);

            metapack = lcpa_init();

            lcpf_qos_data(metapack, 0x42, 100 * PAYLOAD_LEN, dmac, mac, mac, NULL, 0, count);
            lcpf_qosheaders(metapack, 0, 0, 0);
            lcpa_append(metapack, "PAYLOAD", PAYLOAD_LEN, payload);

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

