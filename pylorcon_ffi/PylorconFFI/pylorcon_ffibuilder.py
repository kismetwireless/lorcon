#!/usr/bin/env python2

from cffi import FFI

ffibuilder = FFI()
ffibuilder.set_source("_pylorcon_ffi", None)
ffibuilder.cdef("""
    struct lorcon;
    typedef struct lorcon lorcon_t;

    struct lorcon_driver {
	struct lorcon_driver *next;
    	char *name;
    	char *details;
    };
    typedef struct lorcon_driver lorcon_driver_t;


    unsigned long int lorcon_get_version(void);
    const char *lorcon_get_error(lorcon_t *);
    lorcon_driver_t *lorcon_list_drivers();
    void lorcon_free_driver_list(lorcon_driver_t *);
    lorcon_driver_t *lorcon_find_driver(const char *);
    lorcon_driver_t *lorcon_auto_driver(const char *);

    lorcon_t *lorcon_create(const char *, lorcon_driver_t *);
    void lorcon_free(lorcon_driver_t *);

    void lorcon_set_vap(lorcon_t *, const char *);
    const char *lorcon_get_vap(lorcon_t *);
    const char *lorcon_get_capiface(lorcon_t *);

    int lorcon_open_inject(lorcon_t *);
    int lorcon_open_monitor(lorcon_t *);
    int lorcon_open_injmon(lorcon_t *);

    struct lorcon_channel {
        unsigned int channel;
        unsigned int center_freq_1;
        unsigned int center_freq_2;
    
        unsigned int type;
    };
    typedef struct lorcon_channel lorcon_channel_t;
    
    #define LORCON_CHANNEL_BASIC    0
    #define LORCON_CHANNEL_HT20     1
    #define LORCON_CHANNEL_HT40P    2
    #define LORCON_CHANNEL_HT40M    3
    #define LORCON_CHANNEL_5MHZ     4
    #define LORCON_CHANNEL_10MHZ    5
    #define LORCON_CHANNEL_VHT80    6
    #define LORCON_CHANNEL_VHT160   7
    #define LORCON_CHANNEL_VHT8080  8

    int lorcon_get_channel(lorcon_t *);
    int lorcon_parse_ht_channel(const char *, lorcon_channel_t *);

    int lorcon_set_channel(lorcon_t *, int);
    int lorcon_set_complex_channel(lorcon_t *, lorcon_channel_t *);

    int lorcon_ifup(lorcon_t *context);
    int lorcon_ifdown(lorcon_t *context);

    int lorcon_send_bytes(lorcon_t *context, int length, char *bytes);
""");

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)

