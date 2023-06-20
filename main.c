#include "includes/bpf_api.h"
#include "includes/tracer.h"
#include "includes/ip.h"
#include "includes/http-types.h"
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#define MAX_PATH_LEN 256

static __always_inline bool skb_revalidate_data(struct __sk_buff *skb,
                                                uint8_t **head, uint8_t **tail,
                                                const __u32 offset) {
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *)(long)skb->data;
        *tail = (uint8_t *)(long)skb->data_end;

        if (*head + offset > *tail) {
            return false;
        }
    }

    return true;
}


__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
    skb_info_t skb_info;

    if (!read_conn_tuple_skb(skb, &skb_info)) {
        return BPF_H_DEFAULT;
    }

    char *p[HTTP_BUFFER_SIZE];
    http_packet_t packet_type;
    http_method_t method = HTTP_METHOD_UNKNOWN;

    if (skb->len - skb_info.data_off < HTTP_BUFFER_SIZE) {
        printt("http buffer reach the limit");
        return BPF_H_DEFAULT;
    }

    for (int i = 0; i < HTTP_BUFFER_SIZE; i++) {
        p[i] = load_byte(skb, skb_info.data_off + i);
    }

    //printt("fallthrough 4\n");

    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
        packet_type = HTTP_RESPONSE;
    } else if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
        packet_type = HTTP_REQUEST;
        method = HTTP_GET;
    } else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
        packet_type = HTTP_REQUEST;
        method = HTTP_POST;
    } else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
        packet_type = HTTP_REQUEST;
        method = HTTP_PUT;
    } else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
        packet_type = HTTP_REQUEST;
        method = HTTP_DELETE;
    } else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
        packet_type = HTTP_REQUEST;
        method = HTTP_HEAD;
    } else if ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S')) {
        packet_type = HTTP_REQUEST;
        method = HTTP_OPTIONS;
    } else if ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H')) {
        packet_type = HTTP_REQUEST;
        method = HTTP_PATCH;
    } 
    //printt("fallthrough 5\n");

    if (method == HTTP_METHOD_UNKNOWN) {
       printt("not an http request");
       return TC_ACT_OK;
    }

    int i;
    char path[MAX_PATH_LEN];
    int path_length = 0;

    printt("--------------");

    // Extract the path
    for (i = 0; i < HTTP_BUFFER_SIZE; i++) {
        if (p[i] == ' ') {
            i++;
            // Find the end of the path
            while (i < HTTP_BUFFER_SIZE && p[i] != ' ' && path_length < MAX_PATH_LEN - 1) {
                path[path_length] = p[i];
                printt("PATH: %c", p[i]);
                path_length++;
                i++;
            }

            // Null-terminate the path
            path[path_length] = '\0';

            // Handle or store the path as needed

            break;
        }
    }

    // Set the mark value
    //__u32 mark_value = 131074;  // Replace with your desired mark value

    //// Apply the mark action
    //bpf_skb_store_bytes(skb, offsetof(struct __sk_buff, mark), &mark_value, sizeof(mark_value), 0);

    printt("-- TC_ACT_OK  --");

    //return TC_ACT_OK;
    //return TC_ACT_SHOT;
    //return XDP_DROP;
    //return XDP_ABORTED;
    //return TC_ACT_UNSPEC;
    //return TC_ACT_PIPE;
    //return TC_ACT_RECLASSIFY;
}

BPF_LICENSE("GPL");

